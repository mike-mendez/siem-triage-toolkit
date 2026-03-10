#!/usr/bin/env python3
"""Offline validation harness for the Nginx detection pack.

This script validates:
1) Rule metadata/schema integrity.
2) Fixture annotation integrity.
3) Rule matching outcomes against tests/expected_hits.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SUPPORTED_RULE_TYPES = {"regex_any", "threshold_count"}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc


def require_type(
    errors: list[str], obj: dict[str, Any], key: str, expected: type, ctx: str
) -> None:
    if key not in obj:
        errors.append(f"{ctx}: missing required key '{key}'")
        return
    if not isinstance(obj[key], expected):
        errors.append(
            f"{ctx}: key '{key}' expected {expected.__name__}, got {type(obj[key]).__name__}"
        )


def validate_rule_schema(
    rule: dict[str, Any], rule_path: Path, repo_root: Path
) -> list[str]:
    errors: list[str] = []
    ctx = str(rule_path)

    for key in (
        "rule_id",
        "name",
        "source",
        "detection_logic",
        "required_fields",
        "mitre",
        "false_positives",
        "tuning",
        "severity",
        "references",
        "playbook",
    ):
        if key not in rule:
            errors.append(f"{ctx}: missing required key '{key}'")

    if errors:
        return errors

    if not isinstance(rule["rule_id"], str) or not rule["rule_id"]:
        errors.append(f"{ctx}: 'rule_id' must be a non-empty string")

    if not isinstance(rule["required_fields"], list) or not all(
        isinstance(item, str) and item for item in rule["required_fields"]
    ):
        errors.append(f"{ctx}: 'required_fields' must be a non-empty string list")

    if not isinstance(rule["false_positives"], list):
        errors.append(f"{ctx}: 'false_positives' must be a list")

    if not isinstance(rule["references"], list):
        errors.append(f"{ctx}: 'references' must be a list")

    if not isinstance(rule["mitre"], dict):
        errors.append(f"{ctx}: 'mitre' must be an object")
    else:
        for mitre_key in ("tactic", "technique_id", "technique"):
            require_type(errors, rule["mitre"], mitre_key, str, f"{ctx}.mitre")

    detection_logic = rule["detection_logic"]
    if not isinstance(detection_logic, dict):
        errors.append(f"{ctx}: 'detection_logic' must be an object")
        return errors

    logic_type = detection_logic.get("type")
    if logic_type not in SUPPORTED_RULE_TYPES:
        errors.append(f"{ctx}: unsupported detection_logic.type '{logic_type}'")
        return errors

    if logic_type == "regex_any":
        if (
            not isinstance(detection_logic.get("fields"), list)
            or not detection_logic["fields"]
        ):
            errors.append(f"{ctx}: regex_any requires non-empty 'fields' list")
        if (
            not isinstance(detection_logic.get("patterns"), list)
            or not detection_logic["patterns"]
        ):
            errors.append(f"{ctx}: regex_any requires non-empty 'patterns' list")

    if logic_type == "threshold_count":
        if (
            not isinstance(detection_logic.get("group_by"), str)
            or not detection_logic["group_by"]
        ):
            errors.append(f"{ctx}: threshold_count requires non-empty 'group_by'")
        if (
            not isinstance(detection_logic.get("where"), list)
            or not detection_logic["where"]
        ):
            errors.append(
                f"{ctx}: threshold_count requires non-empty 'where' condition list"
            )
        if (
            not isinstance(detection_logic.get("min_count"), int)
            or detection_logic["min_count"] < 1
        ):
            errors.append(f"{ctx}: threshold_count requires integer 'min_count' >= 1")

    playbook_path = repo_root / rule["playbook"]
    if not playbook_path.exists():
        errors.append(f"{ctx}: playbook path does not exist: {rule['playbook']}")

    return errors


def parse_nginx_line(raw_line: str) -> dict[str, Any] | None:
    # Combined-like Nginx access format.
    pattern = re.compile(
        r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
        r"\"(?P<method>[A-Z]+) (?P<target>\S+) (?P<protocol>[^\"]+)\" "
        r"(?P<status>\d{3}) (?P<bytes>\S+) \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\"$"
    )
    match = pattern.match(raw_line)
    if not match:
        return None

    target = match.group("target")
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""

    return {
        "event.original": raw_line,
        "event.dataset": "nginx.access",
        "source.ip": match.group("ip"),
        "http.request.method": match.group("method"),
        "url.original": target,
        "url.path": path,
        "url.query": query,
        "http.response.status_code": int(match.group("status")),
        "http.request.referrer": match.group("ref"),
        "user_agent.original": match.group("ua"),
        "nginx.timestamp": match.group("ts"),
    }


def load_fixtures(
    log_path: Path, annotations_path: Path
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    raw_lines = [
        line.rstrip("\n")
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    annotations = load_json(annotations_path)
    if not isinstance(annotations, list):
        raise RuntimeError(f"{annotations_path} must be a JSON array")

    by_line: dict[int, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for obj in annotations:
        if not isinstance(obj, dict):
            raise RuntimeError(f"{annotations_path}: each annotation must be an object")
        fixture_id = obj.get("fixture_id")
        line_number = obj.get("line_number")
        if not isinstance(fixture_id, str) or not fixture_id:
            raise RuntimeError(
                f"{annotations_path}: annotation missing valid fixture_id"
            )
        if not isinstance(line_number, int) or line_number < 1:
            raise RuntimeError(
                f"{annotations_path}: annotation '{fixture_id}' has invalid line_number"
            )
        if line_number in by_line:
            raise RuntimeError(
                f"{annotations_path}: duplicate line_number {line_number}"
            )
        if fixture_id in by_id:
            raise RuntimeError(
                f"{annotations_path}: duplicate fixture_id '{fixture_id}'"
            )
        by_line[line_number] = obj
        by_id[fixture_id] = obj

    fixtures: list[dict[str, Any]] = []
    for index, line in enumerate(raw_lines, start=1):
        annotation = by_line.get(index)
        if annotation is None:
            raise RuntimeError(
                f"{annotations_path}: missing annotation for line {index}"
            )
        parsed = parse_nginx_line(line)
        if parsed is None:
            raise RuntimeError(f"{log_path}: could not parse line {index}: {line}")
        parsed["fixture_id"] = annotation["fixture_id"]
        parsed["fixture_note"] = annotation.get("note", "")
        parsed["fixture_category"] = annotation.get("category", "unknown")
        fixtures.append(parsed)

    for line_number in by_line:
        if line_number > len(raw_lines):
            raise RuntimeError(
                f"{annotations_path}: line_number {line_number} out of range (log has {len(raw_lines)} lines)"
            )

    return fixtures, by_id


def evaluate_condition(
    event: dict[str, Any], condition: dict[str, Any], case_insensitive: bool
) -> bool:
    field = condition.get("field")
    if not isinstance(field, str) or not field:
        return False
    value = event.get(field)

    if "equals" in condition:
        return value == condition["equals"]

    if "regex" in condition:
        if value is None:
            return False
        flags = re.IGNORECASE if case_insensitive else 0
        return re.search(str(condition["regex"]), str(value), flags=flags) is not None

    return False


def apply_rule(rule: dict[str, Any], fixtures: list[dict[str, Any]]) -> set[str]:
    logic = rule["detection_logic"]
    logic_type = logic["type"]
    case_insensitive = bool(logic.get("case_insensitive", False))

    if logic_type == "regex_any":
        fields = logic["fields"]
        flags = re.IGNORECASE if case_insensitive else 0
        patterns = [re.compile(pattern, flags=flags) for pattern in logic["patterns"]]
        matches: set[str] = set()
        for event in fixtures:
            for field in fields:
                value = event.get(field)
                if value is None:
                    continue
                value_text = str(value)
                if any(pattern.search(value_text) for pattern in patterns):
                    matches.add(event["fixture_id"])
                    break
        return matches

    if logic_type == "threshold_count":
        where_conditions = logic["where"]
        group_by = logic["group_by"]
        min_count = logic["min_count"]
        candidates: list[dict[str, Any]] = []
        for event in fixtures:
            if all(
                evaluate_condition(event, cond, case_insensitive)
                for cond in where_conditions
            ):
                candidates.append(event)

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in candidates:
            grouped[str(event.get(group_by, ""))].append(event)

        matches: set[str] = set()
        for _, grouped_events in grouped.items():
            if len(grouped_events) >= min_count:
                for event in grouped_events:
                    matches.add(event["fixture_id"])
        return matches

    raise RuntimeError(f"Unsupported rule type: {logic_type}")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="Offline detection harness for Nginx rules"
    )
    parser.add_argument(
        "--rules-dir",
        default=str(repo_root / "config/detections/nginx/rules"),
        help="Directory containing rule JSON files",
    )
    parser.add_argument(
        "--log-file",
        default=str(repo_root / "samples/logs/nginx_access.log"),
        help="Path to raw Nginx fixture log file",
    )
    parser.add_argument(
        "--annotations",
        default=str(repo_root / "tests/fixture_annotations.json"),
        help="Path to fixture annotation JSON file",
    )
    parser.add_argument(
        "--expected",
        default=str(repo_root / "tests/expected_hits.json"),
        help="Path to expected hits JSON file",
    )
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    log_file = Path(args.log_file)
    annotations = Path(args.annotations)
    expected_path = Path(args.expected)

    try:
        rule_paths = sorted(rules_dir.glob("*.json"))
        if not rule_paths:
            raise RuntimeError(f"No rule files found in {rules_dir}")

        rules: list[dict[str, Any]] = []
        seen_rule_ids: set[str] = set()
        schema_errors: list[str] = []
        for rule_path in rule_paths:
            rule_obj = load_json(rule_path)
            if not isinstance(rule_obj, dict):
                schema_errors.append(
                    f"{rule_path}: rule file root must be a JSON object"
                )
                continue
            schema_errors.extend(validate_rule_schema(rule_obj, rule_path, repo_root))
            rule_id = rule_obj.get("rule_id")
            if isinstance(rule_id, str):
                if rule_id in seen_rule_ids:
                    schema_errors.append(f"{rule_path}: duplicate rule_id '{rule_id}'")
                seen_rule_ids.add(rule_id)
            rules.append(rule_obj)

        if schema_errors:
            print("Schema validation failed:")
            for error in schema_errors:
                print(f"  - {error}")
            return 1

        fixtures, fixture_lookup = load_fixtures(log_file, annotations)
        expected = load_json(expected_path)
        if not isinstance(expected, dict):
            raise RuntimeError(f"{expected_path} must be a JSON object")

        print(f"Loaded {len(rules)} rules and {len(fixtures)} fixtures")

        failed = False
        for rule in rules:
            rule_id = rule["rule_id"]
            if rule_id not in expected:
                print(f"[FAIL] {rule_id}: missing expected hits entry")
                failed = True
                continue

            match_ids = apply_rule(rule, fixtures)
            exp = expected[rule_id]
            if not isinstance(exp, dict):
                print(f"[FAIL] {rule_id}: expected entry must be an object")
                failed = True
                continue

            must_hit = set(exp.get("must_hit", []))
            must_not_hit = set(exp.get("must_not_hit", []))
            missing = sorted(must_hit - match_ids)
            unexpected = sorted(match_ids & must_not_hit)

            if missing or unexpected:
                failed = True
                print(f"[FAIL] {rule_id}")
                if missing:
                    print(f"  missing required hits: {', '.join(missing)}")
                    for item in missing:
                        note = fixture_lookup.get(item, {}).get("note", "")
                        print(f"    - {item}: {note}")
                if unexpected:
                    print(f"  unexpected hits: {', '.join(unexpected)}")
                    for item in unexpected:
                        note = fixture_lookup.get(item, {}).get("note", "")
                        print(f"    - {item}: {note}")
            else:
                print(f"[PASS] {rule_id} ({len(match_ids)} hits)")

        expected_rule_ids = set(expected.keys())
        actual_rule_ids = {rule["rule_id"] for rule in rules}
        extra_expected = sorted(expected_rule_ids - actual_rule_ids)
        if extra_expected:
            failed = True
            print("[FAIL] expected hits includes unknown rule IDs:")
            for rule_id in extra_expected:
                print(f"  - {rule_id}")

        if failed:
            print("Detection harness result: FAILED")
            return 1

        print("Detection harness result: PASSED")
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
