#!/usr/bin/env python3
"""Offline validation harness for Nginx detection rules.

Validates three quality gates:
1) Rule metadata contract via JSON schema.
2) Fixture and annotation integrity.
3) Expected hit assertions per rule.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

TYPE_MAP: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc


def validate_by_schema(instance: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    schema_type = schema.get("type")
    if isinstance(schema_type, str):
        expected_types = TYPE_MAP.get(schema_type)
        if expected_types is None:
            errors.append(f"{path}: unsupported schema type '{schema_type}'")
            return
        if not isinstance(instance, expected_types):
            errors.append(f"{path}: expected {schema_type}, got {type(instance).__name__}")
            return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant value {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']}, got {instance!r}")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            errors.append(f"{path}: minLength {min_length} violated")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, instance) is None:
            errors.append(f"{path}: value {instance!r} does not match pattern {pattern!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            errors.append(f"{path}: minimum {minimum} violated")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            errors.append(f"{path}: minItems {min_items} violated")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(instance):
                validate_by_schema(item, item_schema, f"{path}[{idx}]", errors)

    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    errors.append(f"{path}: missing required key '{key}'")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, sub_schema in properties.items():
                if key in instance and isinstance(sub_schema, dict):
                    validate_by_schema(instance[key], sub_schema, f"{path}.{key}", errors)

        min_props = schema.get("minProperties")
        if isinstance(min_props, int) and len(instance) < min_props:
            errors.append(f"{path}: minProperties {min_props} violated")

        if schema.get("additionalProperties") is False and isinstance(properties, dict):
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected key '{key}'")

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        match_count = 0
        for sub_schema in one_of:
            if not isinstance(sub_schema, dict):
                continue
            local_errors: list[str] = []
            validate_by_schema(instance, sub_schema, path, local_errors)
            if not local_errors:
                match_count += 1
        if match_count != 1:
            errors.append(f"{path}: expected exactly one oneOf branch match, got {match_count}")


def parse_nginx_line(raw_line: str) -> dict[str, Any] | None:
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


def load_fixtures(log_path: Path, annotations_path: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
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
            errors.append(f"{annotations_path}: each annotation must be an object")
            continue
        fixture_id = obj.get("fixture_id")
        line_number = obj.get("line_number")
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"{annotations_path}: annotation missing valid fixture_id")
            continue
        if not isinstance(line_number, int) or line_number < 1:
            errors.append(f"{annotations_path}: annotation '{fixture_id}' has invalid line_number")
            continue
        if line_number in by_line:
            errors.append(f"{annotations_path}: duplicate line_number {line_number}")
        if fixture_id in by_id:
            errors.append(f"{annotations_path}: duplicate fixture_id '{fixture_id}'")
        by_line[line_number] = obj
        by_id[fixture_id] = obj

    fixtures: list[dict[str, Any]] = []
    for index, line in enumerate(raw_lines, start=1):
        annotation = by_line.get(index)
        if annotation is None:
            errors.append(f"{annotations_path}: missing annotation for line {index}")
            continue
        parsed = parse_nginx_line(line)
        if parsed is None:
            errors.append(f"{log_path}: could not parse line {index}: {line}")
            continue
        parsed["fixture_id"] = annotation["fixture_id"]
        parsed["fixture_note"] = annotation.get("note", "")
        parsed["fixture_category"] = annotation.get("category", "unknown")
        fixtures.append(parsed)

    for line_number in by_line:
        if line_number > len(raw_lines):
            errors.append(f"{annotations_path}: line_number {line_number} out of range (log has {len(raw_lines)} lines)")

    return fixtures, by_id, errors


def evaluate_condition(event: dict[str, Any], condition: dict[str, Any], case_insensitive: bool) -> bool:
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
                if any(pattern.search(str(value)) for pattern in patterns):
                    matches.add(event["fixture_id"])
                    break
        return matches

    if logic_type == "threshold_count":
        where_conditions = logic["where"]
        group_by = logic["group_by"]
        min_count = logic["min_count"]

        candidates: list[dict[str, Any]] = []
        for event in fixtures:
            if all(evaluate_condition(event, cond, case_insensitive) for cond in where_conditions):
                candidates.append(event)

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in candidates:
            grouped[str(event.get(group_by, ""))].append(event)

        matches: set[str] = set()
        for grouped_events in grouped.values():
            if len(grouped_events) >= min_count:
                for event in grouped_events:
                    matches.add(event["fixture_id"])
        return matches

    raise RuntimeError(f"Unsupported rule type: {logic_type}")


def validate_expectations(expected: Any, rule_ids: set[str], fixture_lookup: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if not isinstance(expected, dict):
        return ["expected hits document must be a JSON object"]

    for rule_id in sorted(rule_ids):
        entry = expected.get(rule_id)
        if not isinstance(entry, dict):
            errors.append(f"expected hits: missing/invalid object for rule '{rule_id}'")
            continue

        must_hit = entry.get("must_hit")
        must_not_hit = entry.get("must_not_hit")
        if not isinstance(must_hit, list) or not must_hit:
            errors.append(f"expected hits '{rule_id}': must_hit must be a non-empty list")
        if not isinstance(must_not_hit, list) or not must_not_hit:
            errors.append(f"expected hits '{rule_id}': must_not_hit must be a non-empty list")

        for key in ("must_hit", "must_not_hit"):
            values = entry.get(key, [])
            if isinstance(values, list):
                for fixture_id in values:
                    if not isinstance(fixture_id, str):
                        errors.append(f"expected hits '{rule_id}': {key} contains non-string value")
                        continue
                    if fixture_id not in fixture_lookup:
                        errors.append(f"expected hits '{rule_id}': {key} references unknown fixture '{fixture_id}'")

    extra_rule_ids = sorted(set(expected.keys()) - rule_ids)
    for rule_id in extra_rule_ids:
        errors.append(f"expected hits includes unknown rule id '{rule_id}'")

    return errors


def build_text_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Loaded {report['rules_total']} rules and {report['fixtures_total']} fixtures")

    lines.append("\nGate 1: schema validation")
    if report["schema"]["status"] == "passed":
        lines.append("[PASS] rule schema")
    else:
        lines.append("[FAIL] rule schema")
        for error in report["schema"]["errors"]:
            lines.append(f"  - {error}")

    lines.append("\nGate 2: fixture + expectation integrity")
    if report["integrity"]["status"] == "passed":
        lines.append("[PASS] fixture and expected-hit contracts")
    else:
        lines.append("[FAIL] fixture and expected-hit contracts")
        for error in report["integrity"]["errors"]:
            lines.append(f"  - {error}")

    lines.append("\nGate 3: detection outcomes")
    for result in report["rule_results"]:
        if result["status"] == "passed":
            lines.append(f"[PASS] {result['rule_id']} ({result['hit_count']} hits)")
        else:
            lines.append(f"[FAIL] {result['rule_id']}")
            if result["missing_required_hits"]:
                lines.append("  missing required hits: " + ", ".join(result["missing_required_hits"]))
            if result["unexpected_hits"]:
                lines.append("  unexpected hits: " + ", ".join(result["unexpected_hits"]))

    lines.append(f"\nDetection harness result: {'PASSED' if report['status'] == 'passed' else 'FAILED'}")
    return "\n".join(lines)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(description="Offline detection harness for Nginx rules")
    parser.add_argument("--rules-dir", default=str(repo_root / "config/detections/nginx/rules"), help="Directory containing rule JSON files")
    parser.add_argument("--schema", default=str(repo_root / "config/detections/rule.schema.json"), help="Rule schema file")
    parser.add_argument("--log-file", default=str(repo_root / "samples/logs/nginx_access.log"), help="Path to raw Nginx fixture log file")
    parser.add_argument("--annotations", default=str(repo_root / "tests/fixture_annotations.json"), help="Path to fixture annotation JSON file")
    parser.add_argument("--expected", default=str(repo_root / "tests/expected_hits.json"), help="Path to expected hits JSON file")
    parser.add_argument("--output-format", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--json-file", default="", help="Optional path to write JSON report")
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    schema_path = Path(args.schema)
    log_file = Path(args.log_file)
    annotations = Path(args.annotations)
    expected_path = Path(args.expected)

    try:
        schema_obj = load_json(schema_path)
        if not isinstance(schema_obj, dict):
            raise RuntimeError(f"{schema_path} must be a JSON object")

        rule_paths = sorted(rules_dir.glob("*.json"))
        if not rule_paths:
            raise RuntimeError(f"No rule files found in {rules_dir}")

        rules: list[dict[str, Any]] = []
        schema_errors: list[str] = []
        seen_rule_ids: set[str] = set()

        for rule_path in rule_paths:
            rule_obj = load_json(rule_path)
            if not isinstance(rule_obj, dict):
                schema_errors.append(f"{rule_path}: rule file root must be a JSON object")
                continue

            validate_by_schema(rule_obj, schema_obj, str(rule_path), schema_errors)

            playbook_path = repo_root / str(rule_obj.get("playbook", ""))
            if not playbook_path.exists():
                schema_errors.append(f"{rule_path}: playbook path does not exist: {rule_obj.get('playbook')}")

            rule_id = rule_obj.get("rule_id")
            if isinstance(rule_id, str):
                if rule_id in seen_rule_ids:
                    schema_errors.append(f"{rule_path}: duplicate rule_id '{rule_id}'")
                seen_rule_ids.add(rule_id)

            rules.append(rule_obj)

        fixtures, fixture_lookup, fixture_errors = load_fixtures(log_file, annotations)
        expected = load_json(expected_path)

        integrity_errors: list[str] = []
        integrity_errors.extend(fixture_errors)
        integrity_errors.extend(validate_expectations(expected, seen_rule_ids, fixture_lookup))

        failed = bool(schema_errors or integrity_errors)
        rule_results: list[dict[str, Any]] = []

        if not failed:
            for rule in rules:
                rule_id = str(rule["rule_id"])
                expected_entry = expected[rule_id]
                match_ids = apply_rule(rule, fixtures)
                must_hit = set(expected_entry["must_hit"])
                must_not_hit = set(expected_entry["must_not_hit"])
                missing = sorted(must_hit - match_ids)
                unexpected = sorted(match_ids & must_not_hit)
                status = "passed" if not missing and not unexpected else "failed"
                if status == "failed":
                    failed = True
                rule_results.append({
                    "rule_id": rule_id,
                    "status": status,
                    "hit_count": len(match_ids),
                    "missing_required_hits": missing,
                    "unexpected_hits": unexpected,
                })

        report: dict[str, Any] = {
            "status": "failed" if failed else "passed",
            "rules_total": len(rules),
            "fixtures_total": len(fixtures),
            "schema": {"status": "failed" if schema_errors else "passed", "errors": schema_errors},
            "integrity": {"status": "failed" if integrity_errors else "passed", "errors": integrity_errors},
            "rule_results": rule_results,
            "summary": {
                "passed_rules": sum(1 for item in rule_results if item["status"] == "passed"),
                "failed_rules": sum(1 for item in rule_results if item["status"] == "failed"),
            },
        }

        rendered = json.dumps(report, indent=2, sort_keys=True) if args.output_format == "json" else build_text_report(report)

        if args.json_file:
            json_path = Path(args.json_file)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(rendered)
        return 0 if report["status"] == "passed" else 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
