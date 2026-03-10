#!/usr/bin/env python3
"""Ingest Nginx fixture logs into Elasticsearch for Phase 3 validation.

Uses Elasticsearch REST APIs only (stdlib HTTP client), creates a dedicated index
with explicit mapping, parses fixture lines, and submits via bulk API.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import re


def load_annotations(path: Path) -> dict[int, dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError(f"{path} must be a JSON array")
    by_line: dict[int, dict[str, object]] = {}
    for item in data:
        if not isinstance(item, dict):
            raise RuntimeError(f"{path} contains non-object annotation")
        line_number = item.get("line_number")
        if not isinstance(line_number, int):
            raise RuntimeError(f"{path} annotation missing integer line_number: {item}")
        by_line[line_number] = item
    return by_line


def parse_line(raw_line: str) -> dict[str, object]:
    pattern = re.compile(
        r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
        r"\"(?P<method>[A-Z]+) (?P<target>\S+) (?P<protocol>[^\"]+)\" "
        r"(?P<status>\d{3}) (?P<bytes>\S+) \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\"$"
    )
    match = pattern.match(raw_line)
    if not match:
        raise RuntimeError(f"Could not parse nginx line: {raw_line}")

    target = match.group("target")
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""

    return {
        "event": {"dataset": "nginx.access", "original": raw_line},
        "source": {"ip": match.group("ip")},
        "http": {
            "request": {"method": match.group("method"), "referrer": match.group("ref")},
            "response": {"status_code": int(match.group("status"))},
        },
        "url": {"original": target, "path": path, "query": query},
        "user_agent": {"original": match.group("ua")},
        "labels": {},
    }


def to_iso8601(ts: str) -> str:
    # Example input: 09/Mar/2026:10:00:01 +0000
    # Convert manually to avoid extra dependencies.
    month_map = {
        "Jan": "01",
        "Feb": "02",
        "Mar": "03",
        "Apr": "04",
        "May": "05",
        "Jun": "06",
        "Jul": "07",
        "Aug": "08",
        "Sep": "09",
        "Oct": "10",
        "Nov": "11",
        "Dec": "12",
    }
    date_part, tz = ts.split(" ")
    day, mon, rest = date_part.split("/")
    year, hh, mm, ss = rest.split(":")
    month = month_map[mon]
    return f"{year}-{month}-{day}T{hh}:{mm}:{ss}{tz[:3]}:{tz[3:]}"


def auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    return f"Basic {token}"


def request_json(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, object] | None = None,
    insecure: bool = False,
) -> tuple[int, str]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, method=method, headers=headers, data=data)
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, context=context) as resp:  # nosec B310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def request_text(
    method: str,
    url: str,
    headers: dict[str, str],
    data: str | None = None,
    insecure: bool = False,
) -> tuple[int, str]:
    payload = data.encode("utf-8") if data is not None else None
    req = urllib.request.Request(url=url, method=method, headers=headers, data=payload)
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, context=context) as resp:  # nosec B310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def build_mapping() -> dict[str, object]:
    return {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "dataset": {"type": "keyword"},
                        "original": {"type": "wildcard"},
                    }
                },
                "source": {"properties": {"ip": {"type": "ip"}}},
                "http": {
                    "properties": {
                        "request": {
                            "properties": {
                                "method": {"type": "keyword"},
                                "referrer": {"type": "wildcard"},
                            }
                        },
                        "response": {"properties": {"status_code": {"type": "integer"}}},
                    }
                },
                "url": {
                    "properties": {
                        "original": {"type": "wildcard"},
                        "path": {"type": "wildcard"},
                        "query": {"type": "wildcard"},
                    }
                },
                "user_agent": {"properties": {"original": {"type": "wildcard"}}},
                "labels": {
                    "properties": {
                        "fixture_id": {"type": "keyword"},
                        "fixture_category": {"type": "keyword"},
                        "fixture_note": {"type": "wildcard"},
                    }
                },
            }
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3 Nginx fixture ingestion")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--index", default="nginx-phase3-lab")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", required=True)
    parser.add_argument("--log-file", default="samples/logs/nginx_access.log")
    parser.add_argument("--annotations", default="tests/fixture_annotations.json")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--ca-cert", default="", help="CA certificate for HTTPS ES")
    parser.add_argument("--skip-delete", action="store_true", help="Do not delete existing index")
    args = parser.parse_args()

    es_url = args.es_url.rstrip("/")
    log_path = Path(args.log_file)
    annotations_path = Path(args.annotations)
    if not log_path.exists():
        raise RuntimeError(f"Missing log file: {log_path}")
    if not annotations_path.exists():
        raise RuntimeError(f"Missing annotations file: {annotations_path}")

    if args.ca_cert:
        ssl_context = ssl.create_default_context(cafile=args.ca_cert)
        ssl._create_default_https_context = lambda: ssl_context  # type: ignore[assignment]

    headers = {
        "Authorization": auth_header(args.username, args.password),
        "Content-Type": "application/json",
    }

    if not args.skip_delete:
        code, _ = request_json("DELETE", f"{es_url}/{args.index}", headers, insecure=args.insecure)
        if code not in (200, 404):
            raise RuntimeError(f"Failed deleting existing index '{args.index}' (HTTP {code})")

    code, body = request_json(
        "PUT",
        f"{es_url}/{args.index}",
        headers,
        payload=build_mapping(),
        insecure=args.insecure,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Failed creating index '{args.index}' (HTTP {code}): {body}")

    annotations = load_annotations(annotations_path)
    raw_lines = [line.rstrip("\n") for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    bulk_lines: list[str] = []
    sent = 0
    for idx, raw in enumerate(raw_lines, start=1):
        event = parse_line(raw)
        annotation = annotations.get(idx)
        if annotation is None:
            continue
        fixture_id = annotation.get("fixture_id", f"FX{idx:03d}")
        fixture_note = annotation.get("note", "")
        fixture_category = annotation.get("category", "unknown")
        event["labels"] = {
            "fixture_id": fixture_id,
            "fixture_note": fixture_note,
            "fixture_category": fixture_category,
        }
        ts = parse_line(raw)["event"]["original"]  # not used directly, keep parsing consistent
        del ts
        nginx_ts = re.search(r"\[(?P<ts>[^\]]+)\]", raw)
        if nginx_ts:
            event["@timestamp"] = to_iso8601(nginx_ts.group("ts"))
        else:
            event["@timestamp"] = "1970-01-01T00:00:00+00:00"
        bulk_lines.append(json.dumps({"index": {"_index": args.index, "_id": str(fixture_id)}}))
        bulk_lines.append(json.dumps(event))
        sent += 1

    payload = "\n".join(bulk_lines) + "\n"
    code, body = request_text(
        "POST",
        f"{es_url}/_bulk?refresh=true",
        {"Authorization": headers["Authorization"], "Content-Type": "application/x-ndjson"},
        data=payload,
        insecure=args.insecure,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Bulk ingest failed (HTTP {code}): {body}")

    resp = json.loads(body)
    if resp.get("errors"):
        failed = sum(1 for item in resp.get("items", []) if item.get("index", {}).get("error"))
        raise RuntimeError(f"Bulk ingest completed with errors; failed items: {failed}")

    count_code, count_body = request_json(
        "GET", f"{es_url}/{args.index}/_count", headers, insecure=args.insecure
    )
    if count_code != 200:
        raise RuntimeError(f"Could not verify count (HTTP {count_code}): {count_body}")
    indexed = json.loads(count_body).get("count", -1)

    print(f"index={args.index} sent={sent} indexed={indexed} skipped={len(raw_lines) - sent}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
