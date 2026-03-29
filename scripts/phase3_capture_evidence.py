#!/usr/bin/env python3
"""Capture Phase 3 evidence artifacts from Elasticsearch APIs.

Generates:
- samples/evidence/phase3_<mode>_alerts.json
- samples/evidence/phase3_<mode>_aggregations.json
- samples/evidence/phase3_<mode>_rule_counts.json
- docs/phase3_results.md
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RULE_IDS = [
    "phase3_nginx_sqli_querystring",
    "phase3_nginx_webshell_path_probe",
    "phase3_nginx_404_recon_burst",
]


def auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def request_json(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
    insecure: bool = False,
    ca_cert: str = "",
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url=url, method=method, headers=headers, data=data)
    context = None
    if url.startswith("https://"):
        if ca_cert:
            context = ssl.create_default_context(cafile=ca_cert)
        elif insecure:
            context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, context=context) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body}") from exc


def get_field(data: dict[str, Any], path: str) -> Any:
    if path in data:
        return data[path]
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def pick_field(data: dict[str, Any], *paths: str, default: str = "n/a") -> Any:
    for path in paths:
        value = get_field(data, path)
        if value is not None and value != "":
            return value
    return default


def fmt_alert(alert: dict[str, Any]) -> str:
    src = pick_field(alert, "source.ip", default="n/a")
    rule = pick_field(alert, "kibana.alert.rule.rule_id", default="n/a")
    sev = pick_field(alert, "kibana.alert.severity", default="n/a")
    ts = pick_field(alert, "@timestamp", default="n/a")
    path = pick_field(alert, "url.path", "url.original", default="-")
    return f"{ts} | {sev:<6} | {rule:<34} | src={src:<15} | path={path}"


def save_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture Phase 3 evidence artifacts")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", required=True)
    parser.add_argument("--mode-label", default="baseline")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--ca-cert", default="")
    args = parser.parse_args()
    mode_slug = args.mode_label.lower().replace(" ", "_")
    captured_at = datetime.now(timezone.utc).isoformat()

    headers = {"Authorization": auth_header(args.username, args.password), "Content-Type": "application/json"}
    es_url = args.es_url.rstrip("/")
    evidence_dir = Path("samples/evidence")

    # --- Query 1: Fetch recent alerts ---
    alerts_query = {
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"terms": {"kibana.alert.rule.rule_id": RULE_IDS}},
    }
    alerts_resp = request_json(
        "POST",
        f"{es_url}/.internal.alerts-security.alerts-*/_search",
        headers,
        payload=alerts_query,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    alert_hits = [h["_source"] for h in alerts_resp.get("hits", {}).get("hits", [])]
    if not alert_hits:
        raise RuntimeError("No alert hits found in .internal.alerts-security.alerts-*")

    save_json(
        {"captured_at": captured_at, "query": alerts_query, "response": alerts_resp},
        evidence_dir / f"phase3_{mode_slug}_alerts.json",
    )

    # --- Query 2: Fetch aggregations ---
    agg_query = {
        "size": 0,
        "aggs": {
            "top_src": {"terms": {"field": "source.ip", "size": 5}},
            "top_path": {"terms": {"field": "url.path", "size": 5}},
            "status": {"terms": {"field": "http.response.status_code", "size": 10}},
            "status_404_over_time": {
                "filter": {"term": {"http.response.status_code": 404}},
                "aggs": {"per_min": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1m"}}},
            },
        },
    }
    agg_resp = request_json(
        "POST",
        f"{es_url}/nginx-phase3-lab/_search",
        headers,
        payload=agg_query,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    save_json(
        {"captured_at": captured_at, "query": agg_query, "response": agg_resp},
        evidence_dir / f"phase3_{mode_slug}_aggregations.json",
    )

    # --- Query 3: Fetch alert counts by rule ---
    rule_count_query = {
        "size": 0,
        "aggs": {"by_rule": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 10}}},
        "query": {"terms": {"kibana.alert.rule.rule_id": RULE_IDS}},
    }
    by_rule_resp = request_json(
        "POST",
        f"{es_url}/.internal.alerts-security.alerts-*/_search",
        headers,
        payload=rule_count_query,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    by_rule = {
        bucket["key"]: bucket["doc_count"]
        for bucket in by_rule_resp.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    }
    save_json(
        {"captured_at": captured_at, "query": rule_count_query, "response": by_rule_resp},
        evidence_dir / f"phase3_{mode_slug}_rule_counts.json",
    )

    # --- Generate results markdown ---
    top_src = agg_resp["aggregations"]["top_src"]["buckets"]
    top_path = agg_resp["aggregations"]["top_path"]["buckets"]
    status = agg_resp["aggregations"]["status"]["buckets"]
    alert_lines = [fmt_alert(a) for a in alert_hits[:12]]

    results_path = Path("docs/phase3_results.md")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    summary_lines = [
        "# Phase 3 Results",
        "",
        f"**Mode validated:** {args.mode_label}",
        f"**Captured at:** {captured_at}",
        "",
        "## Rule Outcomes",
        *[f"- `{rid}`: {by_rule.get(rid, 0)} alerts" for rid in RULE_IDS],
        "",
        "## Top Source IPs",
        *[f"- {b['key']}: {b['doc_count']} hits" for b in top_src],
        "",
        "## Top Paths",
        *[f"- {b['key']}: {b['doc_count']} hits" for b in top_path],
        "",
        "## Status Code Distribution",
        *[f"- {b['key']}: {b['doc_count']}" for b in status],
        "",
        "## Sample Alerts",
        "```",
        *alert_lines,
        "```",
        "",
        "## Tuning Notes",
        "- SQLi query was tightened to explicit fixture-aligned URL patterns for deterministic validation.",
        "- Webshell and recon rules generated repeat alerts as scheduled runs continued.",
        "- For production-like tuning, add dedup/suppression windows and scanner allowlists.",
        "",
        "## Evidence Artifacts",
        f"- `samples/evidence/phase3_{mode_slug}_alerts.json`",
        f"- `samples/evidence/phase3_{mode_slug}_aggregations.json`",
        f"- `samples/evidence/phase3_{mode_slug}_rule_counts.json`",
        "- `exports/kibana/rules.ndjson`",
        "- `exports/kibana/dashboard.ndjson`",
        "- `exports/kibana/timelines.ndjson`",
        "",
        "## Manual Captures Needed",
        "Take Kibana screenshots for the following views and save to `samples/screenshots/`:",
        f"- Alerts page filtered to Phase 3 rules -> `phase3_{mode_slug}_alert_list.png`",
        f"- Alert detail for one representative alert -> `phase3_{mode_slug}_alert_detail.png`",
        f"- Phase 3 dashboard overview -> `phase3_{mode_slug}_dashboard_summary.png`",
    ]

    if results_path.exists():
        existing = results_path.read_text(encoding="utf-8")
        canonical_marker = (
            "## Baseline Validation (HTTP)"
            if mode_slug == "baseline"
            else "## TLS Validation (HTTPS)"
        )
        if canonical_marker not in existing and f"**Mode validated:** {args.mode_label}" not in existing:
            results_path.write_text(
                existing.rstrip() + "\n\n---\n\n" + "\n".join(summary_lines[2:]) + "\n",
                encoding="utf-8",
            )
    else:
        results_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    # --- Console summary ---
    print(f"mode={args.mode_label}")
    print(f"captured_at={captured_at}")
    print(f"alerts_found={len(alert_hits)}")
    for rid in RULE_IDS:
        print(f"  {rid}={by_rule.get(rid, 0)}")
    print(f"evidence_dir={evidence_dir}")
    print(f"results_doc={results_path}")
    print("")
    print("REMINDER: Take manual Kibana screenshots for portfolio evidence.")
    print(f"  Save to samples/screenshots/phase3_{mode_slug}_*.png")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
