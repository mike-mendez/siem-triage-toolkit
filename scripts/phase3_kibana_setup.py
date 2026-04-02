#!/usr/bin/env python3
"""Phase 3 Kibana setup utility.

Creates:
- Detection engine index
- Three detection rules for nginx-phase3-lab
- Data view + compact dashboard (4 visualizations)
- Export artifacts for rules and dashboard
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

RULE_DEFS = [
    {
        "rule_id": "phase3_nginx_sqli_querystring",
        "name": "Phase3 Nginx SQLi Pattern in Query String",
        "description": "Detect SQL injection style patterns in URL/query fields.",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "language": "kuery",
        "index": ["nginx-phase3-lab"],
        "query": (
            'url.original : ("/products?id=%27%20OR%201=1--" '
            'or "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users" '
            'or "/catalog?item=1%27%20AND%20SLEEP(5)--") '
            "or "
            'url.query : ("*UNION%20SELECT*" or "*SLEEP(5)*" or "*OR%201=1*")'
        ),
        "false_positives": [
            "Authorized security testing",
            "Internal QA replaying SQLi payloads",
        ],
        "tags": ["phase3", "nginx", "sqli", "T1190"],
    },
    {
        "rule_id": "phase3_nginx_webshell_path_probe",
        "name": "Phase3 Nginx Webshell Path Probe",
        "description": "Detect suspicious webshell and traversal-style path probes.",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "language": "kuery",
        "index": ["nginx-phase3-lab"],
        "query": (
            'url.path : ("*/shell.php*" or "*/cmd.php*" or "*/wp-content/uploads/*.php*" '
            'or "/cgi-bin/.%2e/.%2e/.%2e/bin/sh")'
        ),
        "false_positives": [
            "Authorized red-team activity",
            "Known scanner traffic",
        ],
        "tags": ["phase3", "nginx", "webshell", "T1505.003"],
    },
    {
        "rule_id": "phase3_nginx_404_recon_burst",
        "name": "Phase3 Nginx 404 Recon Burst",
        "description": "Detect >=5 sensitive-path 404 probes from one source IP.",
        "risk_score": 55,
        "severity": "medium",
        "type": "threshold",
        "language": "kuery",
        "index": ["nginx-phase3-lab"],
        "query": (
            'http.response.status_code: 404 and url.path : ("/wp-admin" or "/wp-login.php" or "/.env" or "/phpmyadmin/" or "/admin/")'
        ),
        "threshold": {"field": ["source.ip"], "value": 5},
        "false_positives": [
            "Known internal scanners",
            "Authorized exposure assessments",
        ],
        "tags": ["phase3", "nginx", "recon", "T1595"],
    },
]


def auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def request(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict | None = None,
    data: bytes | None = None,
    insecure: bool = False,
    ca_cert: str = "",
) -> tuple[int, str]:
    body = data
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, method=method, headers=headers, data=body)

    context = None
    if url.startswith("https://"):
        if ca_cert:
            context = ssl.create_default_context(cafile=ca_cert)
        elif insecure:
            context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(req, context=context) as resp:  # nosec B310
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def ensure_detection_index(
    kibana_url: str, headers: dict[str, str], insecure: bool, ca_cert: str
) -> None:
    code, body = request(
        "POST",
        f"{kibana_url}/api/detection_engine/index",
        headers,
        payload={},
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code not in (200, 201):
        # Index might already exist and sometimes returns conflict-like responses.
        if "already exists" not in body.lower():
            raise RuntimeError(f"Detection index create failed (HTTP {code}): {body}")


def delete_existing_rules(
    kibana_url: str, headers: dict[str, str], insecure: bool, ca_cert: str
) -> None:
    for rule in RULE_DEFS:
        code, _ = request(
            "DELETE",
            f"{kibana_url}/api/detection_engine/rules?rule_id={rule['rule_id']}",
            headers,
            insecure=insecure,
            ca_cert=ca_cert,
        )
        if code not in (200, 404):
            raise RuntimeError(
                f"Failed deleting existing rule {rule['rule_id']} (HTTP {code})"
            )


def create_rules(
    kibana_url: str, headers: dict[str, str], insecure: bool, ca_cert: str
) -> None:
    for rule in RULE_DEFS:
        payload = {
            "rule_id": rule["rule_id"],
            "name": rule["name"],
            "description": rule["description"],
            "risk_score": rule["risk_score"],
            "severity": rule["severity"],
            "type": rule["type"],
            "enabled": True,
            "interval": "1m",
            "from": "now-30d",
            "index": rule["index"],
            "query": rule["query"],
            "language": rule["language"],
            "false_positives": rule["false_positives"],
            "tags": rule["tags"],
        }
        if rule["type"] == "threshold":
            payload["threshold"] = rule["threshold"]
        code, body = request(
            "POST",
            f"{kibana_url}/api/detection_engine/rules",
            headers,
            payload=payload,
            insecure=insecure,
            ca_cert=ca_cert,
        )
        if code not in (200, 201):
            raise RuntimeError(
                f"Failed creating rule {rule['rule_id']} (HTTP {code}): {body}"
            )


def upsert_data_view(
    kibana_url: str, headers: dict[str, str], insecure: bool, ca_cert: str
) -> str:
    data_view_id = "phase3-nginx-data-view"
    payload = {
        "data_view": {
            "id": data_view_id,
            "title": "nginx-phase3-lab",
            "name": "nginx-phase3-lab",
            "timeFieldName": "@timestamp",
        },
        "override": True,
    }
    code, body = request(
        "POST",
        f"{kibana_url}/api/data_views/data_view",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Failed creating data view (HTTP {code}): {body}")
    return data_view_id


def vis_state_top_terms(title: str, field: str) -> str:
    return json.dumps(
        {
            "title": title,
            "type": "pie",
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {},
                },
                {
                    "id": "2",
                    "enabled": True,
                    "type": "terms",
                    "schema": "segment",
                    "params": {
                        "field": field,
                        "size": 10,
                        "order": "desc",
                        "orderBy": "1",
                    },
                },
            ],
            "params": {"addTooltip": True, "isDonut": True, "legendPosition": "right"},
        }
    )


def vis_state_404_over_time() -> str:
    return json.dumps(
        {
            "title": "404s Over Time",
            "type": "line",
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {},
                },
                {
                    "id": "2",
                    "enabled": True,
                    "type": "date_histogram",
                    "schema": "segment",
                    "params": {
                        "field": "@timestamp",
                        "calendar_interval": "1m",
                        "min_doc_count": 1,
                    },
                },
            ],
            "params": {"addLegend": True, "legendPosition": "right"},
        }
    )


def create_visualization(
    kibana_url: str,
    headers: dict[str, str],
    vis_id: str,
    title: str,
    vis_state: str,
    data_view_id: str,
    query: str = "",
    insecure: bool = False,
    ca_cert: str = "",
) -> None:
    search_source = {
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "index": data_view_id,
    }
    payload = {
        "attributes": {
            "title": title,
            "visState": vis_state,
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search_source)},
        },
        "references": [
            {
                "id": data_view_id,
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
            }
        ],
    }
    code, body = request(
        "POST",
        f"{kibana_url}/api/saved_objects/visualization/{vis_id}?overwrite=true",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code not in (200, 201):
        raise RuntimeError(
            f"Failed creating visualization {vis_id} (HTTP {code}): {body}"
        )


def create_dashboard(
    kibana_url: str, headers: dict[str, str], insecure: bool, ca_cert: str
) -> str:
    dashboard_id = "phase3-nginx-dashboard"
    panels = [
        {
            "panelIndex": "1",
            "gridData": {"x": 0, "y": 0, "w": 24, "h": 12, "i": "1"},
            "type": "visualization",
            "id": "phase3-top-source-ips",
        },
        {
            "panelIndex": "2",
            "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "2"},
            "type": "visualization",
            "id": "phase3-top-paths",
        },
        {
            "panelIndex": "3",
            "gridData": {"x": 0, "y": 12, "w": 24, "h": 12, "i": "3"},
            "type": "visualization",
            "id": "phase3-status-codes",
        },
        {
            "panelIndex": "4",
            "gridData": {"x": 24, "y": 12, "w": 24, "h": 12, "i": "4"},
            "type": "visualization",
            "id": "phase3-404-over-time",
        },
    ]
    payload = {
        "attributes": {
            "title": "Phase3 Nginx Detection Validation",
            "description": "Phase 3 compact dashboard for source/path/status validation.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"language": "kuery", "query": ""}, "filter": []}
                )
            },
        },
        "references": [
            {"id": "phase3-top-source-ips", "name": "panel_1", "type": "visualization"},
            {"id": "phase3-top-paths", "name": "panel_2", "type": "visualization"},
            {"id": "phase3-status-codes", "name": "panel_3", "type": "visualization"},
            {"id": "phase3-404-over-time", "name": "panel_4", "type": "visualization"},
        ],
    }
    code, body = request(
        "POST",
        f"{kibana_url}/api/saved_objects/dashboard/{dashboard_id}?overwrite=true",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code not in (200, 201):
        raise RuntimeError(f"Failed creating dashboard (HTTP {code}): {body}")
    return dashboard_id


def export_rules(
    kibana_url: str,
    headers: dict[str, str],
    out_path: Path,
    insecure: bool,
    ca_cert: str,
) -> None:
    payload = {
        "objects": [{"rule_id": r["rule_id"]} for r in RULE_DEFS],
        "exclude_export_details": True,
    }
    code, body = request(
        "POST",
        f"{kibana_url}/api/detection_engine/rules/_export",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code != 200:
        raise RuntimeError(f"Failed exporting rules (HTTP {code}): {body}")
    out_path.write_text(body, encoding="utf-8")


def export_dashboard(
    kibana_url: str,
    headers: dict[str, str],
    dashboard_id: str,
    out_path: Path,
    insecure: bool,
    ca_cert: str,
) -> None:
    payload = {
        "objects": [{"type": "dashboard", "id": dashboard_id}],
        "includeReferencesDeep": True,
    }
    code, body = request(
        "POST",
        f"{kibana_url}/api/saved_objects/_export",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code != 200:
        raise RuntimeError(f"Failed exporting dashboard (HTTP {code}): {body}")
    out_path.write_text(body, encoding="utf-8")


def export_timelines(
    kibana_url: str,
    headers: dict[str, str],
    out_path: Path,
    insecure: bool,
    ca_cert: str,
) -> None:
    payload = {"ids": []}
    code, body = request(
        "POST",
        f"{kibana_url}/api/timeline/_export?file_name={out_path.name}",
        headers,
        payload=payload,
        insecure=insecure,
        ca_cert=ca_cert,
    )
    if code != 200:
        raise RuntimeError(f"Failed exporting timelines (HTTP {code}): {body}")
    if body.strip():
        out_path.write_text(body, encoding="utf-8")
    else:
        # Keep artifact deterministic when no timelines are defined yet.
        out_path.write_text(
            '{"meta":"no_timelines_defined","exported":0}\n', encoding="utf-8"
        )


def wait_for_alerts(
    es_url: str,
    es_headers: dict[str, str],
    insecure: bool,
    ca_cert: str,
    timeout_sec: int = 180,
) -> dict[str, int]:
    end = time.time() + timeout_sec
    query = {
        "size": 0,
        "query": {
            "terms": {"kibana.alert.rule.rule_id": [r["rule_id"] for r in RULE_DEFS]}
        },
        "aggs": {
            "by_rule": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 10}}
        },
    }
    url = f"{es_url.rstrip('/')}/.internal.alerts-security.alerts-*/_search"
    while time.time() < end:
        code, body = request(
            "POST",
            url,
            {**es_headers, "Content-Type": "application/json"},
            payload=query,
            insecure=insecure,
            ca_cert=ca_cert,
        )
        if code == 200:
            resp = json.loads(body)
            buckets = resp.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
            counts = {bucket["key"]: int(bucket["doc_count"]) for bucket in buckets}
            if all(counts.get(r["rule_id"], 0) > 0 for r in RULE_DEFS):
                return counts
        time.sleep(10)
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Setup Phase 3 Kibana artifacts")
    parser.add_argument("--kibana-url", default="http://localhost:5601")
    parser.add_argument("--es-url", default="http://localhost:9200")
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--password", required=True)
    parser.add_argument("--rules-export", default="exports/kibana/rules.ndjson")
    parser.add_argument("--dashboard-export", default="exports/kibana/dashboard.ndjson")
    parser.add_argument("--timelines-export", default="exports/kibana/timelines.ndjson")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--ca-cert", default="")
    args = parser.parse_args()

    kbn_headers = {
        "Authorization": auth_header(args.username, args.password),
        "kbn-xsrf": "phase3-setup",
        "Content-Type": "application/json",
    }
    es_headers = {"Authorization": auth_header(args.username, args.password)}

    ensure_detection_index(args.kibana_url, kbn_headers, args.insecure, args.ca_cert)
    delete_existing_rules(args.kibana_url, kbn_headers, args.insecure, args.ca_cert)
    create_rules(args.kibana_url, kbn_headers, args.insecure, args.ca_cert)

    data_view_id = upsert_data_view(
        args.kibana_url, kbn_headers, args.insecure, args.ca_cert
    )
    create_visualization(
        args.kibana_url,
        kbn_headers,
        "phase3-top-source-ips",
        "Phase3 Top Source IPs",
        vis_state_top_terms("Phase3 Top Source IPs", "source.ip"),
        data_view_id,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    create_visualization(
        args.kibana_url,
        kbn_headers,
        "phase3-top-paths",
        "Phase3 Top Paths",
        vis_state_top_terms("Phase3 Top Paths", "url.path"),
        data_view_id,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    create_visualization(
        args.kibana_url,
        kbn_headers,
        "phase3-status-codes",
        "Phase3 Requests by Status",
        vis_state_top_terms("Phase3 Requests by Status", "http.response.status_code"),
        data_view_id,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    create_visualization(
        args.kibana_url,
        kbn_headers,
        "phase3-404-over-time",
        "Phase3 404s Over Time",
        vis_state_404_over_time(),
        data_view_id,
        query="http.response.status_code: 404",
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    dashboard_id = create_dashboard(
        args.kibana_url, kbn_headers, args.insecure, args.ca_cert
    )

    rules_export = Path(args.rules_export)
    dashboard_export = Path(args.dashboard_export)
    timelines_export = Path(args.timelines_export)
    rules_export.parent.mkdir(parents=True, exist_ok=True)
    dashboard_export.parent.mkdir(parents=True, exist_ok=True)
    timelines_export.parent.mkdir(parents=True, exist_ok=True)

    export_rules(
        args.kibana_url, kbn_headers, rules_export, args.insecure, args.ca_cert
    )
    export_dashboard(
        args.kibana_url,
        kbn_headers,
        dashboard_id,
        dashboard_export,
        args.insecure,
        args.ca_cert,
    )
    export_timelines(
        args.kibana_url, kbn_headers, timelines_export, args.insecure, args.ca_cert
    )

    counts = wait_for_alerts(
        args.es_url, es_headers, args.insecure, args.ca_cert, timeout_sec=210
    )
    if counts:
        print("alerts_ready=true")
        for rule in RULE_DEFS:
            print(f"{rule['rule_id']}={counts.get(rule['rule_id'], 0)}")
    else:
        print("alerts_ready=false")
        print("warning=No alerts observed for all rules before timeout")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
