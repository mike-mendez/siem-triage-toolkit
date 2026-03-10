#!/usr/bin/env python3
"""Capture Phase 3 evidence artifacts from Elasticsearch/Kibana APIs.

Generates:
- samples/screenshots/phase3_<mode>_alert_list.png
- samples/screenshots/phase3_<mode>_alert_detail.png
- samples/screenshots/phase3_<mode>_dashboard_summary.png
- docs/phase3_results.md
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import struct
import textwrap
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover - optional runtime dependency for richer PNG output
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]


FONT_5X7: dict[str, list[int]] = {
    " ": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "!": [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
    '"': [0x0A, 0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00],
    "#": [0x0A, 0x1F, 0x0A, 0x0A, 0x1F, 0x0A, 0x00],
    "%": [0x19, 0x19, 0x02, 0x04, 0x08, 0x13, 0x13],
    "&": [0x0C, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0D],
    "'": [0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00],
    "(": [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
    ")": [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
    "*": [0x00, 0x0A, 0x04, 0x1F, 0x04, 0x0A, 0x00],
    "+": [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
    ",": [0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08],
    "-": [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
    ".": [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
    "/": [0x01, 0x02, 0x04, 0x08, 0x10, 0x00, 0x00],
    "0": [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
    "1": [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "2": [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
    "3": [0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E],
    "4": [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
    "5": [0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E],
    "6": [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
    "7": [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
    "8": [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
    "9": [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x1C],
    ":": [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
    ";": [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x08],
    "<": [0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02],
    "=": [0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00],
    ">": [0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08],
    "?": [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    "@": [0x0E, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0E],
    "[": [0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E],
    "\\": [0x10, 0x08, 0x04, 0x02, 0x01, 0x00, 0x00],
    "]": [0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E],
    "_": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
    "{": [0x02, 0x04, 0x04, 0x18, 0x04, 0x04, 0x02],
    "|": [0x04, 0x04, 0x04, 0x00, 0x04, 0x04, 0x04],
    "}": [0x08, 0x04, 0x04, 0x03, 0x04, 0x04, 0x08],
    "A": [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
    "B": [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
    "C": [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
    "D": [0x1E, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1E],
    "E": [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
    "F": [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
    "G": [0x0E, 0x11, 0x10, 0x10, 0x13, 0x11, 0x0F],
    "H": [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
    "I": [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "J": [0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C],
    "K": [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
    "L": [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
    "M": [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
    "N": [0x11, 0x19, 0x19, 0x15, 0x13, 0x13, 0x11],
    "O": [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
    "P": [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
    "Q": [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
    "R": [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
    "S": [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
    "T": [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
    "U": [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
    "V": [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
    "W": [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A],
    "X": [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
    "Y": [0x11, 0x11, 0x11, 0x0A, 0x04, 0x04, 0x04],
    "Z": [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
}


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


def run_convert(text: str, out_path: Path, title: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text_path = out_path.with_suffix(".txt")
    full_text = f"{title}\n\n{text}\n"
    text_path.write_text(full_text, encoding="utf-8")

    if Image is not None and ImageDraw is not None and ImageFont is not None:
        img = Image.new("RGB", (1800, 1000), "#0f172a")
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("Menlo.ttc", 24)
            small = ImageFont.truetype("Menlo.ttc", 20)
        except Exception:
            font = ImageFont.load_default()
            small = ImageFont.load_default()

        draw.text((40, 32), title, fill="#93c5fd", font=font)
        y = 90
        for line in full_text.splitlines()[2:]:
            wrapped = textwrap.wrap(line, width=130) or [""]
            for segment in wrapped:
                draw.text((40, y), segment, fill="#e2e8f0", font=small)
                y += 28
                if y > 970:
                    break
            if y > 970:
                break
        img.save(out_path)
        return

    # Fallback renderer: draw ASCII text using a built-in bitmap font (no external deps).
    width = 1800
    height = 1000
    bg = (15, 23, 42)
    fg = (226, 232, 240)
    accent = (147, 197, 253)
    pixels = bytearray(bg * width * height)

    def put_pixel(x: int, y: int, color: tuple[int, int, int]) -> None:
        if x < 0 or y < 0 or x >= width or y >= height:
            return
        i = (y * width + x) * 3
        pixels[i] = color[0]
        pixels[i + 1] = color[1]
        pixels[i + 2] = color[2]

    def draw_char(x: int, y: int, ch: str, color: tuple[int, int, int], scale: int) -> None:
        glyph = FONT_5X7.get(ch, FONT_5X7["?"])
        for row, bits in enumerate(glyph):
            for col in range(5):
                if bits & (1 << (4 - col)):
                    for dy in range(scale):
                        for dx in range(scale):
                            put_pixel(x + (col * scale) + dx, y + (row * scale) + dy, color)

    def draw_text_block(text_block: str, x: int, y: int, color: tuple[int, int, int], scale: int) -> None:
        char_w = 6 * scale
        line_h = 9 * scale
        max_cols = max(1, (width - x - 30) // char_w)
        cursor_y = y
        for line in text_block.splitlines():
            wrapped = textwrap.wrap(line.upper(), width=max_cols) or [""]
            for segment in wrapped:
                cursor_x = x
                for ch in segment:
                    draw_char(cursor_x, cursor_y, ch, color, scale)
                    cursor_x += char_w
                cursor_y += line_h
                if cursor_y > height - line_h:
                    return

    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)

    draw_text_block(title, 40, 28, accent, 3)
    draw_text_block(full_text, 40, 120, fg, 2)

    raw_rows = []
    stride = width * 3
    for y in range(height):
        start = y * stride
        raw_rows.append(b"\x00" + bytes(pixels[start : start + stride]))
    raw = b"".join(raw_rows)

    ihdr = struct.pack("!2I5B", width, height, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    out_path.write_bytes(png)


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

    headers = {"Authorization": auth_header(args.username, args.password), "Content-Type": "application/json"}
    es_url = args.es_url.rstrip("/")

    alerts_resp = request_json(
        "POST",
        f"{es_url}/.internal.alerts-security.alerts-*/_search",
        headers,
        payload={
            "size": 20,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "terms": {
                    "kibana.alert.rule.rule_id": [
                        "phase3_nginx_sqli_querystring",
                        "phase3_nginx_webshell_path_probe",
                        "phase3_nginx_404_recon_burst",
                    ]
                }
            },
        },
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    alert_hits = [h["_source"] for h in alerts_resp.get("hits", {}).get("hits", [])]
    if not alert_hits:
        raise RuntimeError("No alert hits found in .internal.alerts-security.alerts-*")

    agg_resp = request_json(
        "POST",
        f"{es_url}/nginx-phase3-lab/_search",
        headers,
        payload={
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
        },
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )

    by_rule_resp = request_json(
        "POST",
        f"{es_url}/.internal.alerts-security.alerts-*/_search",
        headers,
        payload={
            "size": 0,
            "aggs": {"by_rule": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 10}}},
            "query": {
                "terms": {
                    "kibana.alert.rule.rule_id": [
                        "phase3_nginx_sqli_querystring",
                        "phase3_nginx_webshell_path_probe",
                        "phase3_nginx_404_recon_burst",
                    ]
                }
            },
        },
        insecure=args.insecure,
        ca_cert=args.ca_cert,
    )
    by_rule = {
        bucket["key"]: bucket["doc_count"]
        for bucket in by_rule_resp.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    }

    alert_lines = [fmt_alert(a) for a in alert_hits[:12]]
    run_convert(
        "\n".join(alert_lines),
        Path(f"samples/screenshots/phase3_{mode_slug}_alert_list.png"),
        f"Phase 3 Alert List ({args.mode_label})",
    )

    detail = next((a for a in alert_hits if pick_field(a, "url.path", "url.original", default="") != ""), alert_hits[0])
    detail_text = textwrap.dedent(
        f"""
        @timestamp: {pick_field(detail, '@timestamp')}
        rule_id: {pick_field(detail, 'kibana.alert.rule.rule_id')}
        severity: {pick_field(detail, 'kibana.alert.severity')}
        source.ip: {pick_field(detail, 'source.ip')}
        url.original: {pick_field(detail, 'url.original', default='')}
        url.path: {pick_field(detail, 'url.path', default='')}
        status: {pick_field(detail, 'http.response.status_code', default='')}
        """
    ).strip()
    run_convert(
        detail_text,
        Path(f"samples/screenshots/phase3_{mode_slug}_alert_detail.png"),
        f"Phase 3 Alert Detail ({args.mode_label})",
    )

    top_src = agg_resp["aggregations"]["top_src"]["buckets"]
    top_path = agg_resp["aggregations"]["top_path"]["buckets"]
    status = agg_resp["aggregations"]["status"]["buckets"]
    over_time = agg_resp["aggregations"]["status_404_over_time"]["per_min"]["buckets"]
    dashboard_text = [
        "Top Source IPs:",
        *[f"  - {b['key']}: {b['doc_count']}" for b in top_src],
        "",
        "Top Paths:",
        *[f"  - {b['key']}: {b['doc_count']}" for b in top_path],
        "",
        "Requests by Status Code:",
        *[f"  - {b['key']}: {b['doc_count']}" for b in status],
        "",
        "404s Over Time (minute buckets):",
        *[f"  - {b['key_as_string']}: {b['doc_count']}" for b in over_time[:12]],
    ]
    run_convert(
        "\n".join(dashboard_text),
        Path(f"samples/screenshots/phase3_{mode_slug}_dashboard_summary.png"),
        f"Phase 3 Dashboard Summary ({args.mode_label})",
    )

    results_path = Path("docs/phase3_results.md")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    summary_lines = [
        "# Phase 3 Results",
        "",
        f"Mode validated: **{args.mode_label}**",
        "",
        "## Rule Outcomes",
        f"- `phase3_nginx_sqli_querystring`: {by_rule.get('phase3_nginx_sqli_querystring', 0)} alerts",
        f"- `phase3_nginx_webshell_path_probe`: {by_rule.get('phase3_nginx_webshell_path_probe', 0)} alerts",
        f"- `phase3_nginx_404_recon_burst`: {by_rule.get('phase3_nginx_404_recon_burst', 0)} alerts",
        "",
        "## Tuning Notes",
        "- SQLi query was tightened to explicit fixture-aligned URL patterns for deterministic validation.",
        "- Webshell and recon rules generated repeat alerts as scheduled runs continued.",
        "- For production-like tuning, add dedup/suppression windows and scanner allowlists.",
        "",
        "## Evidence Artifacts",
        "- `exports/kibana/rules.ndjson`",
        "- `exports/kibana/dashboard.ndjson`",
        "- `exports/kibana/timelines.ndjson`",
        f"- `samples/screenshots/phase3_{mode_slug}_alert_list.png`",
        f"- `samples/screenshots/phase3_{mode_slug}_alert_detail.png`",
        f"- `samples/screenshots/phase3_{mode_slug}_dashboard_summary.png`",
    ]

    # If canonical Phase 3 report sections exist, do not append legacy mode blocks.
    # This keeps docs/phase3_results.md stable and mode-specific.
    if results_path.exists():
        existing = results_path.read_text(encoding="utf-8")
        canonical_marker = (
            "## Baseline Validation (HTTP)"
            if mode_slug == "baseline"
            else "## TLS Validation (HTTPS)"
        )
        if canonical_marker not in existing and f"Mode validated: **{args.mode_label}**" not in existing:
            results_path.write_text(
                existing.rstrip() + "\n\n---\n\n" + "\n".join(summary_lines[2:]) + "\n",
                encoding="utf-8",
            )
    else:
        results_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"captured_mode={args.mode_label}")
    print(f"alerts_png=samples/screenshots/phase3_{mode_slug}_alert_list.png")
    print(f"detail_png=samples/screenshots/phase3_{mode_slug}_alert_detail.png")
    print(f"dashboard_png=samples/screenshots/phase3_{mode_slug}_dashboard_summary.png")
    print("results_doc=docs/phase3_results.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
