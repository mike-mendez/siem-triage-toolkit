# Field Contract: Nginx Detection Pack (Phase 2)

## Purpose
Define ECS-aligned fields that Phase 2 detections assume exist before stack validation.
This contract prevents writing rules against fields that may not be produced by ingestion.

## Source
- Telemetry: Nginx access logs (combined-like format)
- Primary fixture file: `samples/logs/nginx_access.log`

## Contract Fields
| ECS/Field | Type | Source in Nginx Log | Why Needed | Expected Ingestion Owner |
|---|---|---|---|---|
| `event.original` | string | Full raw line | Evidence and parser fallback | Ingest pipeline |
| `source.ip` | ip/string | Client IP (first token) | Grouping and attribution | Nginx integration/parser |
| `http.request.method` | keyword | Request method in quoted request | Rule conditions and pivots | Nginx integration/parser |
| `url.original` | keyword | Full request target path+query | Primary match surface | Nginx integration/parser |
| `url.path` | keyword | Request target path (no query) | Path-based detections | Ingest pipeline transform |
| `url.query` | keyword | Request query string | SQLi-style detections | Ingest pipeline transform |
| `http.response.status_code` | int | Status code | Threshold/recon detection | Nginx integration/parser |
| `user_agent.original` | keyword | User-Agent | Triage context and suppression | Nginx integration/parser |
| `http.request.referrer` | keyword | Referer | Triage context | Nginx integration/parser |
| `event.dataset` | keyword | Static assignment (`nginx.access`) | Dataset filtering | Ingest pipeline |

## Detection Scope Assumptions
- Web traffic is internet-facing and can contain both benign and hostile probes.
- Query strings may include URL-encoded payloads.
- 404 bursts against admin/secrets paths are meaningful reconnaissance signals.

## Deferred to Phase 3
- Exact ingest path implementation (Elastic Agent, Filebeat module, or custom pipeline).
- Field normalization edge cases (IPv6, malformed lines, proxy chaining).
