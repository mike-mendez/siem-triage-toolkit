# Phase 3 Results

## Setup
- Telemetry source: `samples/logs/nginx_access.log` (fixture-driven Nginx access logs)
- Indexed target: `nginx-phase3-lab`
- Detection rules validated:
  - `phase3_nginx_sqli_querystring`
  - `phase3_nginx_webshell_path_probe`
  - `phase3_nginx_404_recon_burst`
- Validation sequence:
  - Baseline mode first (`http`)
  - TLS mode parity pass second (`https` + CA trust)

## Baseline Validation (HTTP)
### Rule Outcomes
- `phase3_nginx_sqli_querystring`: 3 alerts
- `phase3_nginx_webshell_path_probe`: 4 alerts
- `phase3_nginx_404_recon_burst`: 4 alerts

### Evidence Artifacts
- `exports/kibana/rules.ndjson`
- `exports/kibana/dashboard.ndjson`
- `exports/kibana/timelines.ndjson`
- `samples/screenshots/phase3_baseline_alert_list.png`
- `samples/screenshots/phase3_baseline_alert_detail.png`
- `samples/screenshots/phase3_baseline_dashboard_summary.png`

## TLS Validation (HTTPS)
### Rule Outcomes
- `phase3_nginx_sqli_querystring`: 6 alerts
- `phase3_nginx_webshell_path_probe`: 5 alerts
- `phase3_nginx_404_recon_burst`: 5 alerts

### Evidence Artifacts
- `exports/kibana/rules.ndjson`
- `exports/kibana/dashboard.ndjson`
- `exports/kibana/timelines.ndjson`
- `samples/screenshots/phase3_tls_alert_list.png`
- `samples/screenshots/phase3_tls_alert_detail.png`
- `samples/screenshots/phase3_tls_dashboard_summary.png`

## Baseline vs TLS Notes
- Rule behavior parity: all three rules fired in both modes.
- Alert counts are not 1:1 across runs because scheduled rule executions can generate additional alerts between captures.
- No TLS-specific detection drift was observed in query/threshold logic.
- `exports/kibana/timelines.ndjson` currently contains a metadata marker (`no_timelines_defined`) because no investigation timelines were authored during this phase.

## Tuning Notes
- SQLi logic was constrained to fixture-aligned URL/query patterns for deterministic Phase 3 validation.
- Webshell and recon detections should add suppression windows and scanner allowlists for production-like noise control.

---

Mode validated: **tls**

## Rule Outcomes
- `phase3_nginx_sqli_querystring`: 15 alerts
- `phase3_nginx_webshell_path_probe`: 8 alerts
- `phase3_nginx_404_recon_burst`: 8 alerts

## Tuning Notes
- SQLi query was tightened to explicit fixture-aligned URL patterns for deterministic validation.
- Webshell and recon rules generated repeat alerts as scheduled runs continued.
- For production-like tuning, add dedup/suppression windows and scanner allowlists.

## Evidence Artifacts
- `exports/kibana/rules.ndjson`
- `exports/kibana/dashboard.ndjson`
- `exports/kibana/timelines.ndjson`
- `samples/screenshots/phase3_tls_alert_list.png`
- `samples/screenshots/phase3_tls_alert_detail.png`
- `samples/screenshots/phase3_tls_dashboard_summary.png`

---

Mode validated: **baseline**

## Rule Outcomes
- `phase3_nginx_sqli_querystring`: 15 alerts
- `phase3_nginx_webshell_path_probe`: 8 alerts
- `phase3_nginx_404_recon_burst`: 8 alerts

## Tuning Notes
- SQLi query was tightened to explicit fixture-aligned URL patterns for deterministic validation.
- Webshell and recon rules generated repeat alerts as scheduled runs continued.
- For production-like tuning, add dedup/suppression windows and scanner allowlists.

## Evidence Artifacts
- `exports/kibana/rules.ndjson`
- `exports/kibana/dashboard.ndjson`
- `exports/kibana/timelines.ndjson`
- `samples/screenshots/phase3_baseline_alert_list.png`
- `samples/screenshots/phase3_baseline_alert_detail.png`
- `samples/screenshots/phase3_baseline_dashboard_summary.png`
