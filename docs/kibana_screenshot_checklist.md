# Native Kibana Screenshot Checklist

## Purpose
Capture interview-grade evidence directly from Kibana UI (not generated summaries) so alert behavior and analyst workflow are demonstrable.

## Required Screenshots
1. Alert list view filtered to `nginx_*` or current batch rule tags.
2. Alert detail flyout/page showing:
   - rule name and severity
   - key event fields (`source.ip`, `url.path`, status)
   - investigation context
3. Dashboard view with:
   - top source IPs
   - top paths
   - 404s over time
   - requests by status code
4. TLS parity evidence:
   - one screenshot from TLS-mode validation with same filters/time window

## Capture Standards
- Use absolute time window and include it in the screenshot.
- Keep browser URL bar visible when possible to show app context.
- Use consistent naming under `samples/screenshots/`:
  - `kibana_baseline_alert_list.png`
  - `kibana_baseline_alert_detail.png`
  - `kibana_baseline_dashboard.png`
  - `kibana_tls_alert_list.png`
  - `kibana_tls_alert_detail.png`
  - `kibana_tls_dashboard.png`
- Avoid redacting core analytic fields unless required.

## Pre-Capture Validation
- `python3 scripts/test_detections.py`
- Relevant rules are enabled in Kibana.
- Fixture ingest index contains expected documents.
- Alerts for selected rules have fired in the current time window.

## Post-Capture Checklist
- Update `docs/phase3_results.md` or phase scorecard with exact screenshot file references.
- Verify no stale/non-mode-specific screenshots are referenced in docs.
