# Phase 4 Batch B Scorecard (Rules 7-10)

## Batch Scope
- Start: 6 rules
- End: 10 rules
- Added rules:
  - `nginx_scanner_user_agent`
  - `nginx_command_injection_query`
  - `nginx_phpunit_eval_stdin_probe`
  - `nginx_xss_query_probe`

## ATT&CK Coverage Delta
- Before Batch B: T1190, T1505.003, T1595, T1110
- After Batch B: T1190, T1505.003, T1595, T1110
- Net new technique coverage: `+0` (depth expansion in existing web attack families)

## Quality Gate Outcomes
- Offline harness: `PASS` (10/10 rules)
- Schema contract: `PASS`
- Fixture integrity: `PASS`
- Expected hit assertions: `PASS`
- Batch B rule hit snapshot:
  - `nginx_scanner_user_agent`: 9 hits
  - `nginx_command_injection_query`: 3 hits
  - `nginx_phpunit_eval_stdin_probe`: 1 hit
  - `nginx_xss_query_probe`: 2 hits

## False-Positive Considerations
- Scanner user-agent rule is intentionally broad and should be suppression-tuned for approved ranges.
- XSS and command-injection probes may include QA payload replay traffic.

## Tuning Changes Introduced
- Added explicit allowlist fields for scanner UA and payload-heavy query detections.
- Maintained strict `must_not_hit` fixtures to prevent over-broad signatures.

## Evidence Notes
- Use `docs/kibana_screenshot_checklist.md` for native UI screenshot set during parity checks.
- Harness snapshot command: `python3 scripts/test_detections.py --output-format json`
