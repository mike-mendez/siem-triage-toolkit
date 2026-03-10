# Phase 4 Batch A Scorecard (Rules 4-6)

## Batch Scope
- Start: 3 rules
- End: 6 rules
- Added rules:
  - `nginx_lfi_path_traversal_probe`
  - `nginx_sensitive_file_access`
  - `nginx_login_bruteforce_burst`

## ATT&CK Coverage Delta
- Before Batch A: T1190, T1505.003, T1595
- After Batch A: T1190, T1505.003, T1595, T1110
- Net new technique coverage: `+1` (T1110)

## Quality Gate Outcomes
- Offline harness: `PASS` (10/10 rules)
- Schema contract: `PASS`
- Fixture integrity: `PASS`
- Expected hit assertions: `PASS`
- Batch A rule hit snapshot:
  - `nginx_lfi_path_traversal_probe`: 3 hits
  - `nginx_sensitive_file_access`: 4 hits
  - `nginx_login_bruteforce_burst`: 5 hits

## False-Positive Considerations
- LFI and sensitive-file probes can overlap with approved security scans.
- Brute-force burst rule may capture load/QA auth testing if not allowlisted.

## Tuning Changes Introduced
- Added per-rule source-IP allowlist fields.
- Kept conservative threshold (`min_count=5`) for login burst to reduce noise.

## Evidence Notes
- Representative stack spot-check to be captured in baseline + TLS after batch promotion.
- Harness snapshot command: `python3 scripts/test_detections.py --output-format json`
