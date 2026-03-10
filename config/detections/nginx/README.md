# Nginx Detection Pack (Phase 2)

## Goal
Provide stack-free, testable detection engineering artifacts for Nginx access logs:
- 3 rules with ATT&CK mapping
- triage playbooks per rule
- fixture-driven expected outcomes
- offline validation harness

## Rule Inventory
1. `nginx_sqli_querystring`
   - Detects common SQL injection strings in URL/query.
   - ATT&CK: T1190 (Exploit Public-Facing Application).
2. `nginx_webshell_path_probe`
   - Detects webshell-like paths and command-execution probes.
   - ATT&CK: T1505.003 (Web Shell).
3. `nginx_404_recon_burst`
   - Detects repeated 404 probes to sensitive web admin/secret paths from one source.
   - ATT&CK: T1595 (Active Scanning).

## Pack Layout
- `rules/` : JSON rule metadata + detection logic
- `playbooks/` : investigation workflow per rule

## Validation
Run from repo root:
```bash
python3 scripts/test_detections.py
```

The harness validates:
- rule schema
- fixture/annotation integrity
- expected hit outcomes (`tests/expected_hits.json`)

## Tuning Notes
- SQLi rule is pattern-based and should be refined with allowlists per app route.
- Webshell rule intentionally favors suspicious file/path probes over generic `.php` traffic.
- Recon burst threshold is tuned for lab fixtures (`>=5` suspicious 404 requests per source).
