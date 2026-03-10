# Nginx Detection Pack (Phase 4)

## Goal
Provide a stack-free, quality-gated detection engineering pack for Nginx access logs with:
- 10 ATT&CK-mapped detections
- triage playbooks per rule
- fixture-driven expected outcomes
- offline harness with schema + integrity + outcome gates

## Rule Inventory
1. `nginx_sqli_querystring` (T1190)
2. `nginx_webshell_path_probe` (T1505.003)
3. `nginx_404_recon_burst` (T1595)
4. `nginx_lfi_path_traversal_probe` (T1190)
5. `nginx_sensitive_file_access` (T1595)
6. `nginx_scanner_user_agent` (T1595)
7. `nginx_login_bruteforce_burst` (T1110)
8. `nginx_command_injection_query` (T1190)
9. `nginx_phpunit_eval_stdin_probe` (T1190)
10. `nginx_xss_query_probe` (T1190)

## Batch Expansion Model
- Batch A (`+3`, total 6):
  - `nginx_lfi_path_traversal_probe`
  - `nginx_sensitive_file_access`
  - `nginx_login_bruteforce_burst`
- Batch B (`+4`, total 10):
  - `nginx_scanner_user_agent`
  - `nginx_command_injection_query`
  - `nginx_phpunit_eval_stdin_probe`
  - `nginx_xss_query_probe`

## Pack Layout
- `rules/`: rule metadata and detection logic JSON
- `playbooks/`: analyst triage guides mapped to `docs/triage_template.md`

## Validation Commands
Single harness run:
```bash
python3 scripts/test_detections.py
```

CI-style local bundle:
```bash
scripts/check_detection_pack.sh
```

Optional machine-readable report:
```bash
scripts/check_detection_pack.sh /tmp/detection_report.json
```

## Quality Contract
Every rule must include:
- hypothesis
- ATT&CK mapping
- false-positive notes
- tuning guidance
- playbook linkage
- fixture assertions (`must_hit`, `must_not_hit`)
