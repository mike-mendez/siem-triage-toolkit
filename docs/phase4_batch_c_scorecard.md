  # Phase 4 Batch C Scorecard (Rule 11)

  ## Batch Scope
  - Start: 10 rules
  - End: 11 rules
  - Added rules:
    - `nginx_sensitive_file_serve`

  ## ATT&CK Coverage Delta
  - Before Batch C: T1190, T1505.003, T1595, T1110
  - After Batch C: T1190, T1505.003, T1595, T1110, T1083
  - Net new technique coverage: `+1` (T1083 - File and Directory Discovery)

  ## Quality Gate Outcomes
  - Offline harness: `PASS` (11/11 rules)
  - Schema contract: `PASS`
  - Fixture integrity: `PASS`
  - Expected hit assertions: `PASS`
  - Batch C rule hit snapshot:
    - `nginx_sensitive_file_serve`: 5 hits

  ## False-Positive Considerations
  - HTTP 200 to a sensitive path can result from intentional security validation by trusted teams.
  - Developer QA scripts targeting known sensitive file paths may trigger the rule.

  ## Tuning Changes Introduced
  - Added `allowlist_source_ips` for authorized security scanners and internal QA.
  - `path_list` is configurable to match the deployed application stack.

  ## Evidence Notes
  - Rule severity: `high` (a successful serve implies real exposure, not just a probe).
  - Harness snapshot command: `python3 scripts/test_detections.py --output-format json`
  EOF

  # --- Option C, part 3: index the new scorecard in README ---
  awk '{print} /Phase 4 Batch B scorecard:/{print "- Phase 4 Batch C scorecard:
  `docs/phase4_batch_c_scorecard.md`"}' README.md > README.md.tmp && mv README.md.tmp README.md

  # --- Medium 1: kibana checklist stale rule-prefix filter ---
  sed -i '' 's/`phase3_\*`/`nginx_*`/' docs/kibana_screenshot_checklist.md

  # --- Medium 2: phase3 checklist hardcoded "3 rules" -> future-proof wording ---
  sed -i '' 's/All 3 rules observed firing on intended fixtures./All detection-pack rules observed firing on
  intended fixtures./' docs/phase3_validation_checklist.md
