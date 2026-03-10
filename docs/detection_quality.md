# Detection Quality Notes (Phase 2)

## Objective
Define practical quality standards for this detection pack before stack validation.

## Quality Dimensions
1. Precision
   - Alerts should represent meaningful suspicious behavior.
   - Minimize matches from routine application traffic.
2. Recall
   - Rules should catch core attack patterns represented in fixtures.
3. Explainability
   - Each rule must map to ATT&CK and include triage guidance.
4. Testability
   - Every rule must have `must_hit` and `must_not_hit` assertions.

## Expected False Positive Sources
- Internal vulnerability scanners and security QA jobs.
- Synthetic tests from engineering environments.
- Bot traffic probing common endpoints.

## Tuning Levers
- Thresholds (`min_count`) for burst-style detections.
- Path/query allowlists for known safe scanners.
- Source IP allowlists for internal tooling.
- Route-based suppression for intentionally noisy endpoints.

## Pass/Fail Quality Gate for Phase 2
- `python3 scripts/test_detections.py` returns success.
- All rules include:
  - hypothesis and ATT&CK mapping
  - false positives
  - tuning guidance
  - linked triage playbook

## Phase 3 Upgrade Targets
- Measure alert rates against ingested fixture and near-real traffic.
- Add suppression logic only after observed false positives are documented.
