# Detection Quality Notes (Phase 4)

## Objective
Scale to 10 Nginx detections without sacrificing correctness, explainability, or testability.

## Quality Dimensions
1. Precision
   - Alerts should represent meaningful suspicious behavior.
   - Known benign fixture traffic should remain outside `must_not_hit` assertions.
2. Recall
   - Every rule has explicit `must_hit` fixtures proving hypothesis coverage.
3. Explainability
   - Each rule includes hypothesis, ATT&CK mapping, false-positive context, and playbook linkage.
4. Testability
   - Rule schema, fixture integrity, and expected outcomes are enforced in automation.

## Expected False Positive Sources
- Internal vulnerability scanners and security QA jobs.
- Synthetic red-team or consultant replay traffic.
- Bot traffic probing common internet-facing paths.

## Tuning Levers
- Threshold values (`min_count`) for burst logic.
- Source IP allowlists for authorized scanners.
- Route/path allowlists for controlled test endpoints.
- Payload-pattern suppressions for known benign automation.

## Phase 4 Quality Gates
- Gate 1: Rule metadata contract passes `config/detections/rule.schema.json`.
- Gate 2: Fixture and expected-hit contracts are complete and internally consistent.
- Gate 3: Rule outcomes satisfy all `must_hit`/`must_not_hit` assertions.
- Gate 4: Evidence references are canonical and current.

## Validation Commands
```bash
python3 scripts/test_detections.py
scripts/check_detection_pack.sh
```

## Phase 4 Upgrade Targets
- Expand from 3 to 10 rules in controlled batches with quality gates staying green.
- Keep Nginx as the primary source until batch quality is stable.
- Add stack spot-check parity for representative rules in baseline and TLS modes.
