# Phase 4 Plan: Scale to 20+ ATT&CK-Mapped Rules

## Current Status
- Phase 4 foundation complete:
  - formal rule schema contract
  - CI-style local quality gate command
  - Nginx pack expanded from 3 to 10 rules in two batches
- Current focus is quality preservation, not raw rule inflation.

## Next Scaling Strategy (10 -> 20+)
1. Batch C: expand to 15 rules.
2. Batch D: expand to 20+ rules.
3. Gate each batch on harness pass and playbook completeness.

## Rule Quality Gates Per Batch
- `scripts/check_detection_pack.sh` passes.
- New rules include hypothesis, ATT&CK mapping, FP notes, tuning, and playbook linkage.
- `tests/expected_hits.json` has explicit `must_hit` and `must_not_hit` assertions for every added rule.

## Recommended Expansion Mix
- Additional web exploitation signatures (RCE paths, framework-specific probes).
- Auth abuse and account takeover patterns.
- Recon and post-exploitation web indicators.

## Portfolio Evidence Targets
- Keep per-batch scorecards with ATT&CK coverage deltas.
- Capture native Kibana screenshots for representative rules in baseline and TLS parity passes.
- Maintain concise metrics for interview narrative updates.
