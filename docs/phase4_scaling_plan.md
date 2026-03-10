# Phase 4 Plan: Scale to 20+ ATT&CK-Mapped Rules

## Goal
Expand from 3 high-quality rules to portfolio-scale breadth without reducing quality.

## Scaling Strategy
1. Batch expansion:
   - Batch A: grow to 10 rules
   - Batch B: grow to 15 rules
   - Batch C: grow to 20+ rules
2. Keep one primary telemetry source until quality remains stable.
3. Add new categories only after prior batch passes quality gates.

## Rule Quality Gates Per Batch
- Offline harness passes for all rules.
- Every rule has:
  - ATT&CK mapping
  - false positive notes
  - tuning levers
  - linked triage playbook
- `docs/mitre_mapping.md` and `docs/detection_quality.md` updated.

## Suggested Batch Mix
- Web exploitation (SQLi/RCE/path traversal)
- Reconnaissance/scanning patterns
- Authentication abuse (if/when auth telemetry is added)
- Persistence and post-exploitation web indicators

## Portfolio Evidence for Resume Alignment
- Keep changelog of rule counts by ATT&CK technique.
- Preserve passing harness output for each batch.
- Capture representative screenshots of validated alerts in stack phase.
