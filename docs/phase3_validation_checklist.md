# Phase 3 Checklist: Stack Validation + Export

## Goal
Validate Phase 2 detections in a running ELK stack and produce portfolio-ready evidence.

## Preconditions
- Phase 2 harness passes:
  - `python3 scripts/test_detections.py`
- Nginx fixture file exists:
  - `samples/logs/nginx_access.log`
- Detection docs/playbooks complete.

## Execution Steps
1. Start stack in chosen mode:
   - `scripts/deploy.sh --mode tls` (preferred)
2. Ingest Nginx fixture logs into Elasticsearch (agent/module/pipeline path).
3. Confirm field mapping aligns with `config/detections/field_contract.md`.
4. Create/import corresponding Kibana detection rules.
5. Validate each rule fires according to expected fixture behavior.
6. Build a compact dashboard for alert + source + path visibility.
7. Export artifacts:
   - `exports/kibana/rules.ndjson`
   - `exports/kibana/dashboard.ndjson`
   - `exports/kibana/timelines.ndjson`
8. Capture 2-4 screenshots or short GIFs in `samples/screenshots/`.

## Acceptance Criteria
- All 3 rules observed firing on intended fixtures.
- No critical schema mismatch between expected fields and ingested data.
- Export files are populated (non-empty) and reusable.
- Visual evidence exists for portfolio/demo usage.
