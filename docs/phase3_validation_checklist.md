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
1. Pre-stack gate:
   - `python3 scripts/test_detections.py`
2. Start stack in baseline mode:
   - `scripts/deploy.sh --mode baseline --project elk --no-pull --timeout 420`
3. Ingest fixtures with explicit ECS-shaped mapping:
   - `python3 scripts/phase3_ingest_nginx.py --es-url http://localhost:9200 --username elastic --password "$ELASTIC_PASSWORD"`
4. Create/update rules, dashboard, and exports:
   - `python3 scripts/phase3_kibana_setup.py --kibana-url http://localhost:5601 --es-url http://localhost:9200 --username elastic --password "$ELASTIC_PASSWORD"`
5. Capture baseline evidence:
   - `python3 scripts/phase3_capture_evidence.py --es-url http://localhost:9200 --username elastic --password "$ELASTIC_PASSWORD" --mode-label baseline`
6. TLS parity pass:
   - `scripts/deploy.sh --mode tls --project elk --no-pull --auto-token --timeout 420`
   - `python3 scripts/phase3_ingest_nginx.py --es-url https://localhost:9200 --ca-cert certs/ca/ca.crt --username elastic --password "$ELASTIC_PASSWORD"`
   - `python3 scripts/phase3_kibana_setup.py --kibana-url https://localhost:5601 --es-url https://localhost:9200 --ca-cert certs/ca/ca.crt --username elastic --password "$ELASTIC_PASSWORD"`
   - `python3 scripts/phase3_capture_evidence.py --es-url https://localhost:9200 --ca-cert certs/ca/ca.crt --username elastic --password "$ELASTIC_PASSWORD" --mode-label tls`
7. Optional post-validation generator:
   - `python3 scripts/gen_nginx_attack_logs.py`
8. Native UI evidence capture:
   - Follow `docs/kibana_screenshot_checklist.md`
   - Keep only mode-specific screenshot names in references

## Acceptance Criteria
- All detection-pack rules observed firing on intended fixtures.
- No critical schema mismatch between expected fields and ingested data.
- Export files are populated and reusable:
  - `rules.ndjson` non-empty
  - `dashboard.ndjson` non-empty
  - `timelines.ndjson` contains exported timelines or explicit `no_timelines_defined` marker
- Visual evidence exists for portfolio/demo usage.
- `docs/phase3_results.md` remains canonical (no duplicate mode append blocks).
