# Contributing

## Setup
1. Copy env template:
   ```bash
   cp .env.example .env
   ```
2. Start baseline:
   ```bash
   scripts/deploy.sh --mode baseline
   ```
3. Start TLS:
   ```bash
   scripts/deploy.sh --mode tls --auto-token
   ```

## Contribution Guidelines
- Keep changes mode-aware (`baseline` and `tls` behavior should be explicit).
- Prefer secure defaults over convenience shortcuts.
- Keep scripts non-destructive unless explicitly requested by the operator.
- Update `README.md` and `docs/runbook.md` when workflow behavior changes.

## Testing Expectations
- Validate compose render:
  - `docker compose -f compose.yml config`
  - `docker compose -f compose.yml -f compose.tls.yml config`
- Validate script help output:
  - `scripts/deploy.sh --help`
  - `scripts/teardown.sh --help`
- Validate detection pack:
  - `python3 scripts/test_detections.py`
  - `scripts/check_detection_pack.sh`

## Secrets and Sensitive Data
- Never commit `.env`.
- Never commit private key material (`*.key`, `*.p12`, `*.pfx`).
- Do not paste real tokens/passwords into issues, PRs, or docs.
