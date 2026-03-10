# Runbook

## Purpose
Operational commands for deploying and tearing down the ELK SIEM toolkit with secure defaults.

## Prerequisites
- Docker Desktop running
- `.env` present (`cp .env.example .env`)
- Certificates generated for TLS mode under `certs/`

## Baseline Mode (HTTP)
Deploy:
```bash
scripts/deploy.sh --mode baseline
```

If `kibana_system` authentication fails, deploy automatically resets the password in
Elasticsearch to match `KIBANA_SYSTEM_PASSWORD` from `.env`.

Teardown:
```bash
scripts/teardown.sh --mode baseline
```

## TLS Mode (HTTPS)
Deploy with existing token:
```bash
scripts/deploy.sh --mode tls
```

Deploy and auto-generate token (session only):
```bash
scripts/deploy.sh --mode tls --auto-token
```

Deploy and persist generated token to `.env`:
```bash
scripts/deploy.sh --mode tls --auto-token --persist-token
```

Teardown:
```bash
scripts/teardown.sh --mode tls
```

## State Isolation Model
- Compose project name controls state scope.
- Different project names create isolated volumes and security state.
- Use `--project <name>` in scripts for explicit isolation.

## Destructive Operations
To wipe Elasticsearch data and security state for one project:
```bash
scripts/teardown.sh --mode tls --volumes
```

After volume wipe, re-bootstrap credentials/tokens.

## Troubleshooting
- Kibana not ready: inspect logs:
  ```bash
  docker compose -p <project> logs --tail=120 kibana
  ```
- Token auth failure in TLS mode: re-run with `--auto-token`.
- TLS trust failures: verify `certs/ca/ca.crt` and SANs in `instances.yml`.

## Detection Pack Validation (No Stack)
Run offline detection checks:
```bash
python3 scripts/test_detections.py
```
