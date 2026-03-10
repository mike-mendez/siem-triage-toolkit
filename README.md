# ELK SIEM Deploy & Triage Toolkit

## Summary
> ### Automates deploy-on-demand ELK-based SIEM stacks with preconfigured parsers, dashboards, and triage logic to rapidly ingest logs, test detections, and evaluate alert quality.

## Repo Provides
- Docker Compose baseline (HTTP) and TLS overlay (HTTPS)
- Kibana configs split into:
  - `kibana.http.yml` (baseline uses `kibana_system`)
  - `kibana.tls.yml` (TLS uses service account token)
- Project-scoped Elasticsearch data volumes by Compose project name (`-p`)

## Main Features (upcoming)
- **Preconfigured parsers** (pipelines / ingestion)
- **Dashboards** (operational views)
- **Triage logic** (queries, filters, maybe rule tuning)
- **Evaluating alert quality** (signal-to-noise, FP reduction)

## Quick Start
---
### Prerequisites
- Docker Desktop (Apple Silicon OK)
- Ports available:
  - Elasticsearch: `${ES_PORT}` (default 9200)
  - Kibana: `${KIBANA_PORT}` (default 5601)
- Create your local env file:
  ```bash
  cp .env.example .env
  ```

### Environment Variables
See `.env.example` for required fields:
- `ELASTIC_PASSWORD`
- `KIBANA_SYSTEM_PASSWORD` (baseline Kibana -> ES)
- `ELASTIC_SERVICE_TOKEN` (TLS Kibana -> ES; optional if using `--auto-token`)
- `STACK_VERSION`
- `ES_PORT`
- `KIBANA_PORT`
- `COMPOSE_PROJECT_NAME`

### Modes
**Baseline (HTTP)**
- ES: `http://localhost:${ES_PORT}`
- Kibana: `http://localhost:${KIBANA_PORT}`
- Kibana -> ES auth: `kibana_system` + `KIBANA_SYSTEM_PASSWORD`

**TLS (HTTPS)**
- ES: `https://localhost:${ES_PORT}`
- Kibana: `https://localhost:${KIBANA_PORT}`
- Kibana -> ES auth: service account token (`ELASTIC_SERVICE_TOKEN`)

### Recommended Workflow (scripts)
The scripts enforce hardened defaults and mode checks.

**Baseline (HTTP)**
```bash
scripts/deploy.sh --mode baseline
```
If baseline auth drifts (fresh volume or password mismatch), deploy auto-resets `kibana_system`
to `KIBANA_SYSTEM_PASSWORD` from `.env` and continues.

**TLS (HTTPS)**
```bash
scripts/deploy.sh --mode tls
```

If TLS token is missing or invalid, auto-generate and keep it in-session only:
```bash
scripts/deploy.sh --mode tls --auto-token
```

Persist a newly generated token to `.env` only when explicitly requested:
```bash
scripts/deploy.sh --mode tls --auto-token --persist-token
```

Teardown:
```bash
scripts/teardown.sh --mode baseline
scripts/teardown.sh --mode tls
```

> Service tokens live in Elasticsearch security state for that Compose project/volume.
> Wiping volumes (`scripts/teardown.sh --volumes`) removes passwords/tokens for that project.

### Manual Compose Workflow (advanced)
Baseline:
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} -f compose.yml up -d
```

TLS:
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} -f compose.yml -f compose.tls.yml up -d
```

Recreate Kibana after auth env changes:
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} -f compose.yml -f compose.tls.yml up -d --force-recreate kibana
```

### Docs Index
- Runbook: `docs/runbook.md`
- Triage template: `docs/triage_template.md`
- Detection quality: `docs/detection_quality.md`
- ATT&CK mapping: `docs/mitre_mapping.md`
- Phase 3 validation checklist: `docs/phase3_validation_checklist.md`
- Phase 4 scaling plan: `docs/phase4_scaling_plan.md`
- Security policy: `SECURITY.md`
- Contribution guide: `CONTRIBUTING.md`

### Detection Pack (Offline Validation)
- Field contract: `config/detections/field_contract.md`
- Nginx detection pack: `config/detections/nginx/`
- Fixtures: `samples/logs/nginx_access.log`
- Expected outcomes: `tests/expected_hits.json`

Run the offline harness:
```bash
python3 scripts/test_detections.py
```

## Certificates (manual, streamlined)
___

This project uses a **local Certificate Authority (CA)** to issue (sign) TLS certificates for:
- Elasticsearch (server cert for `https://localhost:${ES_PORT}`)
- Kibana (server cert for `https://localhost:5601`)

> **Never commit private keys** (`ca.key`, `*.key`). Only the public CA cert (`ca.crt`) is safe to share.

### What files exist and what they do
- `certs/ca/ca.crt`  
  Public CA certificate. Used by clients (curl, Kibana) to **trust** server certificates.
- `certs/ca/ca.key`  
  CA private key. Used only to **sign** leaf certs. Must remain local.
- `certs/elasticsearch/elasticsearch.crt` + `certs/elasticsearch/elasticsearch.key`  
  Elasticsearch leaf cert + private key (server identity for HTTPS).
- `certs/kibana/kibana.crt` + `certs/kibana/kibana.key`  
  Kibana leaf cert + private key (server identity for HTTPS).

### How trust works (mental model)
1) You create a **CA** (root). This CA can sign other certs.
2) You create **leaf certs** for Elasticsearch and Kibana containing the correct names (SANs).
3) Elasticsearch/Kibana present their leaf certs to clients during TLS handshake.
4) Clients verify the leaf cert chains back to the CA they trust (`ca.crt`).

If a client doesn’t trust your CA, you’ll see:
- browser warnings for `https://localhost:5601`
- curl errors unless you pass `--cacert ./certs/ca/ca.crt`

### One-time: Create CA (generates ca.crt + ca.key)
Run **once** (or whenever you intentionally rotate your CA):

```bash
docker compose -p ${COMPOSE_PROJECT_NAME} up -d elasticsearch

docker compose -p ${COMPOSE_PROJECT_NAME} exec elasticsearch \
  bin/elasticsearch-certutil ca --pem --out /tmp/ca.zip

docker compose -p ${COMPOSE_PROJECT_NAME} exec elasticsearch \
  sh -lc "unzip -o /tmp/ca.zip -d /tmp/ca"

mkdir -p certs/ca
docker cp $(docker compose -p ${COMPOSE_PROJECT_NAME} ps -q elasticsearch):/tmp/ca/ca/ca.crt ./certs/ca/ca.crt
docker cp $(docker compose -p ${COMPOSE_PROJECT_NAME} ps -q elasticsearch):/tmp/ca/ca/ca.key ./certs/ca/ca.key
```

### One-time (or after changing instances.yml): Generate leaf certs (ES + Kibana)
```bash
docker run --rm \
  -v "$PWD/certs:/certs" \
  -v "$PWD/instances.yml:/instances.yml:ro" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:${STACK_VERSION} \
  bash -lc '
    bin/elasticsearch-certutil cert --pem \
      --in /instances.yml \
      --ca-cert /certs/ca/ca.crt \
      --ca-key  /certs/ca/ca.key \
      --out /tmp/certs.zip &&
    unzip -o /tmp/certs.zip -d /tmp/certs &&
    cp -r /tmp/certs/elasticsearch /certs/ &&
    cp -r /tmp/certs/kibana /certs/
  '
```
> **Security note**: ca.key is the “master key.” Treat it like a secret.

> Regenerate leaf certs when instances.yml SANs change (e.g., add ::1 or a new hostname)

## Troubleshooting
___
- Kibana 400 on / → Kibana cannot fully initialize (auth/config mismatch); **check Kibana logs + ES auth**.
- 401 token auth → confirm shell env is loaded; **verify token with Bearer header against ES**.
- Browser certificate warning → expected with local CA; **import certs/ca/ca.crt if you want no warning**.
- TLS healthcheck failures → verify `certs/ca/ca.crt` exists and leaf cert SANs include `localhost`.

## Notes
***
- TLS mode now uses CA-validated healthchecks (no insecure `-k` bypass).
- Kibana -> Elasticsearch TLS verification mode is `full` (hostname validation enabled).
- Volumes are project-scoped by Compose project name. Use `--project` in scripts (or `-p` with compose) for explicit isolation.
