# ELK SIEM Deploy & Triage Toolkit

## Summary
> ### Automates deploy-on-demand ELK-based SIEM stacks with preconfigured parsers, dashboards, and triage logic to rapidly ingest logs, test detections, and evaluate alert quality.

## Repo Provides:
- Docker Compose baseline (HTTP) and TLS overlay (HTTPS)
- Kibana configs split into:
  - `kibana.http.yml` (baseline uses `kibana_system`)
  - `kibana.tls.yml` (TLS uses service account token)
- Persistent Elasticsearch data volume (prevents re-bootstrap churn)

## Main Features (upcoming)
- **Preconfigured parsers** (pipelines / ingestion)
- **Dashboards** (operational views)
- **Triage logic** (queries, filters, maybe rule tuning)
- **Evaluating alert quality** (signal-to-noise, FP reduction)

## Quick Start
---
### Prerquisites
- Docker Desktop (Apple Silicon OK)
- Ports available:
  - Elasticsearch: `${ES_PORT}` (default 9200)
  - Kibana: 5601
- Create your local env file:
  ```bash
    cp .env.example .env
  ```

### Environment Variables
See .env.example for required fields:
	•	ELASTIC_PASSWORD
	•	KIBANA_SYSTEM_PASSWORD (baseline Kibana -> ES)
	•	ELASTIC_SERVICE_TOKEN (TLS Kibana -> ES)
	•	STACK_VERSION
	•	ES_PORT

### Modes
**Baseline (HTTP)**
	•	ES: http://localhost:${ES_PORT}
	•	Kibana: http://localhost:5601
	•	Kibana -> ES auth: kibana_system + KIBANA_SYSTEM_PASSWORD

**TLS (HTTPS)**
	•	ES: https://localhost:${ES_PORT}
	•	Kibana: https://localhost:5601
	•	Kibana -> ES auth: service account token (ELASTIC_SERVICE_TOKEN)


### 1. Baseline (HTTP)
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} up -d
```
**Verify elasticsearch connectivity**
```bash
set -o allexport; source .env; set +o allexport
curl -u elastic:${ELASTIC_PASSWORD} http://localhost:${ES_PORT}
```
**Set kibana_system password (match your .env)**
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} exec elasticsearch bin/elasticsearch-reset-password -u kibana_system -i
```
**Kibana Baseline UI**

Go to [http://localhost:5601](http://localhost:5601) and login as elastic

### 2. TLS (HTTPS)
> Assumes certs exist under ./certs. See “Certificates” below
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} -f compose.yml -f compose.tls.yml up -d
```
**Verify ES HTTPS**
```bash
set -o allexport; source .env; set +o allexport
curl --cacert ./certs/ca/ca.crt -u elastic:${ELASTIC_PASSWORD} https://localhost:${ES_PORT}
```
**Create service token (only needed after wiping volumes)**
> Service tokens live in Elasticsearch’s security index (persistent data volume). If you wipe volumes (down -v), the token is gone.

> Switching between HTTP/TLS should NOT require a new token unless you destroyed Elasticsearch data or recreated in a way that bootstraps a fresh security state.
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} exec elasticsearch bin/elasticsearch-service-tokens delete elastic/kibana kibana-docker || true
docker compose -p ${COMPOSE_PROJECT_NAME} exec elasticsearch bin/elasticsearch-service-tokens create elastic/kibana kibana-docker
```
**Paste the token value into .env as ELASTIC_SERVICE_TOKEN=....**

**Recreate Kibana (to pick up the new token)**
> 	Docker Compose only injects env vars at container creation.

> Restarting a container does not re-read .env into the running container.
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} -f compose.yml -f compose.tls.yml up -d --force-recreate kibana
```
**Verify token against ES**
```bash
set -o allexport; source .env; set +o allexport
curl --cacert ./certs/ca/ca.crt -H "Authorization: Bearer ${ELASTIC_SERVICE_TOKEN}" https://localhost:${ES_PORT}/_security/_authenticate
```
**Kibana UI**

Go to [https://localhost:5601](https://localhost:5601) and login as _elastic_

## Notes
- The TLS Kibana healthcheck uses curl -k for local lab convenience because the container trust store does not automatically trust your local CA.
  - In a hardened setup, prefer CA trust (install/mount CA) instead of -k.
- Use -p elk consistently to keep project resources/volumes stable.
