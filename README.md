# ELK SIEM Deploy & Triage Toolkit

## Summary
> ### Automates deploy-on-demand ELK-based SIEM stacks with preconfigured parsers, dashboards, and triage logic to rapidly ingest logs, test detections, and evaluate alert quality.

## Repo Provides
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
### Prerequisites
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
- ELASTIC_PASSWORD
- KIBANA_SYSTEM_PASSWORD (baseline Kibana -> ES)
- ELASTIC_SERVICE_TOKEN (TLS Kibana -> ES)
- STACK_VERSION
- ES_PORT
- COMPOSE_PROJECT_NAME

### Modes
**Baseline (HTTP)**
- ES: http://localhost:${ES_PORT}
- Kibana: http://localhost:5601
- Kibana -> ES auth: kibana_system + KIBANA_SYSTEM_PASSWORD

**TLS (HTTPS)**
- ES: https://localhost:${ES_PORT}
- Kibana: https://localhost:5601
- Kibana -> ES auth: service account token (ELASTIC_SERVICE_TOKEN)

> Whenever `.env` is modified, re-export variables into your current shell:
> ```bash
> set -o allexport; source .env; set +o allexport
> ```

### 1. Baseline (HTTP)
```bash
docker compose -p ${COMPOSE_PROJECT_NAME} up -d
```
> If COMPOSE_PROJECT_NAME isn’t set, replace with **elk**.

> *Baseline uses compose.yml by default.*

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

Go to [http://localhost:5601](http://localhost:5601) and login as username: **elastic** / password: **${ELASTIC_PASSWORD}**

> _Kibana itself authenticates to Elasticsearch using kibana_system in baseline; you log in as elastic in the UI._

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
> Docker Compose only injects env vars at container creation.

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

Go to [https://localhost:5601](https://localhost:5601) and login as username: **elastic** / password: **${ELASTIC_PASSWORD}**

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

## Notes
***
- The TLS Kibana healthcheck uses curl -k for local lab convenience because the container trust store does not automatically trust your local CA.
  - In a hardened setup, prefer CA trust (install/mount CA) instead of -k.
- Use -p ${COMPOSE_PROJECT_NAME} consistently to keep project resources/volumes stable. 
  - _If you forget to source .env, replace with `-p elk`_.
