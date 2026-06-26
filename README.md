# ELK SIEM Detection & Agentic Triage Toolkit

## Summary
> ### A human-gated, agentic SOC triage pipeline and offline detection-engineering pack, built on deploy-on-demand ELK. It ingests an alert, enriches and correlates it, assesses severity against MITRE ATT&CK, and proposes (never applies) detection tuning — proven safe by a validation harness and ratified by a human before anything lands.

> **Project history:** this started as a deploy-on-demand ELK SIEM stack (parsers, dashboards, TLS).
> It was revamped into a detection-engineering and agentic-triage toolkit. The ELK deploy automation
> documented below is now the substrate; the offline detection pack and the human-gated triage
> pipeline are the focus.

## Repo Provides
- Agentic, human-gated triage pipeline on Claude Code (see **Agentic Triage Pipeline** below)
- Offline Nginx detection pack: 11 schema-gated rules with playbooks, fixtures, and a validation harness
- Docker Compose baseline (HTTP) and TLS overlay (HTTPS)
- Kibana configs split into:
  - `kibana.http.yml` (baseline uses `kibana_system`)
  - `kibana.tls.yml` (TLS uses service account token)
- Project-scoped Elasticsearch data volumes by Compose project name (`-p`)
- Security & supply-chain guardrails: secret scanning, Conventional Commits, Dependabot, agent guard hooks

## Main Features
- Human-gated **agentic triage pipeline** (orchestrator + specialist subagents) that triages alerts and proposes detection tuning without acting on live infrastructure
- Hardened mode-aware ELK deploy automation (`baseline` and `tls`)
- Offline detection-engineering pack for Nginx (11 rules) with schema-gated rule contracts and per-rule playbooks
- Fixture-driven validation harness with explicit `must_hit` / `must_not_hit` assertions
- Deterministic guard hooks: write-lane confinement, harness-gated tuning, and a no-production-action denylist
- Security & governance automation: gitleaks secret scanning (pre-commit + CI), Conventional-Commit enforcement, and Dependabot updates
- Exported stack evidence artifacts and screenshot capture workflow
- Batch-based scaling model from 3 validated rules to 11 (and growing) with quality gates

## Agentic Triage Pipeline

A human-gated triage pipeline runs on Claude Code: an `orchestrator` agent drives a security
alert through specialist subagents and proposes (never applies) detection tuning. Agents take
**no autonomous action on live infrastructure** — they produce artifacts and recommendations,
and a human ratifies the disposition before any rule change.

```
alert -> intake -> enrich -> correlate -> assess -> (human ratifies) -> tune -> validate
```

| Stage     | Agent             | Writes                                                  |
| --------- | ----------------- | ------------------------------------------------------- |
| Intake    | `alert-intake`    | `triage/incidents/<id>.md`                              |
| Enrich    | `enricher`        | `triage/enrichment/<id>.md`                             |
| Correlate | `correlator`      | `triage/correlation/<id>.md`                            |
| Assess    | `analyst`         | `triage/reports/<id>.md`                                |
| Ratify    | `orchestrator`    | `triage/status/<id>.md` (human-gated ratification record)|
| Tune      | `detection-tuner` | `config/detections/**` (only after the harness passes)  |

Deterministic guard hooks enforce the invariants: each agent is confined to its write lane
(`agent-write-guard.sh`), detection changes are blocked until `scripts/test_detections.py`
passes (`require-harness-pass.sh`), and state-changing shell commands are denied
(`no-prod-action-guard.sh`). The always-apply rules live in `AGENTS.md`, and the artifact
lanes are documented in `triage/README.md`.

The orchestrator is the only agent that talks to the user or spawns specialists, and it passes file
paths between stages (never artifact bodies) to keep context lean. Specialists kick work back rather
than overstep: `NEEDS CONTEXT:` makes the orchestrator run the enricher and resume; `NEEDS DECISION:`
makes it ask the human. Tuning only begins after the analyst's disposition is ratified and the report
recommends a rule change.

Feed it a sample alert from `samples/alerts/` to run the full flow.

## Security, CI & Governance
Supply-chain and secret hygiene are first-class in this repo:
- **Secret scanning** — `gitleaks` runs as a pre-commit hook and as a server-side CI backstop (`.github/workflows/security.yml`) that scans full git history on every push and PR.
- **Pre-commit hygiene** — private-key detection, large-file / merge-conflict / YAML-TOML-JSON checks, and EOF / trailing-whitespace fixers (`.pre-commit-config.yaml`, every rev pinned).
- **Conventional Commits** — enforced at the `commit-msg` stage via commitizen; a local guard also rejects AI co-author / "generated with" trailers.
- **Dependency updates** — Dependabot watches the `github-actions`, `pip`, and `docker` ecosystems (`.github/dependabot.yml`).
- **Agent guard hooks** — `agent-write-guard.sh` (lane confinement), `require-harness-pass.sh` (no tuning until the harness passes), and `no-prod-action-guard.sh` (state-changing command denylist), wired via `.claude/settings.json`.
- **Governance docs** — `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `.github/CODEOWNERS`.

> Roadmap: a PR-triggered workflow that runs `scripts/test_detections.py` on every change is still
> pending (roadmap phase 5). Today the detection harness is run locally via `scripts/test_detections.py`
> or `scripts/check_detection_pack.sh`.

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
- Install / scaffold guide: `INSTALL.md`
- Agent invariants: `AGENTS.md`
- Agentic triage roadmap: `docs/agentic_triage_roadmap.md`
- Triage artifact lanes: `triage/README.md`
- Runbook: `docs/runbook.md`
- Triage template: `docs/triage_template.md`
- Detection quality: `docs/detection_quality.md`
- ATT&CK mapping: `docs/mitre_mapping.md`
- Native screenshot checklist: `docs/kibana_screenshot_checklist.md`
- Phase 3 validation checklist: `docs/phase3_validation_checklist.md`
- Phase 3 results: `docs/phase3_results.md`
- Phase 4 scaling plan: `docs/phase4_scaling_plan.md`
- Phase 4 Batch A scorecard: `docs/phase4_batch_a_scorecard.md`
- Phase 4 Batch B scorecard: `docs/phase4_batch_b_scorecard.md`
- Phase 4 Batch C scorecard: `docs/phase4_batch_c_scorecard.md`
- Interview narrative notes: `notes/interview_narrative.md`
- Security policy: `SECURITY.md`
- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`

### Detection Pack (Offline Validation)
- Field contract: `config/detections/field_contract.md`
- Nginx detection pack (11 rules): `config/detections/nginx/`
- Per-rule response playbooks: `config/detections/nginx/playbooks/`
- Detection pack overview: `config/detections/nginx/README.md`
- Fixtures: `samples/logs/nginx_access.log`
- Expected outcomes: `tests/expected_hits.json`
- Rule schema contract: `config/detections/rule.schema.json`

Run the offline harness:
```bash
python3 scripts/test_detections.py
```

Run local CI-style quality gates:
```bash
scripts/check_detection_pack.sh
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
