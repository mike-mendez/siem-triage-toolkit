#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="baseline"                 # baseline | tls
PROJECT_NAME=""
TIMEOUT_SEC=300
FORCE_RECREATE=false
NO_PULL=false
AUTO_TOKEN=false                # if true, generate token on 401 and continue
PERSIST_TOKEN=false             # if true and --auto-token is used, write token to .env
LEGACY_AUTO_RESET=false         # deprecated compatibility flag

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy.sh [--mode baseline|tls] [--project NAME] [--timeout SEC]
                    [--force-recreate] [--no-pull]
                    [--auto-token] [--persist-token]

Examples:
  scripts/deploy.sh --mode baseline
  scripts/deploy.sh --mode tls --force-recreate
  scripts/deploy.sh --mode tls --auto-token
  scripts/deploy.sh --mode tls --auto-token --persist-token

Notes:
  - Reads .env from repo root.
  - Baseline auto-resets kibana_system password to match KIBANA_SYSTEM_PASSWORD when needed.
  - TLS requires certs and ELASTIC_SERVICE_TOKEN.
  - If ELASTIC_SERVICE_TOKEN is missing/invalid, use --auto-token.
  - Auto-generated tokens are session-only by default unless --persist-token is set.
USAGE
}

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[$(date +'%H:%M:%S')] $*"; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --project) PROJECT_NAME="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT_SEC="${2:-}"; [[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]] || die "--timeout must be a positive integer"; shift 2 ;;
    --force-recreate) FORCE_RECREATE=true; shift ;;
    --no-pull) NO_PULL=true; shift ;;
    --auto-reset-kibana-system) LEGACY_AUTO_RESET=true; shift ;;
    --auto-token) AUTO_TOKEN=true; shift ;;
    --persist-token) PERSIST_TOKEN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

[[ "$MODE" == "baseline" || "$MODE" == "tls" ]] || die "--mode must be baseline or tls"
if [[ "$PERSIST_TOKEN" == "true" && "$AUTO_TOKEN" != "true" ]]; then
  die "--persist-token requires --auto-token"
fi

have_cmd docker || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose not available (need Compose v2)"
have_cmd curl || die "curl not found"

ENV_FILE="$ROOT_DIR/.env"
[[ -f "$ENV_FILE" ]] || die ".env not found at repo root. Create it: cp .env.example .env"

# load env for this shell
# shellcheck disable=SC1090
set -o allexport; source "$ENV_FILE"; set +o allexport

PROJECT_NAME="${PROJECT_NAME:-${COMPOSE_PROJECT_NAME:-elk}}"
ES_PORT="${ES_PORT:-9200}"
KIBANA_PORT="${KIBANA_PORT:-5601}"

if [[ "$LEGACY_AUTO_RESET" == "true" ]]; then
  log "WARNING: --auto-reset-kibana-system is deprecated. Baseline password reset is now automatic."
fi

: "${STACK_VERSION:?STACK_VERSION missing in .env}"
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD missing in .env}"

if [[ "$MODE" == "baseline" ]]; then
  : "${KIBANA_SYSTEM_PASSWORD:?KIBANA_SYSTEM_PASSWORD missing in .env (baseline mode)}"
else
  if [[ -z "${ELASTIC_SERVICE_TOKEN:-}" && "$AUTO_TOKEN" != "true" ]]; then
    die "ELASTIC_SERVICE_TOKEN missing in .env (tls mode). Re-run with --auto-token to generate one."
  fi
  [[ -f "$ROOT_DIR/certs/ca/ca.crt" ]] || die "Missing certs/ca/ca.crt (TLS mode)"
  [[ -f "$ROOT_DIR/certs/elasticsearch/elasticsearch.crt" ]] || die "Missing certs/elasticsearch/elasticsearch.crt (TLS mode)"
  [[ -f "$ROOT_DIR/certs/elasticsearch/elasticsearch.key" ]] || die "Missing certs/elasticsearch/elasticsearch.key (TLS mode)"
  [[ -f "$ROOT_DIR/certs/kibana/kibana.crt" ]] || die "Missing certs/kibana/kibana.crt (TLS mode)"
  [[ -f "$ROOT_DIR/certs/kibana/kibana.key" ]] || die "Missing certs/kibana/kibana.key (TLS mode)"
fi

COMPOSE=(docker compose --project-directory "$ROOT_DIR" -p "$PROJECT_NAME" -f "$ROOT_DIR/compose.yml")
if [[ "$MODE" == "tls" ]]; then
  COMPOSE+=(-f "$ROOT_DIR/compose.tls.yml")
fi

wait_for_health() {
  local svc="$1"
  local deadline=$((SECONDS + TIMEOUT_SEC))
  local cid
  cid="$("${COMPOSE[@]}" ps -q "$svc" || true)"
  [[ -n "$cid" ]] || die "No container id found for service '$svc'"

  while (( SECONDS < deadline )); do
    local status
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealth{{end}}' "$cid" 2>/dev/null || echo "unknown")"
    if [[ "$status" == "nohealth" ]]; then
      log "WARNING: No healthcheck defined for '$svc' — skipping health wait"
      return 0
    fi
    [[ "$status" == "healthy" ]] && return 0
    log "Waiting for '$svc' health... (status=$status)"
    sleep 3
  done

  log "Last 80 lines of ${svc} logs:"
  "${COMPOSE[@]}" logs --tail=80 "$svc" || true
  die "Timeout waiting for '$svc' to become healthy"
}

probe_es() {
  if [[ "$MODE" == "baseline" ]]; then
    curl -fsS --config - "http://localhost:${ES_PORT}" >/dev/null <<EOF
user = "elastic:${ELASTIC_PASSWORD}"
EOF
  else
    curl -fsS --cacert "$ROOT_DIR/certs/ca/ca.crt" --config - "https://localhost:${ES_PORT}" >/dev/null <<EOF
user = "elastic:${ELASTIC_PASSWORD}"
EOF
  fi
}

check_kibana_system_auth() {
  curl -fsS --config - "http://localhost:${ES_PORT}/_security/_authenticate" >/dev/null <<EOF
user = "kibana_system:${KIBANA_SYSTEM_PASSWORD}"
EOF
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

reset_kibana_system_password_api() {
  local payload
  payload="{\"password\":\"$(json_escape "$KIBANA_SYSTEM_PASSWORD")\"}"

  curl -fsS --config - -H "Content-Type: application/json" \
    -X POST "http://localhost:${ES_PORT}/_security/user/kibana_system/_password" \
    --data-binary "$payload" >/dev/null <<EOF
user = "elastic:${ELASTIC_PASSWORD}"
EOF
}

probe_kibana_ready() {
  if [[ "$MODE" == "baseline" ]]; then
    curl -fsS "http://localhost:${KIBANA_PORT}/api/status" | grep -q '"level":"available"'
  else
    curl -fsS --cacert "$ROOT_DIR/certs/ca/ca.crt" "https://localhost:${KIBANA_PORT}/api/status" | grep -q '"level":"available"'
  fi
}

log "Mode: $MODE"
log "Project: $PROJECT_NAME"
log "ES_PORT: $ES_PORT"

if [[ "$NO_PULL" == "false" ]]; then
  if ! "${COMPOSE[@]}" pull; then
    log "WARNING: Pull failed. Continuing with locally cached images."
    log "         If this is a fresh install, re-run with network access."
  fi
fi

update_env_kv() {
  local key="$1" value="$2" file="$3"
  [[ -f "$file" ]] || die "Cannot update $key: env file not found at $file"

  # Escape backslashes and double-quotes for .env
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\r'/}"
  value="$(printf "%s" "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  if grep -qE "^${key}=" "$file"; then
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$file"
    else
      sed -i '' "s|^${key}=.*|${key}=\"${value}\"|" "$file"
    fi
  else
    printf "\n%s=\"%s\"\n" "$key" "$value" >> "$file"
  fi
}

generate_service_token() {
  local persist_token="${1:-false}"
  log "Generating new service token via REST API (elastic/kibana/kibana-docker)..."

  # Delete existing token (ignore 404 if it doesn't exist)
  curl -fsS --cacert "$ROOT_DIR/certs/ca/ca.crt" \
    -X DELETE --config - \
    "https://localhost:${ES_PORT}/_security/service/elastic/kibana/credential/token/kibana-docker" \
    >/dev/null 2>&1 <<EOF || true
user = "elastic:${ELASTIC_PASSWORD}"
EOF

  # Create token via REST API — stored in .security index (persistent on esdata volume)
  local response token
  response="$(curl -fsS --cacert "$ROOT_DIR/certs/ca/ca.crt" \
    -X POST --config - \
    "https://localhost:${ES_PORT}/_security/service/elastic/kibana/credential/token/kibana-docker" <<EOF
user = "elastic:${ELASTIC_PASSWORD}"
EOF
  )"

  # Parse token value from JSON response:
  # {"created":true,"token":{"name":"kibana-docker","value":"AAEAAWtoken..."}}
  token="$(printf '%s' "$response" | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

  [[ -n "${token:-}" ]] || die "Failed to parse token from API response: $response"

  export ELASTIC_SERVICE_TOKEN="$token"
  log "ELASTIC_SERVICE_TOKEN updated in current deploy session."

  if [[ "$persist_token" == "true" ]]; then
    log "Persisting ELASTIC_SERVICE_TOKEN to .env (--persist-token enabled)."
    update_env_kv "ELASTIC_SERVICE_TOKEN" "$token" "$ENV_FILE"
  else
    log "Token not written to .env (default secure behavior)."
  fi
}

verify_service_token() {
  curl -fsS --cacert "$ROOT_DIR/certs/ca/ca.crt" --config - \
    "https://localhost:${ES_PORT}/_security/_authenticate" >/dev/null <<EOF
header = "Authorization: Bearer ${ELASTIC_SERVICE_TOKEN}"
EOF
}

trap 'log "Deploy interrupted. Containers may still be running — check with: docker compose -p $PROJECT_NAME ps"' ERR

# Start ES first so we can validate/bootstrap auth before Kibana starts failing
log "Starting Elasticsearch..."
"${COMPOSE[@]}" up -d elasticsearch
wait_for_health elasticsearch
log "Elasticsearch reachable."
probe_es

if [[ "$MODE" == "baseline" ]]; then
  log "Validating kibana_system credentials against Elasticsearch..."
  if ! check_kibana_system_auth; then
    log "kibana_system auth FAILED. This typically happens on a fresh esdata volume."
    log "Auto-resetting kibana_system password from .env via Elasticsearch Security API..."
    reset_kibana_system_password_api || die "Failed to reset kibana_system password automatically."
    FORCE_RECREATE=true

    log "Re-checking kibana_system auth..."
    check_kibana_system_auth || die "kibana_system still cannot authenticate after auto-reset. Verify .env credentials and ES state."
  fi
else
  log "TLS mode: verifying service token against ES (after stack start)..."
  # ES is up, but Kibana not started yet. We can still validate/bootstrap token.
  if [[ -z "${ELASTIC_SERVICE_TOKEN:-}" ]]; then
    [[ "$AUTO_TOKEN" == "true" ]] || die "ELASTIC_SERVICE_TOKEN is empty. Re-run with --auto-token to generate one."
    log "No service token found. Auto-generating one..."
    generate_service_token "$PERSIST_TOKEN"
    FORCE_RECREATE=true
    log "Verifying generated service token..."
    verify_service_token || die "Generated service token failed verification."
  elif ! verify_service_token; then
    if [[ "$AUTO_TOKEN" == "true" ]]; then
      log "Service token invalid (401). Auto-generating a new one..."
      generate_service_token "$PERSIST_TOKEN"
      FORCE_RECREATE=true

      log "Re-checking service token..."
      verify_service_token || die "Newly generated service token still fails. Check ES logs and certificate/auth settings."
    else
      die "Service token auth failed. Re-run with --auto-token or regenerate token manually."
    fi
  fi
fi

UP_ARGS=(up -d)
[[ "$FORCE_RECREATE" == "true" ]] && UP_ARGS+=(--force-recreate)

log "Starting Kibana..."
"${COMPOSE[@]}" "${UP_ARGS[@]}" kibana
wait_for_health kibana

log "Probing Kibana readiness..."
# Poll Kibana readiness in case healthcheck is present but slow to flip
deadline=$((SECONDS + TIMEOUT_SEC))
until probe_kibana_ready; do
  if (( SECONDS >= deadline )); then
    log "Last 120 lines of Kibana logs:"
    "${COMPOSE[@]}" logs --tail=120 kibana || true
    die "Timeout waiting for Kibana /api/status to be available"
  fi
  sleep 3
done

if [[ "$MODE" == "baseline" ]]; then
  log "✅ Baseline ready:"
  log "   Elasticsearch: http://localhost:${ES_PORT}"
  log "   Kibana:        http://localhost:${KIBANA_PORT}"
else
  log "✅ TLS ready:"
  log "   Elasticsearch: https://localhost:${ES_PORT}"
  log "   Kibana:        https://localhost:${KIBANA_PORT}"
fi
