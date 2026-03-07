#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="auto"        # baseline | tls | auto
PROJECT_NAME=""
REMOVE_VOLUMES=false
REMOVE_ORPHANS=false
SKIP_CONFIRM=false

usage() {
  cat <<'USAGE'
Usage:
  scripts/teardown.sh [--mode baseline|tls|auto] [--project NAME] [--volumes] [--yes] [--remove-orphans]

Examples:
  scripts/teardown.sh
  scripts/teardown.sh --mode tls
  scripts/teardown.sh --volumes
  scripts/teardown.sh --volumes --yes   # skip confirmation (CI/scripted use)

Notes:
  --volumes wipes Elasticsearch data and security state (passwords/tokens).
  --yes     skip interactive confirmation for --volumes (use in scripts/CI).
USAGE
}

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[$(date +'%H:%M:%S')] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --project) PROJECT_NAME="${2:-}"; shift 2 ;;
    --volumes) REMOVE_VOLUMES=true; shift ;;
    --remove-orphans) REMOVE_ORPHANS=true; shift ;;
    --yes|-y) SKIP_CONFIRM=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

[[ "$MODE" == "baseline" || "$MODE" == "tls" || "$MODE" == "auto" ]] || die "--mode must be baseline, tls, or auto"

ENV_FILE="$ROOT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -o allexport; source "$ENV_FILE"; set +o allexport
fi

PROJECT_NAME="${PROJECT_NAME:-${COMPOSE_PROJECT_NAME:-elk}}"

COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/compose.yml")
if [[ "$MODE" == "tls" ]]; then
  COMPOSE+=(-f "$ROOT_DIR/compose.tls.yml")
elif [[ "$MODE" == "auto" ]]; then
  [[ -f "$ROOT_DIR/compose.tls.yml" ]] && COMPOSE+=(-f "$ROOT_DIR/compose.tls.yml")
fi

DOWN_ARGS=(down)
if [[ "$REMOVE_VOLUMES" == "true" ]]; then
  if [[ "$SKIP_CONFIRM" != "true" ]]; then
    log "WARNING: This will wipe Elasticsearch data and security state."
    read -rp "Type 'yes' to confirm: " confirm
    [[ "$confirm" == "yes" ]] || die "Aborted."
  fi
  DOWN_ARGS+=(-v)
fi

[[ "$REMOVE_ORPHANS" == "true" ]] && DOWN_ARGS+=(--remove-orphans)

log "Project: $PROJECT_NAME"
log "Mode: $MODE"
log "Down args: ${DOWN_ARGS[*]}"
"${COMPOSE[@]}" "${DOWN_ARGS[@]}"

if [[ "$REMOVE_VOLUMES" == "true" ]]; then
  log "⚠️ Volumes removed. Elasticsearch security state wiped."
  log "   You will need to re-bootstrap kibana_system password and service token."
fi

log "✅ Done."
