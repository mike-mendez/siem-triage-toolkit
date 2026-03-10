#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPORT_PATH="${1:-}"

echo "[check] Running detection pack quality gates..."
python3 scripts/test_detections.py --output-format text

if [[ -n "$REPORT_PATH" ]]; then
  echo "[check] Writing JSON report to $REPORT_PATH"
  python3 scripts/test_detections.py --output-format json --json-file "$REPORT_PATH" >/dev/null
else
  python3 scripts/test_detections.py --output-format json >/dev/null
fi

echo "[check] Detection pack checks passed."
