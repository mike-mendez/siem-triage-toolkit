#!/usr/bin/env bash
# PreToolUse guard on writes/edits under config/detections/:
# refuse to let a detection change land unless the offline validation harness
# currently passes. This runs the harness against the CURRENT tree before the
# write is applied, then the tuner is expected to re-run it after editing too.
#
# Rationale: a rule change must never be accepted on a red harness. The tuner's
# own procedure also runs the harness post-edit; this hook is the deterministic
# backstop so the rule can't be bypassed by an agent skipping its steps.
#
# Exit codes: 0 = allow, 2 = block.

set -euo pipefail

# Resolve project dir (Claude Code sets CLAUDE_PROJECT_DIR; fall back to cwd).
proj="${CLAUDE_PROJECT_DIR:-$(pwd)}"
harness="$proj/scripts/test_detections.py"

if [ ! -f "$harness" ]; then
  echo "[harness-gate] WARNING: $harness not found; cannot verify. Blocking to be safe." >&2
  echo "[harness-gate] Check the path in .claude/settings.json matches your repo." >&2
  exit 2
fi

# Run the harness quietly. Any nonzero exit blocks the write.
if ! python3 "$harness" >/tmp/harness-gate.log 2>&1; then
  echo "[harness-gate] BLOCKED: validation harness is failing; detection changes are not allowed" >&2
  echo "[harness-gate] until it passes (including all must_not_hit assertions). Last output:" >&2
  tail -n 20 /tmp/harness-gate.log >&2 || true
  exit 2
fi

exit 0
