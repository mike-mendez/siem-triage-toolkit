#!/usr/bin/env bash
# PreToolUse guard: confine each agent's writes to its assigned lane.
# Claude Code passes hook context as JSON on stdin. We read the active agent
# and the target file path, and exit non-zero (with a message on stderr) to block.
#
# Exit codes: 0 = allow, 2 = block (Claude Code treats stderr + nonzero as a denial).

set -euo pipefail

payload="$(cat)"

# Extract fields with jq if available, else fall back to grep.
if command -v jq >/dev/null 2>&1; then
  agent="$(printf '%s' "$payload" | jq -r '.agent // .agent_name // empty')"
  path="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // empty')"
else
  agent="$(printf '%s' "$payload" | grep -oE '"agent(_name)?"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')"
  path="$(printf '%s' "$payload" | grep -oE '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')"
fi

# No path or no agent context -> nothing to enforce here.
[ -z "${path:-}" ] && exit 0
[ -z "${agent:-}" ] && exit 0

# Lane definitions: agent -> allowed path prefix (regex).
case "$agent" in
  alert-intake)      allowed='(^|/)triage/incidents/' ;;
  enricher)          allowed='(^|/)triage/enrichment/' ;;
  correlator)        allowed='(^|/)triage/correlation/' ;;
  analyst)           allowed='(^|/)triage/reports/' ;;
  detection-tuner)   allowed='(^|/)config/detections/' ;;
  orchestrator)      allowed='(^|/)triage/' ;;   # orchestrator may write status notes under triage/
  *)                 exit 0 ;;                    # unknown agent: not our lane to police
esac

if printf '%s' "$path" | grep -Eq "$allowed"; then
  exit 0
fi

echo "[write-guard] BLOCKED: agent '$agent' may not write to '$path' (allowed lane: $allowed)." >&2
echo "[write-guard] If you need something elsewhere, kick back to the orchestrator." >&2
exit 2
