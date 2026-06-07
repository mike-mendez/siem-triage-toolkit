#!/usr/bin/env bash
# PreToolUse guard on Bash: block any command that would change live infrastructure
# or destroy data. Triage agents produce recommendations; humans take action.
#
# Exit codes: 0 = allow, 2 = block.

set -euo pipefail

payload="$(cat)"

if command -v jq >/dev/null 2>&1; then
  cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty')"
else
  cmd="$(printf '%s' "$payload" | grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:"([^"]*)"/\1/')"
fi

[ -z "${cmd:-}" ] && exit 0

# Denylist of state-changing / destructive patterns. Extend as needed.
deny=(
  'docker[[:space:]].*down[[:space:]].*-v'      # tears down volumes
  'docker[[:space:]].*(rm|kill|stop)'           # stop/remove containers
  'docker[[:space:]]volume[[:space:]]rm'
  'teardown\.sh.*--volumes'
  '\brm[[:space:]]+-rf?\b'                       # recursive delete
  'iptables'                                      # firewall changes
  'ufw[[:space:]]+(deny|allow|delete)'
  'pf(ctl)?[[:space:]]'                           # bsd/macos packet filter
  '[[:space:]]-X[[:space:]]*(DELETE|PUT|POST)'   # mutating HTTP to ES/Kibana
  'curl.*_(close|delete|bulk|update)'
  'elasticsearch.*(delete|close)_index'
)

for pat in "${deny[@]}"; do
  if printf '%s' "$cmd" | grep -Eiq -e "$pat"; then
    echo "[no-prod-action] BLOCKED: command matches prohibited pattern /$pat/." >&2
    echo "[no-prod-action] Triage agents do not change live infrastructure or delete data." >&2
    echo "[no-prod-action] Write a recommendation to the triage artifact for a human to act on." >&2
    exit 2
  fi
done

exit 0
