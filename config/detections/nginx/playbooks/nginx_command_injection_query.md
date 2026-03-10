# Playbook: nginx_command_injection_query

Template reference: `docs/triage_template.md`

## Alert Summary
Request query contains shell metacharacters and command tokens indicative of command injection probing.

## Scope and Severity
- Default severity: high
- Primary scope: command-like query payloads (`;cat /etc/passwd`, pipe-to-command, backtick execution)

## Key Pivots
- `source.ip`
- `url.query` and `url.original`
- `http.response.status_code`
- Related exploit traffic from same source

## Investigation Steps
1. Validate command payload semantics in encoded and decoded forms.
2. Check whether targeted parameter is expected to execute system commands.
3. Inspect server/app logs for command execution side effects.
4. Correlate with file access, webshell, and auth abuse signals.

## Containment and Response
- Block source and add WAF signatures for command injection payloads.
- Patch vulnerable handler endpoints and implement strict input validation.
- Investigate host telemetry for command/process artifacts during alert window.

## Evidence Checklist
- Full payload and decoded command intent
- Source IP and request sequence
- Server-side execution evidence (or absence)
- Applied controls and patch owner

## Escalation Criteria
- Immediate escalation if server command execution is confirmed.
- Escalate when repeated probing persists after blocking controls.
