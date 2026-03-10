# Playbook: nginx_webshell_path_probe

Template reference: `docs/triage_template.md`

## Alert Summary
Request targeted a path commonly associated with webshell deployment or command execution.

## Scope and Severity
- Default severity: high
- Primary scope: suspicious `.php` shell paths or traversal-to-shell probes

## Key Pivots
- `source.ip`
- `url.path` and full `url.original`
- `http.request.method`
- `user_agent.original`
- Any subsequent successful responses from same path/source

## Investigation Steps
1. Validate whether targeted path is expected in the application.
2. Check for follow-up requests with command-like query parameters (`cmd=`, `exec=`, etc.).
3. Inspect nearby logs for upload endpoints and unusual write activity.
4. Correlate with endpoint/web server telemetry for file creation events.

## Containment and Response
- Block source if malicious intent is confirmed.
- Isolate affected host if compromise is suspected.
- Search for unauthorized web-accessible scripts in upload/static paths.

## Evidence Checklist
- Full suspicious URL and method
- Source IP/user-agent and request timing pattern
- Any successful (2xx) responses to suspect paths
- File integrity/endpoint artifacts around web root

## Escalation Criteria
- Immediate escalation when suspicious path is successfully served/executed.
- Escalate if paired with SQLi/recon activity from same source.
