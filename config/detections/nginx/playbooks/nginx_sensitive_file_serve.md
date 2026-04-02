# Playbook: nginx_sensitive_file_serve

Template reference: `docs/triage_template.md`

## Alert Summary
Successful serves of known-sensitive resource paths that should not be publicly available.

## Scope and Severity
- Default severity: high
- Primary scope: successful direct requests to `.env`, `wp-config.php`, `.git/config`, `.php`, `.yaml` variants, backup SQL artifacts

## Key Pivots
- `source.ip`
- `url.path`
- `http.response.status_code`
- Successful path probing from same or various unauthorized sources

## Investigation Steps
1. Identify what data was in the served file.
2. Check for additional recon/exploitation patterns from same source.
3. Validate server configuration for deny rules on sensitive files.

## Containment and Response
- Block offending source and tighten perimeter rules for sensitive path patterns.
- Immediately assess whether credentials in the exposed file are still active and rotate them.
- Add server-level deny rules and remove sensitive files from web root.

## Evidence Checklist
- Requested sensitive path(s)
- Response code and byte patterns
- Source attribution and recurrence
- Remediation actions and owner confirmation

## Escalation Criteria
- Escalate if the served file contained credentials or secrets that could enable further compromise.
- Escalate if the same sensitive path returns 200 across multiple applications.
