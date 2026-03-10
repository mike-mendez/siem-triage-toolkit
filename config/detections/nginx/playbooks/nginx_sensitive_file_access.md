# Playbook: nginx_sensitive_file_access

Template reference: `docs/triage_template.md`

## Alert Summary
Source requested paths commonly associated with leaked secrets or configuration files.

## Scope and Severity
- Default severity: high
- Primary scope: direct requests to `.git/config`, `wp-config.php`, `.env` variants, backup SQL artifacts

## Key Pivots
- `source.ip`
- `url.path`
- `http.response.status_code`
- Sequential path probing from same source

## Investigation Steps
1. Confirm whether requested sensitive path exists or should be inaccessible.
2. Determine if response status/size indicates potential disclosure success.
3. Check for additional recon/exploitation patterns from same source.
4. Validate server configuration for deny rules on sensitive files.

## Containment and Response
- Block offending source and tighten perimeter rules for sensitive path patterns.
- Rotate credentials/secrets if exposure is suspected.
- Add server-level deny rules and remove sensitive files from web root.

## Evidence Checklist
- Requested sensitive path(s)
- Response code and byte patterns
- Source attribution and recurrence
- Remediation actions and owner confirmation

## Escalation Criteria
- Immediate escalation when sensitive files are served (2xx).
- Escalate if repeated probing is observed across multiple applications.
