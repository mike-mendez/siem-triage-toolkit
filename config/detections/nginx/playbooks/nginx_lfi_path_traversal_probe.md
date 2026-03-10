# Playbook: nginx_lfi_path_traversal_probe

Template reference: `docs/triage_template.md`

## Alert Summary
Request pattern indicates attempted local file inclusion/path traversal behavior against web endpoints.

## Scope and Severity
- Default severity: high
- Primary scope: requests with traversal fragments (`../`, encoded `%2e%2e`) and sensitive file targets

## Key Pivots
- `source.ip`
- `url.path`, `url.query`, `url.original`
- `http.response.status_code`
- Nearby requests from same source to admin/upload routes

## Investigation Steps
1. Verify traversal intent in raw path/query and target file path (`/etc/passwd`, `/proc/self/environ`).
2. Check whether app routing or CDN rewrites could explain benign traversal-like strings.
3. Correlate with subsequent exploitation attempts (webshell, command injection, auth abuse).
4. Review endpoint/server telemetry for file read anomalies around alert time.

## Containment and Response
- Block source IP or apply temporary WAF deny rules for traversal signatures.
- Validate app/framework path normalization and disable unsafe file include logic.
- Escalate for rapid patching if vulnerable endpoint is internet-exposed.

## Evidence Checklist
- Full request URI and decoded payload
- Source IP and burst context
- Endpoint ownership and exposure status
- Any follow-on exploitation attempts from same source

## Escalation Criteria
- Immediate escalation if sensitive file content exposure is confirmed.
- Escalate when traversal attempts are paired with successful 2xx responses.
