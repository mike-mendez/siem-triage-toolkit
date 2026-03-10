# Playbook: nginx_xss_query_probe

Template reference: `docs/triage_template.md`

## Alert Summary
Request query includes encoded script/event-handler payloads consistent with reflected XSS probing.

## Scope and Severity
- Default severity: medium
- Primary scope: encoded `<script>` and inline event payloads in query parameters

## Key Pivots
- `source.ip`
- `url.query` and `url.original`
- Response behavior for targeted endpoint
- Repeat payload patterns from same source

## Investigation Steps
1. Decode and classify payload style (`<script>`, `onerror=`, `javascript:`).
2. Determine if target parameter is reflected without sanitization.
3. Review app-side logs or test endpoint manually in a safe lab context.
4. Check whether same source also triggered SQLi/command injection probes.

## Containment and Response
- Apply output encoding and input sanitization in impacted routes.
- Add temporary WAF signatures for common reflected XSS probes.
- Coordinate with app owners for secure coding remediation and regression tests.

## Evidence Checklist
- Raw and decoded payload
- Target endpoint and reflection behavior
- Source attribution and recurrence
- Mitigation and verification notes

## Escalation Criteria
- Escalate if exploitable reflected XSS is confirmed.
- Escalate when broad payload spray is observed across multiple parameters/routes.
