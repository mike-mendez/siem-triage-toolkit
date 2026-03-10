# Playbook: nginx_404_recon_burst

Template reference: `docs/triage_template.md`

## Alert Summary
Single source generated repeated 404s against sensitive/admin paths, consistent with reconnaissance.

## Scope and Severity
- Default severity: medium
- Trigger condition: >=5 matching 404 events from one source in fixture set/window

## Key Pivots
- `source.ip`
- Repeated `url.path` values
- Time density of requests
- Related authentication/application alerts

## Investigation Steps
1. Confirm path pattern aligns with known recon targets (`/wp-admin`, `/.env`, `/phpmyadmin`, etc.).
2. Determine if source belongs to internal scanning or external internet host.
3. Check if burst is followed by exploit attempts (SQLi/webshell probes).
4. Review historical activity from same source against other services.

## Containment and Response
- Apply temporary block/rate limiting for non-approved external scanners.
- Tighten exposure of admin routes and ensure secrets are not web-accessible.
- Validate WAF/reverse proxy detections for repeated probing.

## Evidence Checklist
- Source IP and request count
- List of targeted sensitive paths
- Time window of burst
- Any follow-on suspicious detections tied to same source

## Escalation Criteria
- Escalate when recon burst is followed by exploitation signals.
- Escalate for repeated bursts across multiple apps/services.
