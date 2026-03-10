# Playbook: nginx_login_bruteforce_burst

Template reference: `docs/triage_template.md`

## Alert Summary
Single source generated repeated failed login attempts consistent with brute-force behavior.

## Scope and Severity
- Default severity: high
- Trigger condition: >=5 failed `POST` logins (`401`) from one source to auth endpoints

## Key Pivots
- `source.ip`
- `url.path` (`/api/login`, `/wp-login.php`)
- `http.request.method` and `http.response.status_code`
- Adjacent successful auth events from same source/user

## Investigation Steps
1. Confirm burst threshold and timing density of failed login events.
2. Identify targeted account identifiers from app/auth logs (if available).
3. Check whether source IP is internal QA automation or external actor.
4. Pivot for follow-on access attempts after failures (credential stuffing progression).

## Containment and Response
- Apply IP throttling/temporary blocks and enforce MFA where possible.
- Notify application owner to review account lockout and rate-limit controls.
- Consider forced credential reset for impacted accounts.

## Evidence Checklist
- Failed attempt count and time window
- Source IP and targeted login path(s)
- Any correlated success after failure burst
- Existing auth control posture (lockout/MFA/rate-limit)

## Escalation Criteria
- Escalate immediately if brute force is followed by successful authentication.
- Escalate if campaign appears distributed across multiple source IPs.
