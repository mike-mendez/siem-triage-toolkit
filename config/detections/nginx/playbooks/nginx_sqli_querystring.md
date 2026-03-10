# Playbook: nginx_sqli_querystring

Template reference: `docs/triage_template.md`

## Alert Summary
Potential SQL injection pattern observed in Nginx URL/query telemetry.

## Scope and Severity
- Default severity: medium
- Primary scope: requests containing SQLi-like payload fragments

## Key Pivots
- `source.ip`
- `url.original` and `url.query`
- `http.request.method`
- `user_agent.original`
- Adjacent events from same source within 15 minutes

## Investigation Steps
1. Confirm payload semantics in `url.query` (tautology, union-select, sleep, schema probing).
2. Check if the source is allowlisted scanner or expected QA traffic.
3. Review response status/body size patterns to spot successful exploitation indicators.
4. Pivot on `source.ip` for other suspicious paths and request bursts.

## Containment and Response
- Rate-limit or block abusive source at WAF/reverse proxy if hostile.
- Review vulnerable endpoint and parameter handling.
- Coordinate with app owner for immediate patching/hardening.

## Evidence Checklist
- Raw request path/query
- Source IP and User-Agent
- Status code trend before/after attempts
- Related hits from webshell/recon rules

## Escalation Criteria
- Escalate immediately if payloads are successful (2xx/3xx plus anomalous behavior).
- Escalate if same source triggers multiple web exploitation rules.
