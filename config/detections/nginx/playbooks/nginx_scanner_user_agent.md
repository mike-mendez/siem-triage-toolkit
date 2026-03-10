# Playbook: nginx_scanner_user_agent

Template reference: `docs/triage_template.md`

## Alert Summary
Request user-agent matches a known scanning tool signature.

## Scope and Severity
- Default severity: medium
- Primary scope: user-agent strings tied to active reconnaissance tooling

## Key Pivots
- `source.ip`
- `user_agent.original`
- Request path diversity from same source
- Temporal clustering of scanner traffic

## Investigation Steps
1. Verify scanner signature and normalize casing variants.
2. Determine whether source belongs to approved internal scanning ranges.
3. Review targeted paths to estimate intent (recon only vs exploit attempts).
4. Link with other rule hits from same source in the same window.

## Containment and Response
- For unauthorized scanners, block/rate-limit source and monitor recurrence.
- For authorized scanners, tag/suppress according to change window policy.
- Update allowlists only with documented ownership and expiry.

## Evidence Checklist
- Source IP and scanner user-agent
- Targeted endpoint categories
- Authorized vs unauthorized determination
- Suppression/allowlist decision record

## Escalation Criteria
- Escalate when scanner traffic transitions to exploitation indicators.
- Escalate when scanners target production-only sensitive routes unexpectedly.
