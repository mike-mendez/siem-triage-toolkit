# Playbook: nginx_phpunit_eval_stdin_probe

Template reference: `docs/triage_template.md`

## Alert Summary
Request targeted known PHPUnit `eval-stdin.php` exploit path associated with legacy RCE scanning.

## Scope and Severity
- Default severity: high
- Primary scope: direct requests to vulnerable PHPUnit endpoint path

## Key Pivots
- `source.ip`
- `url.path`
- `http.response.status_code`
- Follow-on requests to adjacent `vendor/` paths

## Investigation Steps
1. Verify target path presence in deployed application artifacts.
2. Determine whether endpoint responded with indicators of executable behavior.
3. Check package/dependency version and patch status for PHPUnit components.
4. Correlate with command-injection or webshell alerts from same source.

## Containment and Response
- Block source and restrict direct web access to vendor paths.
- Remove/deploy patched dependencies and validate build hygiene.
- Trigger incident response if vulnerable endpoint is confirmed in production.

## Evidence Checklist
- Exact targeted PHPUnit path
- Source attribution and recurrence pattern
- Package/version verification evidence
- Remediation timeline and owner

## Escalation Criteria
- Immediate escalation if vulnerable endpoint is reachable.
- Escalate if repeated probes appear across multiple applications.
