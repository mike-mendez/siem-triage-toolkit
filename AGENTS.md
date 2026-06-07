# AGENTS.md

Always-apply conventions for every agent in this repo. Read every time. Keep this file short;
if a line wouldn't cause a mistake by its absence, remove it. Repo layout and architecture live in
`README.md` and `docs/agentic_triage_roadmap.md`, not here.

## What this repo is

An ELK-based SIEM deploy & triage toolkit. The agentic layer triages security alerts against an
offline detection pack and proposes (never applies) detection tuning. You are operating on a
security tool: caution is the default, not the exception.

## Hard prohibitions (each paired with what to do instead)

- **Do not take autonomous action on infrastructure.** No blocking IPs, closing alerts, changing
  firewall/iptables state, stopping containers, or deleting volumes/data. → Write your finding and
  recommendation to the correct `triage/` artifact and let a human act.
- **Do not accept a detection change until the harness passes.** → Run `python3 scripts/test_detections.py`
  and only mark a rule change ready if it exits clean, including every `must_not_hit` assertion.
- **Do not assert severity or disposition without evidence.** → Cite the specific log lines, field
  values, or ES query results that support each claim, inline in the artifact.
- **Do not write outside your lane.** → Each agent writes only to its assigned directory (enforced
  by `agent-write-guard.sh`). If you need something elsewhere, kick back to the orchestrator.
- **Do not invent enrichment data.** → If a lookup source is stubbed or unavailable, say so
  explicitly and mark the field `unknown`; never fabricate reputation, geo, or asset facts.
- **Do not guess when a human decision is needed.** → Return `NEEDS DECISION: <question>` to the
  orchestrator rather than choosing for the user on disposition or any state-changing step.

## Workflow invariants

- Pass **file paths, not file contents**, between stages. Keep context lean.
- The pipeline gates on human ratification: planning a tuning and writing to `config/detections/`
  do not begin until the analyst's report disposition is accepted by the user.
- Kick-back signals: `NEEDS CONTEXT:` (orchestrator runs the enricher), `NEEDS DECISION:`
  (orchestrator asks the human). Subagents cannot spawn subagents.
- Before claiming success, run the relevant check (`scripts/check_detection_pack.sh` or
  `scripts/test_detections.py`) and report failures plainly. Do not report success on a failing run.

## Key paths (do not hardcode elsewhere; reference these)

- Detection pack: `config/detections/nginx/`
- Rule schema contract: `config/detections/rule.schema.json`
- Field contract: `config/detections/field_contract.md`
- Fixtures: `samples/logs/nginx_access.log`
- Expected outcomes: `tests/expected_hits.json`
- Offline harness: `scripts/test_detections.py`
- Local quality gate: `scripts/check_detection_pack.sh`
- MITRE mapping: `docs/mitre_mapping.md`
- Triage template (incident schema source): `docs/triage_template.md`

## Honesty

State uncertainty plainly. "Insufficient evidence to disposition" is a valid analyst output and is
preferred over a confident guess. Formatting and linting are left to deterministic tooling, not you.
