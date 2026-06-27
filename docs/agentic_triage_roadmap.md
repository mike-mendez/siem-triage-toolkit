# Roadmap: Agentic SIEM Triage Pipeline

> Status: in progress (updated 2026-06). The core human-gated pipeline is **delivered** — phases
> 1-4 in section 9 (reframe, scaffold, vertical slice, tuner + harness gate are all in place and
> the pipeline has been run end-to-end). The phase 5 **CI harness** — running `test_detections.py`
> on every push and PR — is now in place (`.github/workflows/detection-harness.yml`). **Remaining:**
> the phase 5 eval scorecard (extending `detection_quality.md`) and the optional phase 6 (continuous learning).
>
> This document defines that phase: turning manual triage into an orchestrated, human-gated agentic
> pipeline running on Claude Code.

## 1. Why this phase

The toolkit today deploys ELK, ships an offline Nginx detection pack with schema-gated rule
contracts, and validates rules with a `must_hit` / `must_not_hit` harness. Everything is
human-driven: a person writes rules, runs the harness, reads results, and decides dispositions.

This phase adds an **agentic triage pipeline** that mirrors how a SOC analyst actually works —
ingest an alert, enrich it, correlate related events, assess severity against MITRE ATT&CK,
recommend a disposition, and (only on human approval) propose a detection tuning that is proven
safe by the existing validation harness before it lands.

The design borrows two patterns from prior art and adapts them to a security context:

- **CodeSeoul `automate-development-with-agents`** — the orchestrator + specialist-subagent
  pipeline, file-based artifact handoff, and deterministic guard hooks. This is the structural
  backbone.
- **ECC (`affaan-m/ECC`)** — the narrower ideas of verification loops and continuous learning
  (distilling recurring patterns into reusable "instincts"). Used as inspiration, not vendored;
  ECC is a general dev harness and folding it in wholesale would bury this focused tool.

## 2. Design principles (security-specific invariants)

These are non-negotiable and will live in `AGENTS.md`:

- **No autonomous action on production.** Agents never block IPs, close alerts, modify firewall
  state, or delete data. They produce recommendations and artifacts; humans act.
- **Gate before tuning.** No detection rule change is accepted until the existing
  `scripts/test_detections.py` harness passes, including all `must_not_hit` assertions.
- **Evidence or it didn't happen.** Every severity claim and disposition cites the specific log
  lines, fields, or ES query results that support it.
- **Read-only by default.** Enrichment and correlation agents have read-only access to the stack.
  Only the detection-tuner writes, and only into `config/detections/`, confined by a guard hook.
- **Human ratification gates the pipeline.** Disposition and any tuning are proposed, not applied,
  until a human accepts — mirroring CodeSeoul's "spec must be Ratified" gate.

## 3. Pipeline overview

```
alert → intake → enrich → correlate → assess → (human ratifies) → tune detection → validate
```

The `orchestrator` is the default session agent and the only one that talks to the user. It spawns
specialists, passes them file paths (never artifact content) to keep its own context lean, and
resumes them on kick-back signals (`NEEDS CONTEXT:` → run enricher; `NEEDS DECISION:` → ask the human).

| Stage      | Agent              | Model  | Writes                       | Reads                         |
| ---------- | ------------------ | ------ | ---------------------------- | ----------------------------- |
| Intake     | `alert-intake`     | sonnet | `triage/incidents/<id>.md`   | raw alert JSON                |
| Enrich     | `enricher`         | haiku  | `triage/enrichment/<id>.md`  | incident + threat-intel stubs |
| Correlate  | `correlator`       | sonnet | `triage/correlation/<id>.md` | incident + ES (read-only)     |
| Assess     | `analyst`          | opus   | `triage/reports/<id>.md`     | all of the above + MITRE map  |
| Tune       | `detection-tuner`  | sonnet | `config/detections/**`       | report + harness results      |

## 4. Artifact lanes

Each artifact type has one home so the agents never blur incidents, analysis, and rule changes:

- **`triage/incidents/`** — normalized incident records. Schema derives from the existing
  `docs/triage_template.md`. Lifecycle `Open → Assessed → Closed`.
- **`triage/enrichment/`** — context lookups (IP reputation, asset role, geo). Stubbed first,
  real connectors later.
- **`triage/correlation/`** — related-event queries around the alert window.
- **`triage/reports/`** — the analyst's disposition: severity, MITRE technique, true/false
  positive call, recommended next step, and the evidence behind each claim.
- **`config/detections/`** — the only place rule changes land, and only after the harness passes.

## 5. Guard hooks (deterministic, run by the harness)

Adapted from CodeSeoul's `agent-write-guard.sh` / `prune-worktrees.sh`:

- **`agent-write-guard.sh`** (`PreToolUse`) — confines `alert-intake` to `triage/incidents/`,
  the read-only agents to no writes at all, and `detection-tuner` to `config/detections/`.
- **`require-harness-pass.sh`** (`PreToolUse` on detection-tuner writes / `Stop`) — refuses to let
  a rule change be marked accepted unless `scripts/test_detections.py` exits clean.
- **`no-prod-action-guard.sh`** (`PreToolUse` on `Bash`) — blocks any command matching a denylist
  of state-changing actions (firewall, alert-close API calls, `docker ... down -v`, deletes).

## 6. Continuous learning (ECC-inspired, optional later phase)

When the analyst repeatedly marks the same rule a false positive for the same reason, that pattern
gets distilled into a small reusable "tuning instinct" the tuner consults next time. Keep this as a
clearly separated, opt-in skill so the core pipeline stays legible.

## 7. Verification / scorecard

Extend `docs/detection_quality.md` into an eval that scores each detection on precision against the
fixtures (false-positive rate from `must_not_hit`, recall from `must_hit`). Add a CI workflow that
runs the harness on every PR so rule changes can't regress silently.

## 8. Proposed file tree (additions only)

```
.claude/
  settings.json              # default agent = orchestrator; wires hooks
  agents/
    orchestrator.md
    alert-intake.md
    enricher.md
    correlator.md
    analyst.md
    detection-tuner.md
  hooks/
    agent-write-guard.sh
    require-harness-pass.sh
    no-prod-action-guard.sh
AGENTS.md                    # always-apply security invariants (short, ~150 lines max)
triage/
  incidents/.gitkeep
  enrichment/.gitkeep
  correlation/.gitkeep
  reports/.gitkeep
  README.md                  # explains the lanes + lifecycle
docs/
  agentic_triage_roadmap.md  # this file
samples/alerts/              # sample alert JSON to feed the pipeline
.github/workflows/
  detection-harness.yml      # run test_detections.py on every PR
```

## 9. Phased delivery

Each phase is a clean, self-contained set of commits. Resist a big-bang rewrite.

1. **Reframe** _(done)_ — land this roadmap + a README scope update. Signals direction immediately.
2. **Scaffold** _(done)_ — add `.claude/` (orchestrator + agents), `AGENTS.md`, hooks, `triage/` lanes.
3. **One real vertical slice** _(done)_ — alert → intake → analyst → report against the existing Nginx pack
   and fixtures, with enrichment stubbed. One working path beats five stubs.
4. **Tuner + harness gate** _(done)_ — the differentiating piece; reuses `test_detections.py`.
5. **Eval + CI** _(partial — CI harness done; eval scorecard remaining)_ — the PR harness workflow (`.github/workflows/detection-harness.yml`) runs `test_detections.py` on every push and PR; the scorecard extending `detection_quality.md` is still to add.
6. **Continuous learning** _(planned, optional)_ — optional, opt-in instincts layer.

## 10. Resume / interview framing

- "Built a human-gated agentic SOC triage pipeline on Claude Code: orchestrator delegates to
  read-only enrichment/correlation/assessment specialists, with deterministic guard hooks that
  prevent autonomous production actions and block detection changes until a validation harness passes."
- The *gating* and *no-autonomous-action* design is itself the security story — it demonstrates you
  understand the risk of agents acting on live infrastructure, not just that you can wire agents up.
