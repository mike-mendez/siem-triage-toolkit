# triage/

Artifact lanes for the agentic triage pipeline. Each stage writes to exactly one directory; agents
are confined to their lane by `.claude/hooks/agent-write-guard.sh`. The orchestrator passes file
paths between stages, never file contents.

| Directory       | Written by         | Contents                                              | Lifecycle                 |
| --------------- | ------------------ | ----------------------------------------------------- | ------------------------- |
| `incidents/`    | `alert-intake`     | Normalized incident record (schema from `docs/triage_template.md`) | `Open → Assessed → Closed` |
| `enrichment/`   | `enricher`         | Context lookups (reputation, asset role, geo); stubbed offline | n/a                       |
| `correlation/`  | `correlator`       | Related events around the alert window, evidence-cited | n/a                       |
| `reports/`      | `analyst`          | Disposition: severity, MITRE technique, TP/FP call, recommended next step | drives ratification        |

Files are named by incident id, e.g. `INC-2026-0001.md`, consistent across all lanes for one incident.

These directories are tracked but start empty (`.gitkeep`). Generated triage artifacts are real
work product; decide per your workflow whether to commit them or gitignore them.
