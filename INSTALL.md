# Installing the agentic triage scaffold

Copy these into the root of your `siem-triage-toolkit` repo, preserving paths:

```
.claude/                 # agents, hooks, settings
AGENTS.md                # always-apply security invariants
triage/                  # artifact lanes (incidents/enrichment/correlation/reports)
samples/alerts/          # sample alert to exercise the pipeline
docs/agentic_triage_roadmap.md   # the roadmap (rename from the separately-shared file)
```

Then:

1. `chmod +x .claude/hooks/*.sh` (already executable here; re-apply after copy if needed).
2. Verify the paths in `.claude/settings.json` and `.claude/hooks/require-harness-pass.sh`
   match your repo — they assume `scripts/test_detections.py` and `config/detections/`.
3. Confirm Claude Code is v2.1.0+ (`claude --version`). The hook wiring in `settings.json`
   follows the matcher syntax from that version.
4. Start a Claude Code session in the repo and try:
   `Triage the alert at samples/alerts/INC-sample-sqli.json`
   The orchestrator should run intake → enrich → correlate → assess, then pause for your
   ratification before any tuning.

## Smoke-testing the hooks without Claude Code

The guards read JSON on stdin. Quick manual checks:

```bash
# write-guard: enricher trying to write outside its lane -> should BLOCK (exit 2)
echo '{"agent":"enricher","tool_input":{"file_path":"config/detections/nginx/x.json"}}' \
  | .claude/hooks/agent-write-guard.sh; echo "exit=$?"

# write-guard: enricher writing in its lane -> should ALLOW (exit 0)
echo '{"agent":"enricher","tool_input":{"file_path":"triage/enrichment/INC-1.md"}}' \
  | .claude/hooks/agent-write-guard.sh; echo "exit=$?"

# no-prod-action: destructive command -> should BLOCK (exit 2)
echo '{"tool_input":{"command":"docker compose down -v"}}' \
  | .claude/hooks/no-prod-action-guard.sh; echo "exit=$?"
```
