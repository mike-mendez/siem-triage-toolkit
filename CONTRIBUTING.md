# Contributing

Thanks for your interest in improving this SIEM deploy & triage toolkit. This guide
covers environment setup, the branching model, testing, and our commit conventions.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). For
security issues, **do not** open a public issue — follow [SECURITY.md](SECURITY.md).

## Development Environment Setup

1. Copy the env template and fill in local values:
   ```bash
   cp .env.example .env
   ```
2. Install and activate the git hooks (required — they run secret scanning, commit
   linting, and the co-author guard):
   ```bash
   pipx install pre-commit   # or: pip install --user pre-commit
   pre-commit install --hook-type pre-commit --hook-type commit-msg
   ```
3. Start the stack:
   ```bash
   scripts/deploy.sh --mode baseline          # http baseline
   scripts/deploy.sh --mode tls --auto-token  # tls
   ```

## Branching Model

- `master` is the default branch and always deployable.
- Create a short-lived feature branch off `master`:
  `feat/<short-topic>`, `fix/<short-topic>`, `docs/<short-topic>`, etc.
- Open a pull request into `master`. Security-critical paths require review from a
  code owner (see [.github/CODEOWNERS](.github/CODEOWNERS)).
- Keep PRs focused; rebase on `master` before requesting review.

## Contribution Guidelines

- Keep changes mode-aware (`baseline` and `tls` behavior should be explicit).
- Prefer secure defaults over convenience shortcuts.
- Keep scripts non-destructive unless explicitly requested by the operator.
- Update `README.md` and `docs/runbook.md` when workflow behavior changes.

## Testing & Validation

Run these before opening a PR:

- Render compose configs:
  ```bash
  docker compose -f compose.yml config
  docker compose -f compose.yml -f compose.tls.yml config
  ```
- Script help output:
  ```bash
  scripts/deploy.sh --help
  scripts/teardown.sh --help
  ```
- Detection-validation harness (must pass, including every `must_not_hit`):
  ```bash
  python3 scripts/test_detections.py
  scripts/check_detection_pack.sh
  ```
- Run all pre-commit hooks across the tree:
  ```bash
  pre-commit run --all-files
  ```

## Commit Conventions

This repository requires **[Conventional Commits](https://www.conventionalcommits.org/)**.
Commit messages are linted at the `commit-msg` stage by the `commitizen` hook; a
non-conforming message is rejected locally before the commit is created.

Format:

```
<type>(<scope>)<!>: <subject>

[optional body]

[optional footer(s)]
```

**Accepted types:** `feat`, `fix`, `docs`, `refactor`, `chore`, `test`, `build`, `ci`,
`perf`, `style`.

**Common scopes in this repo:** `triage`, `detections`, `claude`, `hooks`, `ci`,
`docs`, `deploy`, `security`, `deps`, `governance`.

**Breaking changes:** append `!` after the type/scope (e.g. `refactor(deploy)!: ...`)
and/or add a `BREAKING CHANGE:` footer describing the break.

Examples:
- `feat(detections): add nginx LFI traversal rule`
- `fix(deploy): correct TLS verification mode in kibana config`
- `docs(security): document coordinated disclosure window`
- `refactor(claude)!: rename orchestrator settings schema`

> Note: commits must not include `Co-authored-by: Claude` or "Generated with Claude
> Code" trailers — a `commit-msg` guard rejects them. Claude Code's `attribution`
> setting is disabled in `.claude/settings.json` to prevent these.

## Secrets and Sensitive Data

- Never commit `.env`.
- Never commit private key material (`*.key`, `*.p12`, `*.pfx`).
- Do not paste real tokens/passwords into issues, PRs, or docs.
- A gitleaks pre-commit hook and CI secret scan enforce this, but they are a backstop —
  not a license to be careless.
