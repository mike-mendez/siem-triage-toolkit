# Security Policy

## Supported Versions
This repository is a portfolio/lab toolkit. Security updates are applied on the `main` branch as changes are made.

## Reporting a Vulnerability
- Do not open public issues for active security vulnerabilities.
- Report findings privately to the repository owner.
- Include:
  - affected file(s) and mode (`baseline` or `tls`)
  - reproduction steps
  - expected vs observed behavior
  - impact and suggested mitigation

## Security Expectations
- Never commit secrets (`.env`, private keys, service tokens).
- TLS mode is the recommended default for security-focused testing.
- Use project-scoped Compose names to avoid cross-environment state leakage.
- Rotate credentials/tokens after `--volumes` resets or suspected disclosure.
