# Security Policy

This project is a SIEM deploy & triage toolkit. We take the security of the toolkit —
and of the people who report issues in it — seriously.

## Supported Versions

This is a portfolio/lab toolkit released as a rolling distribution: security fixes are
applied to the tip of the default branch (`master`). There are no long-term support
branches; always run the latest `master`.

| Version            | Supported |
| ------------------ | --------- |
| `master` (latest)  | ✅        |
| any older commit   | ❌        |

## Reporting a Vulnerability

**Please do not open public issues, pull requests, or discussions for security
vulnerabilities.** Public disclosure before a fix puts users at risk.

Report privately using **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab → **Report a vulnerability**
   (or: <https://github.com/mike-mendez/siem-triage-toolkit/security/advisories/new>).
2. GitHub creates a private advisory visible only to you and the maintainer.

Please include:
- affected file(s) and deployment mode (`baseline` or `tls`);
- reproduction steps and a proof of concept if available;
- expected vs. observed behavior;
- impact assessment and any suggested mitigation.

## Our Commitments (Coordinated Disclosure)

| Stage                         | Target window                                  |
| ----------------------------- | ---------------------------------------------- |
| Acknowledge your report       | within **3 business days**                     |
| Initial assessment & severity | within **10 business days**                    |
| Fix or mitigation for valid,  | within **90 days** of acknowledgement          |
| high-impact issues            | (sooner for critical, actively-exploited bugs) |
| Public disclosure             | coordinated with you, after a fix is available |

We will keep you informed of progress, credit you in the advisory and release notes
(unless you prefer to remain anonymous), and coordinate the disclosure timing with you.

## Safe Harbor

We support good-faith security research. If you make a genuine effort to comply with
this policy, we will consider your research **authorized**, will not pursue or support
legal action against you, and will work with you to understand and resolve the issue.
Good faith means:
- you only test against your **own** local deployment of this toolkit;
- you avoid privacy violations, data destruction, and service disruption;
- you do **not** access, modify, or exfiltrate data that is not yours;
- you give us a reasonable time to remediate before any public disclosure.

This safe harbor applies to the toolkit in this repository only; it cannot authorize
testing against third-party systems (e.g. Elastic, GitHub) or any infrastructure you
do not own.

## Security Expectations for Contributors

- Never commit secrets (`.env`, private keys, service tokens). The repository enforces
  this with a gitleaks pre-commit hook and a CI secret scan.
- TLS mode is the recommended default for security-focused testing.
- Use project-scoped Compose names to avoid cross-environment state leakage.
- Rotate credentials/tokens after `--volumes` resets or any suspected disclosure.
