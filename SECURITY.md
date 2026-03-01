# Security Policy

## Supported Versions

This repository follows a direct dependency policy of **N (latest major) or N-1**.

| Version | Supported |
| --- | --- |
| main branch | Yes |
| Older release branches | No |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Include reproduction details, impact, and any proof-of-concept.

Do not open public issues for unpatched vulnerabilities.

## Security Response Targets

- Initial triage: within 24 hours
- Severity confirmation and remediation plan: within 72 hours
- Critical fixes: target patch within 7 days

## Baseline Security Controls

- Daily/PR vulnerability scanning through OSV and advisory audit workflows
- PR dependency delta checks with `dependency-review-action`
- Automated dependency updates via Dependabot
- N/N-1 dependency drift enforcement via `scripts/check-n-minus-one.mjs`
