# Security policy

Security reports are taken seriously, especially because local.env handles encrypted local-development environment values and device access.

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected vulnerability.**

Use GitHub's private vulnerability-reporting flow for this repository when it is available. If private reporting is unavailable, contact the maintainer through the security contact listed on the repository profile and share only the minimum information needed to establish impact.

Do not include real managed values, repository encryption keys, device private identities, session tokens, OAuth tokens, GitHub App credentials, webhook secrets, or other live credentials in a report.

A useful report should include:

- the affected local.env version or commit;
- the affected component, such as CLI, server, dashboard, GitHub integration, storage, or release pipeline;
- prerequisites required to reproduce the issue;
- clear reproduction steps using non-secret placeholder data;
- the expected and observed security behavior;
- your assessment of impact and attack conditions;
- relevant logs or traces only after confirming that they contain no secrets.

If a proof of concept is necessary, use synthetic repositories, accounts, and values whenever possible.

## What should be reported privately

Examples include:

- server-side exposure or persistence of managed plaintext values;
- exposure of plaintext repository encryption keys or device private identities;
- authentication or authorization bypasses;
- unauthorized repository or device access;
- cryptographic misuse that could permit tampering, decryption, replay, or cross-repository confusion;
- unsafe device approval, revocation, or repository-key rotation behavior;
- GitHub App permission or webhook handling flaws that materially expand access;
- path, file-permission, or write-boundary issues that could expose or overwrite unrelated local files;
- dashboard or API behavior that reveals data outside the documented metadata boundary;
- release or update mechanisms that could cause users to trust tampered artifacts.

Ordinary bugs without a security impact can be reported through the public bug-report form.

## Supported versions

Only the latest v1 release receives security fixes.

| Version | Supported |
| --- | --- |
| Latest v1 release | Yes |
| Older v1 releases | No |
| Development snapshots / untagged commits | Best effort only |

Self-hosted operators should keep backups, upgrade to the latest supported release, and verify instance readiness after upgrades.

## Security boundaries

local.env is for **local-development** environment values only. It is not a production, staging, CI, password-manager, or general-purpose credential system.

The intended boundary is:

- managed values encrypt and decrypt on developer devices;
- plaintext repository encryption keys stay on developer devices;
- the server stores ciphertext, public device recipients, device-wrapped repository keys, and metadata;
- the dashboard is metadata-only and does not accept or display managed plaintext values;
- GitHub receives repository contract and readiness information, not managed secret values.

See the [security model](website/src/content/docs/docs/security/security-model/index.md) and [threat model and limitations](website/src/content/docs/docs/security/threat-model-and-limitations/index.md) for the detailed design.

## Known limitations and out-of-scope guarantees

A compromised authorized developer machine can read values available to that device. Revoking a developer or device can prevent future access after key rotation, but it cannot make a person or machine forget values already received while authorized.

local.env also cannot protect users who intentionally run an untrusted or modified CLI binary. Release verification and endpoint security remain part of the operator's responsibility.

Do not describe the project as "unbreakable" or rely on an undefined "zero knowledge" claim. Security properties should be evaluated against the documented threat model.

## Disclosure and fixes

Please give the maintainer a reasonable opportunity to investigate and prepare a fix before publishing technical details that could put users at risk.

When a vulnerability is confirmed, the preferred remediation path is a coordinated fix and a supported release, followed by an advisory that explains affected versions, impact, mitigation, and upgrade guidance without exposing user secrets.

No bounty or monetary reward is promised unless a separate program explicitly states otherwise.
