# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting form for this repository.
Do not open a public issue for a suspected vulnerability and do not include
managed values, repository encryption keys, session tokens, OAuth tokens, or
GitHub App credentials in a report.

If private reporting is unavailable, contact the maintainers through the
repository's listed security contact and share only the minimum reproduction
metadata needed to establish impact.

## Supported versions

Only the latest v1 release receives security fixes. Self-hosted operators
should back up `/data`, upgrade to the latest release, and verify `/readyz`.

## Security boundaries

Managed secret values and plaintext repository encryption keys are handled
only by the CLI. The server stores ciphertext, public device recipients, and
per-device wrapped repository keys. A compromised developer machine or a
developer who already synced a value is outside that boundary; see
[`docs/security-model.md`](docs/security-model.md) for details.
