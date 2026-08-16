---
title: Security advisories
description: How local.env publishes security advisories for the public site and releases.
---

## Goal

Know where to read and report security issues affecting local.env releases.

## Reporting vulnerabilities

Report suspected vulnerabilities through the repository
[security policy](https://github.com/mithatakbulut/local.env/security/policy).
Do not open public issues for undisclosed exploit details.

## Published advisories

Security advisories appear on the [blog](/blog/) after coordinated review.
Advisories include affected versions, impact, mitigation steps, and fixed
versions when available.

The blog is reserved for an active, coordinated advisory; it is not a
standing “no known issues” announcement. Check the repository security policy
and the published-advisory list when assessing the current status.

## Our publication process

Before publication, maintainers confirm the affected release range, impact,
and practical mitigation. The advisory then names the first fixed version when
one exists. It also makes the security boundary explicit: local.env does not
claim to protect a compromised developer machine, values that were already
synced locally, or a malicious modified CLI.

Reporters should share only the information needed to establish impact. Do not
attach managed values, repository encryption keys, session tokens, OAuth
tokens, GitHub App credentials, or unredacted customer data.

## What advisories exclude

Public advisories never publish exploit credentials, unredacted customer
incident details, managed secret values, or reproduction steps that disclose
secrets.

## Next step

Return to the [CLI commands reference](../../reference/cli-commands/) or the
[documentation home](../../).
