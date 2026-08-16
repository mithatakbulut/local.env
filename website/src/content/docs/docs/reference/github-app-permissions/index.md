---
title: GitHub App permissions
description: Required GitHub App permissions and the temporary PR comment exception.
---

## Goal

Understand which GitHub permissions the company-owned App requests and which
permissions remain forbidden in v1.

## Default production manifest

The generated App requests:

| Permission | Access | Purpose |
| --- | --- | --- |
| Contents | Read | Read `localenv.yaml`, schemas, and repository metadata |
| Metadata | Read | Repository discovery |
| Checks | Write | Publish `local.env / readiness` check runs |
| Issues | Write | Marker-bounded PR readiness comments |
| Pull requests | Read | Inspect open PR metadata |

## Temporary exception

Some installations also require **Pull requests: write** so marker-bounded PR
comments can be created and updated while
[`github/rest-api-description#6994`](https://github.com/github/rest-api-description/issues/6994)
is unresolved. If you enable it:

- Scope the installation to **selected repositories**.
- Do not add Contents write.
- Record the explicit security decision in your operator runbook.

## Forbidden permissions

Never grant:

- Contents write
- Actions
- Administration
- Secrets or dependency permissions beyond the v1 manifest

## Bootstrap OAuth App

The separate bootstrap OAuth App is used only during `/setup` for administrator
identity. It is not the repository integration App.

## Next step

Return to [verify your instance](../../self-host/verify-your-instance/) or
[join prerequisites](../../join-an-instance/prerequisites/).
