---
title: Resolve PR requirements
description: Satisfy missing local requirements on an open pull request from the CLI.
---

## Goal

Use the CLI to encrypt and upload values for keys marked missing on an open
pull request.

## Preconditions

- Initialized repository from
  [initialize a repository](../initialize-a-repository/).
- An open pull request that adds or changes declared local schema keys.
- GitHub readiness check reporting a missing requirement.

## Steps

1. Check out the pull request branch locally.

2. Resolve the missing key interactively:

```bash
localenv resolve --pr NUMBER
```

Replace `NUMBER` with the pull request number. The CLI prompts for a value,
masks terminal echo, encrypts locally, and uploads ciphertext only.

Alternatively set a single PR-scoped key:

```bash
localenv set EXAMPLE_KEY --pr NUMBER
```

Use `EXAMPLE_KEY` as a declared schema key name, not a real secret value.

3. Refresh GitHub and confirm the readiness check turns green when all
   requirements are satisfied.

## Expected result

- The server stores ciphertext for the PR-scoped value.
- GitHub readiness metadata names the key and CLI guidance, never the value.
- The dashboard PR requirement table shows ready/missing states without a
  value field.

## Verify

Open the pull request in GitHub and confirm:

- The `local.env / readiness` check succeeds.
- No secret value appears in comments, checks, or the dashboard.

## Next step

[Sync safely →](../sync-safely/)
