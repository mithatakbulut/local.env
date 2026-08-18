---
title: Join prerequisites
description: What developers need before connecting to a local.env instance.
---

## Goal

Confirm you have access to an existing local.env instance and a repository
that already declares a local environment contract.

## Preconditions

- An administrator gave you the instance URL, for example
  `https://example.localenv.test`.
- You have GitHub write access to at least one repository managed by that
  instance.
- You work on a machine where you can install the CLI and open a browser for
  first sign-in.

## Requirements checklist

| Requirement | Notes |
| --- | --- |
| Instance URL | HTTPS origin provided by your operator |
| GitHub account | Must have write access to the target repository |
| Local Git checkout | Repository contains `localenv.yaml` and declared schema files |
| CLI platform | macOS or Linux on amd64 or arm64 |
| Installer tools | `curl`, `tar`, and `shasum` or `sha256sum` |
| `cosign` | Required by the recommended installer and self-update for Sigstore verification |
| Secure credential storage | OS keychain preferred; optional explicit credential file for headless use |

## Placeholder convention

Documentation examples use:

- Instance URL: `https://example.localenv.test`
- Example managed value: `EXAMPLE_VALUE_DO_NOT_USE`

Never paste real managed values into tickets, screenshots, or documentation.

## Expected result

You know which instance to join and which repository you will initialize or
sync first.

## Verify

Ask your operator to confirm:

- `/readyz` returns `ready` on the instance.
- The target repository is installed on the company GitHub App.

For the recommended CLI installer, also confirm:

```bash
cosign version
```

## Next step

[Install the CLI →](../install-the-cli/)
