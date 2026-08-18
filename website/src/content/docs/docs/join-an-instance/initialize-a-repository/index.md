---
title: Initialize a repository
description: Create a repository encryption key and activate local.env for a Git checkout.
---

## Goal

Run `localenv repo init` once for a repository so the CLI can encrypt and
sync values for that contract.

## Preconditions

- Signed in from [sign in and register a device](../sign-in-and-register-device/).
- Local Git checkout with a valid committed `localenv.yaml` and schema files.
- Current GitHub write access to the repository.

## Steps

1. Change to the repository root:

```bash
cd /path/to/your/checkout
```

2. Initialize the repository key locally:

```bash
localenv repo init
```

The CLI generates a random repository encryption key, wraps it for your device,
and sends only the wrapped blob to the server.

3. Confirm readiness metadata in the dashboard or with:

```bash
localenv status
```

## Expected result

- Epoch 1 repository key material exists server-side only as device-wrapped
  ciphertext.
- The repository appears in dashboard metadata views.
- No plaintext repository encryption key is transmitted or stored
  server-side.

## Verify

Run read-only diagnostics:

```bash
localenv doctor
```

Resolve contract and ignore warnings before syncing. A present target that is
not mode `0600` fails until `localenv import` or `localenv sync` tightens it.
`doctor` does not change files.

## Next step

[Resolve PR requirements →](../resolve-pr-requirements/)
