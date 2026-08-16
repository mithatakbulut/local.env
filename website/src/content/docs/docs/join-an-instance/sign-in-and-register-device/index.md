---
title: Sign in and register a device
description: Authenticate with the instance and create a device identity.
---

## Goal

Sign in to your team's instance and register an age device identity used for
repository key wrapping.

## Preconditions

- Installed CLI from [install the CLI](../install-the-cli/).
- Browser available for the OAuth loopback handoff.

## Steps

1. Start login against your instance URL:

```bash
localenv login https://example.localenv.test
```

2. Complete GitHub sign-in in the browser. The CLI stores an opaque session
   in your operating-system credential store by default.

3. Confirm identity metadata:

```bash
localenv status
```

First login also generates a device identity stored locally. Only public
recipient metadata is sent to the server.

## Headless alternative

For machines without a usable keychain, pass an explicit credential file path
documented in your operator runbook. The file must be mode `0600`.

## Expected result

- `localenv status` shows your GitHub user, instance, and device fingerprint.
- No session token or private device key appears in command output.

## Verify

```bash
localenv status
```

Confirm the instance URL, repository detection, and device fingerprint match
what you expect before initializing a repository.

## Next step

[Initialize a repository →](../initialize-a-repository/)
