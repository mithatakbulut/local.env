---
title: Install the CLI
description: Install the localenv CLI on your development machine.
---

## Goal

Install a verified `localenv` CLI binary for your operating system.

## Preconditions

- Completed [join prerequisites](../prerequisites/).

## macOS and Linux

Download a release archive from your organization's approved release channel.
Verify checksums and Sigstore bundles before installing the binary to your
`PATH`.

Example install shape only:

```bash
chmod +x localenv
sudo install -m 0755 localenv /usr/local/bin/localenv
localenv --version
```

## Verify installation

```bash
localenv --version
```

The command should print a non-empty version string from a verified release.

## Expected result

The `localenv` command is available in your shell and matches the server
version your operator recommends.

## Next step

[Sign in and register a device →](../sign-in-and-register-device/)
