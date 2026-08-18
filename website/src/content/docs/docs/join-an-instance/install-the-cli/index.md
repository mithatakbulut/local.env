---
title: Install the CLI
description: Install and keep the localenv CLI up to date on your development machine.
---

## Goal

Install a verified `localenv` release and keep it up to date without replacing
an installed binary before verification succeeds.

## Preconditions

- Completed [join prerequisites](../prerequisites/).
- `cosign` is available on `PATH` if you want to use verified self-update.

## Supported platforms

Release archives are published for:

- macOS on arm64 and amd64
- Linux on arm64 and amd64

## First install

Download the release archive for your platform from the local.env GitHub
Releases page. Verify the published checksum and Sigstore bundle before placing
the binary on your `PATH`.

If you want `localenv` to update itself later, install it somewhere your user
can write to. For example:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 localenv "$HOME/.local/bin/localenv"
export PATH="$HOME/.local/bin:$PATH"
localenv --version
```

Add `$HOME/.local/bin` to your shell's `PATH` permanently if it is not already
there.

A system-wide install also works:

```bash
sudo install -m 0755 localenv /usr/local/bin/localenv
```

But a root-owned binary may not be replaceable by a normal user during
self-update. In that case, install the new release manually with the required
permissions or move the CLI to a user-writable directory.

## Check for updates

`--version` is intentionally script-friendly and prints only the installed
build version:

```bash
localenv --version
```

For a human-readable update check:

```bash
localenv version
```

Interactive commands also check for a newer release at most once every 24
hours. When one is available, the terminal can show:

```text
Update available: v1.1.3 → v1.2.0
Update now? [y/N]
```

Answering `n` or pressing Enter keeps the current version and suppresses that
release notice for 24 hours.

## Update explicitly

You can update without waiting for the prompt:

```bash
localenv version --update
```

Before replacing the current executable, localenv:

1. downloads `checksums.txt` and its Sigstore bundle,
2. verifies the bundle against the exact local.env GitHub Actions release
   workflow identity,
3. reads the expected SHA-256 for your platform archive from the verified
   manifest,
4. downloads the archive and verifies its digest, and
5. replaces the current executable only after every verification succeeds.

Automatic update requires `cosign` on `PATH`. If signature verification,
checksum verification, download, extraction, or executable replacement fails,
the installed CLI is left unchanged.

To disable background update checks and prompts while keeping explicit
`localenv version --update` available, set `LOCALENV_NO_UPDATE_NOTIFIER` to any
non-empty value.

## Verify installation

```bash
localenv --version
localenv version
```

The first command should print the installed release version. The second should
report whether it is current.

## Expected result

The `localenv` command is available in your shell, its release can be verified,
and supported installations can update through the CLI without bypassing
release signature or checksum verification.

## Next step

[Sign in and register a device →](../sign-in-and-register-device/)
