---
title: Install the CLI
description: Install a verified localenv release on macOS or Linux.
---

## Goal

Install the `localenv` CLI without manually choosing a release archive.

## Preconditions

- Completed [join prerequisites](../prerequisites/).
- `curl`, `tar`, and a SHA-256 tool (`shasum` on macOS or `sha256sum` on Linux).
- [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) on `PATH` for release signature verification.

On macOS with Homebrew:

```bash
brew install cosign
```

## Install

The recommended installer detects macOS or Linux and amd64 or arm64, downloads
the matching GitHub release, verifies it, and installs the CLI to
`~/.local/bin/localenv` by default.

```bash
curl -fsSL https://www.local.env.best/install.sh | sh
```

The installer is served by the public documentation Worker at
`www.local.env.best`. The apex `local.env.best` hostname is reserved for the
local.env application instance and is not the installer origin.

The installer does not use `sudo` and does not modify your shell profile. If
`~/.local/bin` is not already on `PATH`, it tells you to add it.

Prefer to inspect the script first?

```bash
curl -fsSL https://www.local.env.best/install.sh -o install-localenv.sh
less install-localenv.sh
sh install-localenv.sh
```

## What the installer verifies

Before anything is placed on `PATH`, the installer:

1. resolves a stable `vX.Y.Z` GitHub release,
2. downloads `checksums.txt` and `checksums.txt.bundle`,
3. verifies the Sigstore bundle against the exact local.env GitHub Actions
   release workflow identity,
4. reads the expected SHA-256 for your platform archive from that verified
   manifest,
5. downloads the archive and verifies its SHA-256,
6. extracts only the `localenv` binary,
7. checks that the binary reports the expected release version, and
8. atomically installs it into the selected user-writable directory.

If any verification step fails, the installer exits without installing the
new binary.

## Choose a version or install directory

Install a specific release:

```bash
curl -fsSL https://www.local.env.best/install.sh | LOCALENV_VERSION=v1.2.3 sh
```

Choose another writable directory:

```bash
curl -fsSL https://www.local.env.best/install.sh | LOCALENV_INSTALL_DIR="$HOME/bin" sh
```

Self-update needs write access to the installed executable's directory. A
user-owned directory such as `~/.local/bin` lets later `Update now? [y/N]`
prompts replace the CLI without elevation. If your organization installs
`localenv` into a root-owned directory such as `/usr/local/bin`, use your
package-management process for upgrades instead.

## Verify installation

```bash
localenv --version
localenv version
```

`localenv --version` prints only the installed version. `localenv version`
also checks whether a newer GitHub release is available.

After the first install, interactive commands can offer:

```text
Update available: v1.2.3 → v1.2.4
Update now? [y/N]
```

You can also update explicitly:

```bash
localenv version --update
```

See the [CLI command reference](../../reference/cli-commands/) for update
behavior and how to disable update prompts.

## Expected result

The `localenv` command is available in your shell from a verified release and
can update itself later when installed in a user-writable directory.

## Next step

[Sign in and register a device →](../sign-in-and-register-device/)
