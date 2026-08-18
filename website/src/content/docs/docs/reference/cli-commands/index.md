---
title: CLI commands
description: Reference for common localenv CLI commands.
---

## Authentication and status

| Command | Purpose |
| --- | --- |
| `localenv login INSTANCE_URL` | Browser OAuth sign-in; stores opaque session locally |
| `localenv logout` | Revokes remote session |
| `localenv status` | Shows non-secret user, repository, and device metadata |
| `localenv doctor` | Read-only diagnostics; a present target must be Git-ignored and mode `0600` |

## Repository bootstrap

| Command | Purpose |
| --- | --- |
| `localenv repo init` | Creates local REK epoch 1 and activates repository |

## Secret updates (CLI only)

| Command | Purpose |
| --- | --- |
| `localenv resolve --pr NUMBER` | Interactive PR requirement resolution |
| `localenv set KEY --pr NUMBER` | Set one PR-scoped declared key |
| `localenv import FILE` | Import declared baseline keys from a dotenv file; set an existing target to mode `0600` before reading it |

Values encrypt locally before upload. Commands never print decrypted values in
normal output. `import` reports when it changes the target mode.

## Sync and runtime

| Command | Purpose |
| --- | --- |
| `localenv sync` | Write marker-bounded managed block to target; tighten an unchanged existing target to mode `0600` |
| `localenv sync --dry-run` | Preview key-name changes only |
| `localenv diff` | Show key-name change summary |
| `localenv run -- COMMAND` | Inject values into child process without target write |
| `localenv run --pr N -- COMMAND` | Same using PR-scoped snapshot |

## Devices and keys

| Command | Purpose |
| --- | --- |
| `localenv devices` | List device identity metadata |
| `localenv devices approve CODE` | Approve pending device access |
| `localenv devices revoke DEVICE_ID` | Revoke device access |
| `localenv keys rotate` | Rotate repository encryption epoch |

## Server operator command

| Command | Purpose |
| --- | --- |
| `localenv-server backup --output PATH` | Online backup archive (run inside container) |

## Next step

[Environment variables →](../environment-variables/)
