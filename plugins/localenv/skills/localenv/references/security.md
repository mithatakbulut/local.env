# Security rules for developer agents

These rules apply whenever an agent uses local.env on a developer machine or
inside a repository.

## Never expose managed plaintext values

Do not intentionally read, display, summarize, log, transform, or transmit
managed plaintext secrets.

Avoid commands and behaviors such as:

- `cat .env`, `cat .env.local`, or equivalent reads of managed targets,
- `grep`, `sed`, `awk`, editors, or scripts used to reveal managed values,
- `printenv`, `env`, shell tracing (`set -x`), or debug tooling that dumps the
  child-process environment,
- echoing a secret into a shell pipeline,
- passing a secret as a CLI argument,
- placing secrets in chat, commits, PR descriptions, logs, screenshots, test
  fixtures, or generated documentation.

Key names, schema paths, target paths, readiness state, device metadata, and
other non-secret metadata are acceptable to inspect.

## Human secret entry stays outside chat

When local.env requires a value, prefer the interactive `localenv` CLI prompt.
The human enters the value directly into the terminal. Do not ask them to paste
it into the AI conversation.

Do not automate around the interactive prompt by scraping terminal input or
constructing plaintext temporary files.

## Prefer local.env inspection primitives

For state and changes, prefer:

```bash
localenv status
localenv doctor
localenv diff
localenv sync --dry-run
```

These are preferable to manually opening managed target files.

## Respect filesystem and Git boundaries

Managed target files must remain local and should be ignored by Git. Do not
stage, commit, upload, or attach them.

If diagnostics report an unsafe target permission or missing ignore rule, fix
the repository/filesystem condition without exposing the target contents.

## Scope boundary

local.env manages local-development values only.

Do not use it for:

- production secrets,
- CI/CD secrets,
- staging or deployment credentials,
- cloud-provider vault replacement,
- passwords or general-purpose credentials.

## Compromised device model

Revoking a device prevents future authorized access but cannot make a machine
forget plaintext that it previously received. Treat device revocation and
repository-key rotation as containment actions, not retroactive erasure.
