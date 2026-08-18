---
name: localenv
description: >
  Use local.env for developer-side local development environment workflows in an
  existing team or repository. Use for joining an existing local.env instance,
  logging in, repository onboarding, resolving pull-request environment
  requirements, syncing local dotenv targets, inspecting diffs, importing or
  setting developer values, running commands with managed values, diagnostics,
  device authorization, and repository-key rotation. Do not use this skill to
  deploy, create, upgrade, back up, restore, migrate, or administer the
  self-hosted local.env server instance; use localenv-admin for those tasks.
---

# local.env developer workflows

local.env keeps local-development environment requirements synchronized with the
code changes that introduce them. Use the `localenv` CLI as the execution
interface and source of truth.

Read `references/security.md` before any workflow that can touch secret values.
Use `references/workflows.md` to choose the safest command sequence.

## Routing boundary

This skill is for developers working with repositories and local machines.

Use this skill for:

- joining an existing local.env instance,
- logging in and checking account/repository/device state,
- adding or validating `localenv.yaml`,
- initializing an authorized repository,
- resolving PR requirements,
- setting or importing local-development values,
- syncing or diffing managed local targets,
- running a process with managed values without writing them to disk,
- diagnosing local developer setup,
- approving/revoking developer devices and rotating a repository key.

Do not use this skill for server deployment, `/setup`, GitHub OAuth/App
bootstrap configuration, TLS, persistent server storage, backups, restores,
upgrades, or migrations. Route those tasks to `localenv-admin`.

## First inspection

Before changing anything:

1. Check for `localenv.yaml` in the repository.
2. Inspect declared schema paths such as `.env.example`; key names are safe to
   reason about, but do not inspect managed target values.
3. Check that the CLI exists with `command -v localenv`.
4. If installed, prefer `localenv status` and `localenv doctor` for state and
   diagnostics.
5. If a command or flag is uncertain, run `localenv --help` or the relevant
   subcommand help. Never invent CLI flags.

## Safe operating order

Prefer this sequence whenever possible:

1. inspect metadata,
2. run read-only diagnostics,
3. dry-run or diff,
4. explain the intended change,
5. perform the mutation.

For synchronization, prefer:

```bash
localenv status
localenv sync --dry-run
localenv diff
localenv sync
```

Do not manually copy managed values between dotenv files when local.env can do
the operation.

## Common tasks

### Join an existing instance

Use the instance URL provided by the organization:

```bash
localenv login https://env.example.com
localenv status
localenv doctor
```

Do not guess an organization instance URL.

### Configure or initialize a repository

A repository opts in through a committed `localenv.yaml`, typically mapping a
schema file to a developer-local target:

```yaml
version: 1

files:
  - schema: .env.example
    target: .env.local
```

Inspect the repository structure before proposing mappings. Never invent schema
or target paths without evidence from the repository.

Once configuration is correct, an authorized developer can initialize the
repository:

```bash
localenv repo init
```

### Resolve requirements introduced by a pull request

When the user identifies a PR:

```bash
localenv resolve --pr <number>
```

Let the interactive CLI collect secret values. Do not ask the user to paste
those values into chat and do not pass them as command-line arguments.

For a single PR-scoped key, verify current CLI syntax with help before using
`localenv set`.

### Import an existing local baseline

Use the CLI rather than reading the dotenv target yourself:

```bash
localenv import <file>
```

The agent must not inspect or echo the file contents before or after import.

### Sync after pulling code changes

Start with:

```bash
localenv sync --dry-run
localenv diff
```

Then, when the intended changes are understood:

```bash
localenv sync
```

### Run without writing managed values to disk

When appropriate:

```bash
localenv run -- <command>
```

Example:

```bash
localenv run -- npm run dev
```

Do not run a child command that intentionally dumps its environment.

### Diagnose a developer setup

Start read-only:

```bash
localenv doctor
localenv status
```

Use their output to investigate repository configuration, ignored targets,
permissions, authentication, or device state. Do not fall back to printing
secret-bearing files.

### Device access and repository-key rotation

Inspect current device state with:

```bash
localenv devices
```

Verify current CLI help before approving or revoking a device. After a device
is revoked, repository-key rotation may be appropriate from an active authorized
device:

```bash
localenv keys rotate
```

Treat revocation and key rotation as consequential operations: explain the
impact before executing them.

## Product boundary

local.env is for local development. It is not a production secret manager, CI
secret store, staging credential store, deployment vault, password manager, or
browser-based secret editor.
