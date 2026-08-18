---
title: Everyday CLI workflows
description: Routine local.env commands for day-to-day local development.
---

## Goal

Use the CLI for the common loop: check status, resolve PR changes, sync, and
inspect metadata safely.

## Typical loop

1. **Start work on a branch**

```bash
git switch feature/add-local-key
localenv status
```

2. **Resolve missing PR requirements**

```bash
localenv resolve --pr 42
```

3. **Sync after merge**

```bash
git switch main
git pull
localenv sync
```

4. **Inspect without writing**

```bash
localenv sync --dry-run
localenv diff
```

## Baseline updates

Import declared baseline keys from a dotenv file:

```bash
localenv import path/to/example.env
```

The CLI encrypts locally and uploads ciphertext only. If the declared target
already exists, `import` sets it to mode `0600` before reading it and reports
when the mode changes. Use files containing placeholder values such as
`EXAMPLE_VALUE_DO_NOT_USE` in documentation, not real secrets.

## Rules to remember

- Commands print key names and categories, not decrypted values.
- The dashboard is metadata-only; secret edits happen in the CLI.
- `localenv doctor` is read-only and safe to run any time. A present target
  that is not mode `0600` fails until `import` or `sync` tightens it.

## Next step

[Runtime mode →](../runtime-mode/)
