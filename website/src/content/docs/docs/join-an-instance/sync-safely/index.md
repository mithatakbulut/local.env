---
title: Sync safely
description: Download ciphertext and write only the managed block to your local target file.
---

## Goal

Synchronize authorized baseline (or PR-scoped) values into your configured
local dotenv target without disturbing unrelated content.

## Preconditions

- Repository initialized and, when applicable, PR requirements resolved.
- Active device access to the repository key.

## Steps

1. Preview changes without writing:

```bash
localenv sync --dry-run
```

Output lists key names and change categories only, never decrypted values.

2. Apply the sync:

```bash
localenv sync
```

The CLI downloads ciphertext, decrypts in memory, and writes only the
marker-bounded managed block in the configured target such as `.env.local`.

3. Optionally inspect a diff summary:

```bash
localenv diff
```

## Expected result

- Unrelated variables outside the managed block remain unchanged.
- The target file is written atomically with Unix mode `0600`. An already
  up-to-date existing target is still tightened to `0600`.
- If the target is not ignored by Git, the CLI warns you.

## Verify

```bash
localenv doctor
```

Confirm target permissions, ignore status, and repository key availability.
Review the managed block and verify only expected key **names** changed.

## Next step

[Verify your first sync →](../verify-your-first-sync/)
