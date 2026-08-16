---
title: Verify your first sync
description: Confirm your device, files, and workflow are correct after the first sync.
---

## Goal

Prove your first successful sync preserved local-only content and stayed
within the metadata-only server boundary.

## Preconditions

- Completed [sync safely](../sync-safely/).

## Verification checklist

| Check | Action | Expected |
| --- | --- | --- |
| Managed block | Inspect target file | Only declared keys inside markers |
| Local-only vars | Compare before/after | Unrelated keys unchanged |
| File mode | `stat` the target | Mode `0600` |
| CLI output | Re-run `localenv diff` | Key names only, no values |
| Dashboard | Visit repository metadata | Readiness counts without values |
| Doctor | `localenv doctor` | No blocking errors |

## Expected result

You can repeat `localenv sync` after merges and trust that only managed keys
inside the marker block change.

## Daily workflow

For routine work after your first sync, see
[everyday CLI workflows](../../use-localenv/everyday-cli-workflows/).

## Next step

Read [everyday CLI workflows →](../../use-localenv/everyday-cli-workflows/)
