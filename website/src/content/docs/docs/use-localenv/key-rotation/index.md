---
title: Key rotation
description: Rotate repository encryption keys after device revocation or policy events.
---

## Goal

Move the repository to a new key epoch so revoked devices cannot decrypt
future ciphertext.

## Preconditions

- At least one active authorized device remains.
- Any revoked devices should already be removed with
  [device approval and revocation](../device-approval-and-revocation/).

## Steps

1. From an active authorized device in the repository checkout:

```bash
localenv keys rotate
```

2. The CLI decrypts the current snapshot locally, generates epoch N+1,
   re-encrypts each current version locally, and wraps the new repository key
   only to remaining active devices.

3. Other active devices run `localenv sync` to pick up epoch N+1 ciphertext.

## Expected result

- Revoked devices cannot decrypt epoch N+1 snapshots even if they retained
  older epoch material.
- Active devices continue to sync normally after rotation completes.

## Verify

Attempt `localenv sync` from a revoked device credential store in a controlled
test environment. Expect denial without value disclosure.

## Next step

[Backup, restore, and upgrades →](../../operate/backup-restore-and-upgrades/)
