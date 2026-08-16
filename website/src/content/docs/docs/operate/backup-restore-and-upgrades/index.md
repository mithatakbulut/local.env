---
title: Backup, restore, and upgrades
description: Back up instance state, restore to a fresh volume, and upgrade safely.
---

## Goal

Protect instance state with online backups and restore or upgrade without
mixing data from two instances.

## Backup

Create a backup while the server runs with the same release version currently
serving the instance:

```bash
docker exec localenv localenv-server backup \
  --output /data/backups/localenv-example-backup.tar.gz
```

The archive contains an online SQLite snapshot and credential files when
present. It holds ciphertext and metadata—not managed secret plaintext or a
plaintext repository encryption key.

## Restore

1. Stop the server.
2. Create a fresh empty `/data` volume with mode `0700`.
3. Extract the archive into the fresh volume.
4. Restore the exact deployment configuration, especially
   `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY`.
5. Start the same local.env version and verify readiness before upgrading.

Never restore into a live data directory or combine files from two instances.

## Upgrade

1. Back up using the currently running release.
2. Deploy the new container image.
3. Startup applies forward migrations only and refuses a database schema newer
   than the binary supports.

## Verify

```bash
curl --fail https://example.localenv.test/readyz
```

Active devices should decrypt restored ciphertext because private age
identities remain on developer machines.

## Next step

[Troubleshooting →](../troubleshooting/)
