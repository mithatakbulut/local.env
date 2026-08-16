---
title: Verify your instance
description: Confirm a fresh self-hosted instance is healthy, ready, and metadata-only.
---

## Goal

Verify that your instance is operationally ready for developers to join.

## Preconditions

- Completed the self-hosting steps through
  [configure instance branding](../configure-instance-branding/).

## Verification checklist

| Check | Command or action | Expected |
| --- | --- | --- |
| Process health | `curl --fail https://example.localenv.test/healthz` | `ok` |
| Readiness | `curl --fail https://example.localenv.test/readyz` | `ready` |
| Setup complete | Visit `/setup` while configured | Redirects or shows completed state |
| Dashboard access | Visit `/login` with a repository writer | Metadata-only repository list |
| No secret UI | Browse repository and PR views | No value fields or secret editors |
| Persistent data | Inspect `/data` permissions | Directory `0700`, SQLite `0600` |

## Expected result

Administrators can sign in, see repository readiness metadata, and hand
developers the instance URL for CLI login. The dashboard never exposes managed
secret plaintext or plaintext repository encryption keys.

## Verify

Create a backup before inviting developers:

```bash
docker exec localenv localenv-server backup \
  --output /data/backups/localenv-example-backup.tar.gz
```

Store the archive as securely as the `/data` volume. It contains ciphertext
and metadata, not managed secret plaintext.

## Next step

Share the instance URL with developers and point them to
[join-an-instance prerequisites](../../join-an-instance/prerequisites/).
