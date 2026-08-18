---
title: Troubleshooting
description: Common self-hosted and CLI issues with safe diagnostic steps.
---

## Goal

Resolve common operational problems without exposing secrets in logs or
support tickets.

## Instance not ready

| Symptom | Check |
| --- | --- |
| `/readyz` returns `503` | Complete `/setup`, verify migrations, confirm encrypted GitHub App credentials exist |
| Setup unavailable | Confirm all three bootstrap OAuth/encryption env vars are set |
| Webhook failures | Verify public URL, TLS, and App installation on the repository |

## CLI login or sync failures

| Symptom | Check |
| --- | --- |
| Login loop fails | Confirm instance URL matches `LOCALENV_PUBLIC_URL` exactly |
| Snapshot denied | Verify GitHub write access and active device approval |
| Decryption failure | Run `localenv doctor`; tampered ciphertext fails authenticated decryption |
| Doctor FAIL target mode `0600` | Run `localenv import FILE` or `localenv sync`. Editors often create `.env` files as `0644`; the CLI tightens the declared target. |
| Pending access | An authorized device must approve the request code |

## Safe diagnostics

```bash
localenv doctor
localenv status
curl --fail https://example.localenv.test/healthz
curl --fail https://example.localenv.test/readyz
```

Share command output that includes only metadata, never managed values, OAuth
secrets, session tokens, or private keys.

## Dashboard access denied

Dashboard sessions require write, maintain, or admin collaborator access to
every configured repository. Read-only collaborators cannot access global
metadata views.

## Next step

Review the [security model](../security/security-model/) if a failure might
involve authorization or ciphertext integrity.
