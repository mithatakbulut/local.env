---
title: Security model
description: How local.env protects local-development values and what the server stores.
---

## Scope

local.env synchronizes **local-development** environment values. It is not for
production, staging, CI, or general-purpose credential storage.

## Client-side encryption

- The CLI generates a random per-repository encryption key (REK).
- Managed values use XChaCha20-Poly1305 with random nonces.
- Associated data binds ciphertext to instance, repository, file, key name,
  scope, version, and key epoch.
- Values encrypt and decrypt only on developer devices.

## Server storage

The server stores:

- Ciphertext envelopes and authenticated metadata
- Device-specific age-wrapped repository keys
- Repository, PR, device, and audit metadata

The server never stores:

- Managed secret plaintext
- Plaintext repository encryption keys
- Device private identities
- Persisted OAuth access tokens from dashboard login

## Authorization

- GitHub repository write access is checked before snapshots or mutations.
- Device approval requires an already-authorized device to re-wrap the REK
  locally.
- Revocation removes future access; rotate keys afterward.

## Local file safety

`localenv sync` writes marker-bounded managed blocks atomically with mode
`0600` and preserves unrelated content. `localenv run -- …` avoids writing a
managed plaintext dotenv file entirely.

## Logging

Server request logs contain request ID, method, status, and latency only.

## Next step

[Threat model and limitations →](../threat-model-and-limitations/)
