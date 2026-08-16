---
title: Threat model and limitations
description: Known limits and threats local.env does not fully mitigate.
---

## Goal

Understand what local.env does **not** protect against so you can make accurate
operational decisions.

## Out of scope protections

local.env does **not** fully protect against:

- A compromised developer machine with access to decrypted values
- Values a removed teammate already learned while authorized
- A malicious modified CLI binary not verified by your release process
- An actively compromised server during device provisioning if operators ignore
  fingerprint verification

## Operational mitigations

- Compare device fingerprints carefully during approval.
- Deploy signed releases and verify checksums and Sigstore bundles.
- Revoke lost devices promptly and rotate repository keys afterward.
- Keep `/data` backups as sensitive as the ciphertext they contain.

## Dashboard and browser boundary

The dashboard exposes metadata only. It is not a secret editor and must not
display managed values or plaintext repository keys.

## Honest positioning

Avoid unreviewed marketing claims such as “zero knowledge” or “unbreakable.”
Prefer the precise statements in the [security model](../security-model/).

## Next step

[Security advisories →](../security-advisories/)
