---
title: Device approval and revocation
description: Share repository access with another device using explicit approval.
---

## Goal

Allow a teammate's new device to decrypt repository keys only after an
authorized device explicitly approves the request.

## Preconditions

- At least one active device already holds the repository key.
- The requesting developer completed `localenv login` and attempted `sync`.

## Approve a pending device

1. The requesting developer runs `localenv sync` and receives a one-time
   approval code in the CLI.

2. An authorized developer lists devices and inspects metadata:

```bash
localenv devices
```

3. Approve after verifying fingerprint and identity:

```bash
localenv devices approve APPROVAL_CODE
```

The approving CLI re-wraps the repository key locally and uploads only the
new wrapped blob.

## Revoke a device

```bash
localenv devices revoke DEVICE_ID
```

Revocation removes future snapshot access for that device. Run
[key rotation](../key-rotation/) afterward so future ciphertext uses a new
epoch unavailable to the revoked device.

## Expected result

- Pending devices cannot decrypt before approval.
- Approved devices can sync immediately.
- Revoked devices cannot fetch new snapshots.

## Verify

The dashboard devices view shows active, pending, and revoked states with
public identity metadata only.

## Next step

[Key rotation →](../key-rotation/)
