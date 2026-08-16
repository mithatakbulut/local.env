---
title: Runtime mode
description: Inject managed values into a child process without writing a managed dotenv file.
---

## Goal

Run a development command with managed environment values in memory when you
do not want a plaintext managed dotenv file on disk.

## Preconditions

- Active device access and a valid repository contract.
- Understanding that child programs may still write their own files.

## Usage

```bash
localenv run -- npm run dev
```

For an open pull request snapshot:

```bash
localenv run --pr 42 -- npm test
```

## Expected result

- The CLI downloads ciphertext, decrypts in its own memory, and starts the
  child with managed keys in the environment.
- No configured managed target such as `.env.local` is created or updated.

## Verify

Confirm no managed target file was modified:

```bash
localenv doctor
```

Configure child tools that might write env files according to your team's
policy.

## Next step

[Device approval and revocation →](../device-approval-and-revocation/)
