---
title: Overview
description: What local.env is for, how the workflow fits together, and what it is not for.
---

local.env connects GitHub pull-request readiness with a local CLI so a team's
**local-development** environment contract can change alongside its code.

## What it is for

- Keeping declared local environment keys synchronized with the repository
  schema committed in Git.
- Making new local requirements visible on pull requests before merge.
- Letting each developer resolve missing requirements on their own machine
  and sync only a managed block into a local dotenv target such as
  `.env.local`.
- Running a self-hosted coordination service with a metadata-only dashboard
  for repository readiness, device access, and audit events.

## What it is not for

local.env is **not** a production, staging, CI, or general-purpose credential
manager. Do not use it as a password manager or as the system of record for
production secrets.

## How the workflow fits together

1. **Repository contract** — The team commits a `localenv.yaml` contract and
   schema files that declare which local keys exist.
2. **Pull-request readiness** — GitHub checks report whether an open PR's
   local requirements are ready before merge.
3. **Local resolution** — Developers use the CLI on their own machines to
   create or update encrypted values for missing requirements.
4. **Safe sync** — The CLI writes only a marker-bounded managed block in the
   configured target file and leaves unrelated local configuration alone.

The dashboard shows repository, device, and audit **metadata only**. It never
accepts or displays managed secret values.

## Security boundary in brief

- The CLI generates per-repository encryption keys and encrypts values locally
  before upload.
- The server stores ciphertext and age-wrapped repository keys for authorized
  devices.
- Device approval requires an already-authorized device to re-wrap the
  repository key locally.

Read the full [security model](../security/security-model/) and
[threat model](../security/threat-model-and-limitations/) before evaluating
the product for your team.

## Next step

Choose a journey from the [documentation home](../):

- [Self-host an instance](../self-host/prerequisites/)
- [Join an existing instance](../join-an-instance/prerequisites/)
