---
title: Self-host prerequisites
description: What you need before deploying a local.env instance.
---

## Goal

Confirm you have the accounts, infrastructure, and secrets required to deploy
a new local.env instance.

## Preconditions

- You can create or administer a GitHub organization for your team.
- You can run a container (Docker or compatible runtime) with a persistent
  volume mounted at `/data`.
- You can publish an HTTPS URL that reaches the container (direct TLS or a
  reverse proxy).

## Requirements checklist

| Requirement | Notes |
| --- | --- |
| Public HTTPS URL | Example placeholder: `https://example.localenv.test` |
| Persistent `/data` volume | Mode `0700`; SQLite and credential files use `0600` |
| Bootstrap GitHub OAuth App | Used only for first-run administrator identity |
| GitHub App credentials encryption key | Random 32-byte key, base64-encoded, stored outside `/data` |
| Organization owner access | Needed to create and install the company-owned GitHub App |

## Placeholder convention

Documentation examples use obviously non-secret placeholders:

- Hostname: `example.localenv.test`
- Example managed value: `EXAMPLE_VALUE_DO_NOT_USE`
- OAuth client secret label: `EXAMPLE_OAUTH_CLIENT_SECRET_DO_NOT_USE`

Never commit real OAuth secrets, webhook secrets, encryption keys, or managed
environment values to Git.

## Expected result

You have a hostname, container runtime, and GitHub organization ready for the
deployment steps that follow.

## Verify

- You can create a GitHub OAuth App in the target organization or a dedicated
  bootstrap account approved by your security team.
- Your hosting plan includes TLS termination and a stable public URL.

## Next step

[Deploy with Docker →](../deploy-with-docker/)
