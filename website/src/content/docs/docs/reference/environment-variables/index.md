---
title: Environment variables
description: Non-secret server configuration variables for local.env.
---

## Required

| Variable | Purpose |
| --- | --- |
| `LOCALENV_PUBLIC_URL` | Absolute HTTPS origin for the instance |

## Server settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOCALENV_DATA_DIR` | `/data` | Persistent SQLite directory |
| `LOCALENV_LISTEN_ADDR` | `:8080` | HTTP listener address |
| `LOCALENV_DISPLAY_NAME` | `local.env` | Dashboard title and text mark |
| `LOCALENV_LOGO_URL` | unset | Optional HTTPS dashboard logo |
| `LOCALENV_FAVICON_URL` | unset | Optional HTTPS dashboard favicon |

## Bootstrap setup secrets

Set outside `/data` before first `/setup`:

| Variable | Purpose |
| --- | --- |
| `LOCALENV_GITHUB_OAUTH_CLIENT_ID` | Bootstrap OAuth App client ID |
| `LOCALENV_GITHUB_OAUTH_CLIENT_SECRET` | Bootstrap OAuth App client secret |
| `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY` | Base64-encoded 32-byte key for encrypting generated App credentials |

## Documentation placeholders

Examples in this site use `example.localenv.test` and
`EXAMPLE_VALUE_DO_NOT_USE`. Never copy example secrets into production
configuration.

## Next step

[GitHub App permissions →](../github-app-permissions/)
