---
title: Configure GitHub OAuth
description: Create the bootstrap OAuth App and deployment secrets for first-run setup.
---

## Goal

Provide the bootstrap GitHub OAuth credentials and credentials-encryption key
required before `/setup` becomes available.

## Preconditions

- A stable HTTPS public URL from
  [configure public URL and TLS](../configure-public-url-and-tls/).
- Permission to create a GitHub OAuth App for bootstrap administrator sign-in.

## Steps

1. Create a bootstrap GitHub OAuth App owned by your organization or an
   approved bootstrap account.

2. Set the OAuth callback URL to:

```text
https://example.localenv.test/auth/github/callback
```

3. Generate a random 32-byte key and base64-encode it for
   `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY`. Store it outside the
   persistent `/data` volume with your other deployment secrets.

4. Configure these environment variables on the container:

| Variable | Purpose |
| --- | --- |
| `LOCALENV_GITHUB_OAUTH_CLIENT_ID` | Bootstrap OAuth App client ID |
| `LOCALENV_GITHUB_OAUTH_CLIENT_SECRET` | Bootstrap OAuth App client secret |
| `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY` | Encrypts generated GitHub App credentials at rest |

Example shape only — use values from your secret manager, not from docs:

```bash
--env LOCALENV_GITHUB_OAUTH_CLIENT_ID=example-client-id \
--env LOCALENV_GITHUB_OAUTH_CLIENT_SECRET=EXAMPLE_OAUTH_CLIENT_SECRET_DO_NOT_USE \
--env LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY=EXAMPLE_BASE64_32_BYTE_KEY_DO_NOT_USE
```

5. Restart the container and confirm `/setup` is reachable.

## Expected result

- `/setup` loads instead of reporting missing bootstrap configuration.
- The bootstrap OAuth App requests only the scopes needed for administrator
  identity and organization discovery during setup.

## Verify

Visit `https://example.localenv.test/setup` and confirm the setup flow offers
GitHub sign-in rather than a configuration error.

## Next step

[Create and install the GitHub App →](../create-and-install-github-app/)
