---
title: Create and install the GitHub App
description: Finish /setup by creating the company-owned GitHub App and installing it.
---

## Goal

Connect your instance to GitHub by creating the organization-owned App and
installing it on the repositories local.env should manage.

## Preconditions

- Bootstrap OAuth credentials configured in
  [configure GitHub OAuth](../configure-github-oauth/).
- Organization-owner access to approve App creation and installation.

## Steps

1. Visit `https://example.localenv.test/setup` and sign in with GitHub as an
   administrator.

2. Select the GitHub organization that will own the App.

3. Complete the manifest flow to create the company-owned GitHub App. The
   generated App requests read-only source access plus Checks, Issues, and
   limited Pull request write access for readiness comments. It never requests
   Contents write, Actions, Administration, or Secrets permissions.

4. Install the App on the repositories you want local.env to discover. Prefer
   **selected repositories** rather than all repositories unless your security
   review requires otherwise.

5. Confirm webhook delivery succeeds for a test `pull_request` event after
   installation.

## Expected result

- Encrypted GitHub App credentials are stored under `/data` with mode `0600`.
- `/readyz` reports `ready` once setup, migrations, and credentials are
  present.
- Repository discovery shows installed repositories in the dashboard metadata
  views.

## Verify

```bash
curl --fail https://example.localenv.test/readyz
```

Sign in at `https://example.localenv.test/login` with a GitHub account that
has write access to an installed repository and confirm the repository list
renders metadata only.

## Next step

[Configure instance branding →](../configure-instance-branding/)
