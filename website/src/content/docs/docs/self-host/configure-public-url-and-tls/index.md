---
title: Configure public URL and TLS
description: Set LOCALENV_PUBLIC_URL and terminate TLS for your instance.
---

## Goal

Ensure every browser, GitHub callback, and CLI request uses the same stable
HTTPS origin configured as `LOCALENV_PUBLIC_URL`.

## Preconditions

- A running container from [deploy with Docker](../deploy-with-docker/).
- DNS pointing your hostname to the container host or reverse proxy.

## Steps

1. Set `LOCALENV_PUBLIC_URL` to the exact HTTPS origin users will visit:

```bash
LOCALENV_PUBLIC_URL=https://example.localenv.test
```

2. Terminate TLS at the container or a reverse proxy in front of it. GitHub
   OAuth callbacks, webhook delivery, and CLI login all depend on this URL
   being reachable and stable.

3. Restart the container after changing the public URL so cookies, redirects,
   and GitHub callback URLs stay consistent.

## Expected result

- `curl --fail https://example.localenv.test/healthz` succeeds from outside
  your laptop.
- Browser navigation to `https://example.localenv.test/setup` loads without
  certificate warnings once OAuth credentials are configured.

## Verify

Confirm the value inside the running container matches the public URL:

```bash
docker exec localenv printenv LOCALENV_PUBLIC_URL
```

The printed value must exactly match the URL in your browser and GitHub App
settings.

## Next step

[Configure GitHub OAuth →](../configure-github-oauth/)
