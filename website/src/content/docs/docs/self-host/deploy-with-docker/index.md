---
title: Deploy with Docker
description: Run the local.env server container with a persistent data volume.
---

## Goal

Start a local.env server container from an official release image with
persistent storage.

## Preconditions

- Completed [self-host prerequisites](../prerequisites/).
- A published stable local.env release such as `v1.2.0`.
- Docker or another OCI-compatible container runtime.

Each stable release publishes a multi-platform Linux image to GitHub Container
Registry for `amd64` and `arm64` together with an immutable image digest in the
release assets.

## Steps

1. Choose the release you want to deploy:

```bash
VERSION=v1.2.0
```

Use a real published release tag from the local.env Releases page.

2. Pull the official image:

```bash
docker pull ghcr.io/mithatakbulut/local.env:${VERSION}
```

For a long-lived deployment, you can replace the tag with the immutable
`ghcr.io/mithatakbulut/local.env@sha256:...` reference recorded in that
release's `container-image-digest.txt` asset.

3. Create a named volume for persistent state:

```bash
docker volume create localenv-data
```

4. Start the container with your future public URL and persistent `/data`
mount:

```bash
docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://example.localenv.test \
  ghcr.io/mithatakbulut/local.env:${VERSION}
```

The bootstrap GitHub OAuth credentials are configured in a later step. A fresh
container can start without them, but it will not report ready until setup is
complete.

5. Confirm the local process is alive before putting a proxy or tunnel in
front of it:

```bash
curl --fail http://127.0.0.1:8080/healthz
```

## Expected result

- `/healthz` returns `ok`.
- `/readyz` returns `503 not ready` until GitHub setup is complete.
- `/data` inside the container is mode `0700` and the SQLite file is `0600`.

## Verify

```bash
curl --fail http://127.0.0.1:8080/healthz
curl --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  http://127.0.0.1:8080/readyz
```

Expect `200` from `/healthz` and `503` from `/readyz` on a fresh instance.

## Next step

[Configure public URL and TLS →](../configure-public-url-and-tls/)
