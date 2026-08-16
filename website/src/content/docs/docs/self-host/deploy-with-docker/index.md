---
title: Deploy with Docker
description: Run the local.env server container with a persistent data volume.
---

## Goal

Start a local.env server container with persistent storage and a configured
public URL.

## Preconditions

- Completed [self-host prerequisites](../prerequisites/).
- A published container image digest or a locally built image from a verified
  release tag.

## Steps

1. Create a named volume for persistent state:

```bash
docker volume create localenv-data
```

2. Start the container with your public URL and persistent `/data` mount:

```bash
docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://example.localenv.test \
  ghcr.io/localenv/localenv:VERSION
```

Replace `VERSION` with a verified release tag or digest from your release
process.

3. Confirm the process is alive:

```bash
curl --fail https://example.localenv.test/healthz
```

## Expected result

- `/healthz` returns `ok`.
- `/readyz` returns `503 not ready` until GitHub setup is complete.
- `/data` inside the container is mode `0700` and the SQLite file is `0600`.

## Verify

```bash
curl --fail https://example.localenv.test/healthz
curl --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://example.localenv.test/readyz
```

Expect `200` from `/healthz` and `503` from `/readyz` on a fresh instance.

## Next step

[Configure public URL and TLS →](../configure-public-url-and-tls/)
