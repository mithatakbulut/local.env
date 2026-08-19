# Installation and deployment

Use a published stable release. Each release publishes signed CLI/server archives
and a multi-platform Linux container image for amd64 and arm64.

For Docker deployments, pull the versioned image from GitHub Container Registry:

```bash
VERSION=v1.2.0
docker pull ghcr.io/mithatakbulut/local.env:${VERSION}

docker volume create localenv-data
docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://env.acme.com \
  ghcr.io/mithatakbulut/local.env:${VERSION}
```

Replace `v1.2.0` with a real published release tag. For a long-lived deployment,
prefer the immutable `ghcr.io/mithatakbulut/local.env@sha256:...` reference from
that release's `container-image-digest.txt` asset.

Terminate TLS at the server or a reverse proxy. Keep `/data` persistent and
restricted (`0700`); the server enforces `0600` for SQLite and credential
files. Configure GitHub OAuth/bootstrap credentials outside `/data`, then
visit `/setup`.

The dashboard has no plaintext secret editor. Sign in at `/login` with a
GitHub account belonging to the configured organization to view repository,
device, and metadata-only audit state.

The complete supported self-hosting path lives in the public documentation:
https://www.local.env.best/docs/self-host/prerequisites/
