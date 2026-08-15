# Installation and deployment

Build the release binaries from a verified tag, or use a published container
digest. Verify the published checksum and signature bundle before use.

```bash
docker volume create localenv-data
docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://env.acme.com \
  ghcr.io/localenv/localenv:VERSION
```

Terminate TLS at the server or a reverse proxy. Keep `/data` persistent and
restricted (`0700`); the server enforces `0600` for SQLite and credential
files. Configure GitHub OAuth/bootstrap credentials outside `/data`, then
visit `/setup`. See the root README for the required variables, backup,
restore, and migration procedure.

The dashboard has no plaintext secret editor. Sign in at `/login` with a
GitHub account belonging to the configured organization to view repository,
device, and metadata-only audit state.
