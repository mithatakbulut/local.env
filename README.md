# local.env

Your code changed. Your local env should too.

`local.env` is a self-hosted GitHub App and CLI for keeping a team's local
development environment variables synchronized with its codebase. It is not a
production, staging, CI, or general-purpose secret manager.

## P0 development server

The initial operational foundation provides the server process, a persistent
SQLite database, and health endpoints. GitHub App setup arrives in P1.

```bash
LOCALENV_PUBLIC_URL=http://localhost:8080 \
  go run ./cmd/localenv-server
```

In a second terminal:

```bash
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/readyz
```

`LOCALENV_PUBLIC_URL` is required and must be an absolute HTTP(S) URL. The
server accepts the following optional non-secret settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOCALENV_DATA_DIR` | `/data` | Persistent SQLite directory |
| `LOCALENV_LISTEN_ADDR` | `:8080` | HTTP listener address |
| `LOCALENV_DISPLAY_NAME` | `local.env` | Future dashboard branding |
| `LOCALENV_LOGO_URL` | unset | Future dashboard branding |
| `LOCALENV_FAVICON_URL` | unset | Future dashboard branding |

`/healthz` confirms that the process is alive. `/readyz` confirms SQLite is
readable and every compiled migration is applied. The GitHub App configuration
readiness condition is introduced together with the setup flow in P1.

## Container

Build and run with a named persistent volume:

```bash
docker build -f deploy/docker/Dockerfile -t localenv:dev .
docker volume create localenv-data
docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://env.acme.com \
  localenv:dev
curl --fail http://localhost:8080/healthz
curl --fail http://localhost:8080/readyz
```

For Compose, set `LOCALENV_PUBLIC_URL` in your shell or `.env` file, then run:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

The container keeps `/data` at `0700` and its SQLite database at `0600`.
Back up the data directory before any future upgrade. The P10 backup/restore
command will provide the supported online backup workflow.

## Development checks

```bash
go vet ./...
go test ./...
go build ./cmd/localenv ./cmd/localenv-server
```
