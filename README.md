# local.env

Your code changed. Your local env should too.

`local.env` is a self-hosted GitHub App and CLI for keeping a team's local
development environment variables synchronized with its codebase. It is not a
production, staging, CI, or general-purpose secret manager.

## Development server

The server provides a persistent SQLite database, health endpoints, and the
GitHub App setup flow.

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
server accepts the following non-secret settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOCALENV_DATA_DIR` | `/data` | Persistent SQLite directory |
| `LOCALENV_LISTEN_ADDR` | `:8080` | HTTP listener address |
| `LOCALENV_DISPLAY_NAME` | `local.env` | Future dashboard branding |
| `LOCALENV_LOGO_URL` | unset | Future dashboard branding |
| `LOCALENV_FAVICON_URL` | unset | Future dashboard branding |

## GitHub App setup (P1)

Before a new instance can complete `/setup`, its administrator must register a
small, company-owned bootstrap GitHub OAuth App. Configure its callback URL as:

```text
https://your-localenv-domain/auth/github/callback
```

The OAuth App is used only to identify the setup administrator and list their
organizations (`read:org`). The setup wizard then creates the separate,
company-owned GitHub App that receives repository webhooks.

Set these deployment secrets outside the repository and persistent `/data`
volume:

| Variable | Purpose |
| --- | --- |
| `LOCALENV_GITHUB_OAUTH_CLIENT_ID` | Bootstrap OAuth App client ID |
| `LOCALENV_GITHUB_OAUTH_CLIENT_SECRET` | Bootstrap OAuth App client secret |
| `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY` | Base64-encoded, random 32-byte key for encrypting GitHub App credentials at rest |

The setup wizard is intentionally unavailable until all three are present.
After they are configured, visit `/setup`, sign in with GitHub, select the
organization, create the App, and install it into the repositories to
discover. The generated App requests only Contents/Pull requests read,
Checks/Issues write, and Metadata read; it never requests source-code write,
Actions, Administration, or Secrets permissions.

`/healthz` confirms that the process is alive. `/readyz` confirms SQLite is
readable, every compiled migration is applied, and the encrypted GitHub App
credentials and instance setup are present.

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

## CLI runtime mode

For a development command that should not require a managed plaintext dotenv
file, use runtime injection:

```bash
localenv run -- npm run dev
```

The CLI downloads and decrypts the selected repository snapshot in its own
memory, then starts the child command with the managed keys in its environment.
It does not create or update any configured `.env.local` target. Child programs
can still choose to write their own files, so configure them accordingly.

Use `localenv doctor` to check the instance, GitHub session, local repository
contract, target ignore/permission safety, device identity, and availability of
the repository encryption key. It is diagnostic only and does not modify local
dotenv targets.
