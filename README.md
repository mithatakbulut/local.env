# local.env

Your code changed. Your local env should too.

`local.env` is a self-hosted GitHub App and CLI for keeping a team's local
development environment variables synchronized with its codebase. It is not a
production, staging, CI, or general-purpose secret manager.

See the [installation guide](docs/installation.md), [CLI reference](docs/cli.md),
and [security model](docs/security-model.md). The server-rendered dashboard at
`/login` is metadata-only: it shows repository readiness, public device
identity, and audit events, but never accepts or displays a secret value.

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

## Backup, restore, and upgrades

Create a consistent backup while the server is running with the same released
server version that currently serves the instance:

```bash
docker exec localenv localenv-server backup \
  --output /data/backups/localenv-2026-08-15.tar.gz
```

The archive contains an online SQLite snapshot (`localenv.db`) plus the
instance credential files when present. It contains ciphertext, never managed
secret plaintext or a plaintext repository key. Store the archive as securely
as the `/data` volume. The command refuses to overwrite an existing archive.

To restore, stop the server, create a fresh empty `/data` volume with mode
`0700`, extract the archive into it, and restore the exact deployment
configuration—especially `LOCALENV_GITHUB_APP_CREDENTIALS_ENCRYPTION_KEY`.
Then start the same local.env version and check readiness before upgrading:

```bash
docker stop localenv
tar -xzf localenv-2026-08-15.tar.gz -C /path/to/fresh-data
chmod 0700 /path/to/fresh-data
chmod 0600 /path/to/fresh-data/*
# start the container with /path/to/fresh-data mounted at /data
curl --fail https://env.acme.com/readyz
```

Existing active devices can decrypt the restored ciphertext because their
private age identities stay on their machines. Never restore into a live data
directory or combine files from two instances. Before an upgrade, make a
backup using the currently running release; startup applies only forward
migrations and refuses a database schema newer than the binary supports.

After removing a device, run `localenv keys rotate` from an active authorized
device. It decrypts the current repository snapshot locally, creates a new
REK epoch, re-encrypts the snapshot locally, and wraps the new REK only to
remaining active devices. A removed device cannot decrypt the new epoch, but
it cannot be made to forget values it previously received.

## Development checks

```bash
go vet ./...
go test ./...
go build ./cmd/localenv ./cmd/localenv-server
```

## Release verification

Tagged releases publish checksums, a Sigstore bundle, an SPDX SBOM, and the
container image digest. Verify a downloaded artifact with the release checksum
and its `cosign` bundle before deployment. CI also runs formatting, tests,
`go vet`, Go vulnerability scanning, and a high/critical container scan.

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
