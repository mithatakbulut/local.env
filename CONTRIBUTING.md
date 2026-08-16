# Contributing to local.env

Thanks for taking the time to contribute.

`local.env` is intentionally narrow: it coordinates **local-development** environment values with the code changes that require them. It is not a production, staging, CI, cloud-secret-manager, password-manager, or browser-based plaintext secret editor.

For material product or security changes, open an issue before starting a large implementation so the direction can be discussed first. Small bug fixes, documentation improvements, tests, and focused maintenance changes can go straight to a pull request.

## Before you start

Please keep these project constraints intact:

- Managed secret plaintext and plaintext repository encryption keys must never be persisted or logged server-side.
- Encryption and decryption of managed values happen on developer devices.
- GitHub integration should keep permissions minimal and must not require source-code write access.
- Managed dotenv updates must stay marker-bounded and preserve unrelated local configuration.
- The dashboard is metadata-only. It must not become a secret editor or display managed plaintext values.
- Avoid adding infrastructure or abstractions that are not required by the current product scope.

If your proposal changes one of those boundaries, explain why in an issue before opening a pull request.

## Repository layout

The main areas of the repository are:

- `cmd/localenv/` — CLI entry point.
- `cmd/localenv-server/` — self-hosted server entry point and operational commands.
- `internal/cli/` — CLI behavior and local workflows.
- `internal/server/` — HTTP API, authentication, setup, and dashboard integration.
- `internal/cryptokit/` — client-side cryptographic primitives and repository-key handling.
- `internal/repository/` — `localenv.yaml` contract parsing and repository detection.
- `internal/pranalysis/` — pull-request environment requirement analysis.
- `internal/store/sqlite/` — persistent server state.
- `frontend/` — the metadata-only dashboard UI.
- `website/` — public website, documentation, and blog.
- `migrations/` — SQLite schema migrations.

## Development setup

### Go

The Go module contains the CLI and server.

Run the core checks with:

```bash
gofmt -w $(find . -name '*.go' -not -path './vendor/*')
go vet ./...
go test ./...
go build ./cmd/localenv ./cmd/localenv-server
```

Before submitting, also run:

```bash
git diff --check
```

### Dashboard

The dashboard lives in `frontend/` and builds into the server's embedded UI assets.

```bash
cd frontend
npm ci
npm run check
npm run build
```

For local UI development:

```bash
npm run dev
```

### Website and documentation

The public website and documentation live in `website/`.

```bash
cd website
npm ci
npm run verify
```

For local documentation or website work:

```bash
npm run dev
```

## Testing expectations

Add or update focused tests whenever behavior changes.

A pull request should normally include the smallest relevant verification set plus any broader checks affected by the change. Examples:

- repository contract changes → repository parser tests;
- encryption or device-access changes → cryptographic and CLI tests;
- API or authorization changes → server tests;
- dashboard changes → TypeScript check and frontend build;
- website/docs changes → `npm run verify` in `website/`.

Do not weaken a test solely to make a change pass. If an existing invariant must change, explain that explicitly in the pull request.

## Security and secret handling

Never put real secrets in:

- source code;
- tests or fixtures;
- command arguments;
- screenshots;
- logs;
- issues or pull requests;
- documentation examples;
- stored snapshots.

Use clearly fake sentinel values such as `EXAMPLE_VALUE_DO_NOT_USE` when an example needs a value.

If you discover a vulnerability, **do not open a public issue**. Follow [SECURITY.md](SECURITY.md).

## Pull requests

Keep pull requests focused. A reviewer should be able to explain the purpose of the change without also understanding unrelated refactors.

Your pull request should describe:

- what changed;
- why it changed;
- user or operator impact;
- security impact, especially for authentication, encryption, device access, GitHub permissions, storage, or secret handling;
- how the change was verified.

Please update documentation when a user-facing command, workflow, configuration option, security boundary, or operational requirement changes.

## Commit and generated-file guidance

Use clear commit messages that describe the change rather than the implementation session.

Do not commit local environment files, credentials, generated secrets, or temporary debugging artifacts.

The dashboard build writes assets under `internal/server/ui/dist/`; if your dashboard change requires those generated assets to stay in sync, include the corresponding build output in the same pull request.

## Scope questions

If you are unsure whether a proposal belongs in local.env, open a feature request first. The project prefers saying no to adjacent scope rather than slowly becoming a general-purpose secrets platform.
