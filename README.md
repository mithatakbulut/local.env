# local.env

**Your code changed. Your local env should too.**

`local.env` keeps a team's local development environment variables synchronized with the code changes that require them.

It connects GitHub pull requests with a local CLI, so a new environment requirement can be detected, resolved, and distributed without passing `.env` files around in Slack or DMs.

Self-hosted. Apache-2.0 licensed. Plaintext managed values stay on developer machines.

[Website](https://www.local.env.best) · [Documentation](https://www.local.env.best/docs/) · [Releases](https://github.com/mithatakbulut/local.env/releases)

## The problem

Adding a new environment variable is easy:

```diff
+ STRIPE_SECRET_KEY=
```

Keeping everyone else's local environment up to date is usually not.

Someone mentions the new key in Slack. Someone sends the value over DM. A developer misses the message. Another joins the project two weeks later. Eventually someone pulls `main` and discovers that the code works — their local environment is just stale.

`local.env` moves that coordination back into the development workflow.

## How it works

```text
PR adds a new environment key
            ↓
local.env detects the requirement
            ↓
GitHub readiness check reports it missing
            ↓
developer runs `localenv resolve --pr 42`
            ↓
value is encrypted on the developer machine
            ↓
readiness check passes
            ↓
merge
            ↓
teammates run `localenv sync`
```

GitHub sees the key name and its readiness state.

It never receives the managed plaintext value.

## Repository contract

A repository opts into local.env with a small committed `localenv.yaml` file:

```yaml
version: 1

files:
  - schema: .env.example
    target: .env.local
```

The schema declares which keys developers need:

```dotenv
DATABASE_URL=
STRIPE_SECRET_KEY=
REDIS_URL=
```

The schema belongs in Git.

The developer's actual values do not.

Monorepos can declare multiple schema/target pairs:

```yaml
version: 1

files:
  - schema: apps/web/.env.example
    target: apps/web/.env.local

  - schema: apps/api/.env.example
    target: apps/api/.env.local
```

## Everyday workflow

Sign in to your team's local.env instance:

```bash
localenv login https://env.example.com
```

A repository is initialized once by an authorized developer:

```bash
localenv repo init
```

When a pull request introduces a new requirement:

```bash
localenv resolve --pr 42
```

After the change merges:

```bash
git pull
localenv sync
```

Want to inspect changes without touching your local file?

```bash
localenv diff
localenv sync --dry-run
```

Don't want managed values written to a dotenv file at all?

```bash
localenv run -- npm run dev
```

The CLI decrypts the managed values in memory and passes them directly to the child process environment.

## What local.env does

- Keeps local-development environment requirements alongside the codebase.
- Detects new environment keys introduced by pull requests.
- Reports environment readiness through GitHub.
- Encrypts managed values locally before upload.
- Synchronizes only the managed section of local dotenv files.
- Supports runtime injection without writing managed values to disk.
- Manages repository access through authorized devices.
- Supports repository-key rotation after device revocation.
- Provides a self-hosted, metadata-only dashboard for repositories, devices, and audit events.

## Security boundary

`local.env` is designed so the coordination server does not need managed plaintext secrets.

- Managed values are encrypted and decrypted by the CLI.
- Repository encryption keys are generated on developer machines.
- The server stores ciphertext and device-wrapped repository keys.
- GitHub receives key names and readiness metadata, not secret values.
- The dashboard never accepts or displays managed secret values.

A compromised authorized developer machine is outside this boundary: a device that has already received a secret cannot be made to forget it.

Read the [security model](https://www.local.env.best/docs/security/security-model/) and [threat model](https://www.local.env.best/docs/security/threat-model-and-limitations/) for the complete design.

## What local.env is not

`local.env` is intentionally narrow.

It is **not** a production secret manager, CI secret store, cloud vault, password manager, or browser-based secret editor.

Use your existing infrastructure for production and deployment credentials.

`local.env` focuses on one problem:

> keeping local development environments synchronized with the code changes that introduce new requirements.

## Self-hosting

Each team runs its own local.env instance and connects an organization-owned GitHub App.

The service requires:

- an HTTPS endpoint,
- persistent storage,
- a GitHub organization,
- the bootstrap GitHub authentication configuration,
- and the local.env server.

Start with the [self-hosting guide](https://www.local.env.best/docs/self-host/prerequisites/).

If your organization already runs an instance, follow the [developer onboarding guide](https://www.local.env.best/docs/join-an-instance/prerequisites/).

## CLI

The main commands are:

```text
localenv login
localenv status
localenv repo init
localenv resolve
localenv set
localenv import
localenv sync
localenv diff
localenv run
localenv doctor
localenv devices
localenv keys rotate
```

See the [CLI reference](https://www.local.env.best/docs/reference/cli-commands/) for details.

## Contributing

Contributions are welcome.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security-sensitive issues should follow [SECURITY.md](SECURITY.md) instead of being reported publicly.

## License

Apache License 2.0.
