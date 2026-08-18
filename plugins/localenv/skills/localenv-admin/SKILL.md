---
name: localenv-admin
description: >
  Administer and self-host a local.env server instance. Use when creating,
  deploying, configuring, upgrading, backing up, restoring, migrating, or
  diagnosing the shared local.env service; configuring its HTTPS endpoint,
  persistent storage, GitHub organization OAuth/App bootstrap, `/setup`, or
  server-side operational lifecycle. Do not use this skill for normal developer
  repository workflows such as sync, diff, resolve, import, run, or local
  dotenv management; use localenv for those tasks.
---

# local.env administrator workflows

This skill is for platform owners and administrators responsible for a shared
self-hosted local.env instance.

Read `references/operations.md` before changing infrastructure or instance
configuration. Keep local.env's security boundary intact: the server coordinates
ciphertext and metadata and must not become a plaintext secret editor or general
production secret store.

## Routing boundary

Use this skill for:

- creating a new local.env instance,
- deploying or upgrading the local.env server,
- configuring the public HTTPS endpoint,
- persistent `/data` storage and permissions,
- GitHub organization and bootstrap authentication configuration,
- initial `/setup`,
- reverse proxy or TLS integration,
- backup, restore, and migration procedures,
- server-side health and operational diagnosis,
- recovery and lifecycle changes affecting the shared service.

Do not use this skill for ordinary developer work inside a repository. Route
login, `repo init`, PR resolution, sync, diff, import, run, doctor, local device
workflows, and repository dotenv management to `localenv`.

## Establish the deployment target

Before changing infrastructure, determine:

1. the intended public HTTPS URL,
2. the GitHub organization that will own/use the instance,
3. where persistent data will live,
4. how TLS is terminated,
5. which released local.env version or immutable container digest will run,
6. how server bootstrap credentials are supplied and protected,
7. how backups will be taken before upgrades or migrations.

Do not invent organization names, domains, credentials, repository permissions,
or cloud resources. Use values supplied by the administrator or already present
in their infrastructure configuration.

## Prefer verified release artifacts

For production-like self-hosting, use a verified tagged release binary or a
published container digest. Avoid deploying arbitrary development builds unless
the administrator explicitly intends to test one.

A minimal container deployment follows this shape:

```bash
docker volume create localenv-data

docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://env.example.com \
  ghcr.io/localenv/localenv:VERSION
```

Treat this as a pattern, not permission to guess real deployment values. Verify
current release and configuration requirements from project documentation before
executing.

## Persistent storage

The server requires persistent storage for `/data`. Do not deploy with ephemeral
storage if the instance is expected to survive restarts or replacement.

Keep the data directory restricted. The documented deployment model uses
restricted directory/file permissions, including `0700` for `/data` and `0600`
for SQLite and credential files.

Before destructive changes, upgrades, restores, or migrations, establish a
recoverable backup according to the current project procedure.

## GitHub and initial setup

local.env instances are organization-scoped and use GitHub authentication and
an organization-owned GitHub App/integration.

Supply bootstrap credentials through the supported server configuration; do not
write them into repository files or documentation. After the server is reachable
at its configured HTTPS URL, use `/setup` for the documented initial setup flow.

Do not turn the dashboard into a mechanism for entering or displaying managed
plaintext values. Its role is repository, device, audit, and other metadata.

## TLS and exposure

Expose the instance over HTTPS. TLS may terminate at the local.env server or an
appropriate reverse proxy. Ensure the configured public URL matches the URL
users and GitHub callbacks will reach.

Do not silently expose an unauthenticated development endpoint to the public
Internet.

## Operational changes

For upgrades, migration, backup/restore, and recovery:

1. identify the currently running version and storage location,
2. verify the current documented procedure,
3. create/verify a backup before mutation,
4. make one controlled change at a time,
5. verify service health, login, repository metadata, and persistence afterward,
6. keep rollback possible until verification succeeds.

If command-line flags, environment variable names, migration steps, or release
requirements are uncertain, inspect the current project documentation or
release help rather than guessing.

## Security boundary

The shared server must not require managed plaintext secret values to coordinate
a repository. Developer clients encrypt/decrypt managed values locally; the
server stores ciphertext, wrapped repository keys, and metadata.

local.env remains a local-development coordination system. Do not repurpose the
instance as a production, staging, CI/CD, password, or general-purpose secret
manager.
