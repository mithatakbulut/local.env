# local.env administrator operations

Use this reference for instance-level operations only.

## New instance checklist

1. Choose the public HTTPS URL.
2. Confirm the GitHub organization that will use the instance.
3. Choose a persistent storage location for `/data`.
4. Choose a verified release version or immutable container digest.
5. Configure TLS directly or through a reverse proxy.
6. Supply the documented GitHub/bootstrap server credentials outside repository source files.
7. Start the service.
8. Visit `/setup` and complete the documented organization setup.
9. Verify sign-in and metadata-only dashboard access.
10. Document backup and recovery ownership before broad rollout.

## Container deployment shape

The project documentation currently shows this baseline pattern:

```bash
docker volume create localenv-data

docker run --detach --name localenv --publish 8080:8080 \
  --volume localenv-data:/data \
  --env LOCALENV_PUBLIC_URL=https://env.example.com \
  ghcr.io/localenv/localenv:VERSION
```

Replace example values only with administrator-provided or already configured values. Verify current configuration requirements before executing.

## Storage rules

- `/data` must be persistent for a durable instance.
- Keep server data restricted; the documented model uses `0700` for the data directory and `0600` for SQLite and credential files.
- Do not copy server credential files into source control.
- Do not treat the server database as a plaintext secret store.

## Upgrade or migration

Before an upgrade or migration:

1. identify current version and storage,
2. read the current release/migration instructions,
3. create and verify a recoverable backup,
4. record the rollback target,
5. perform the smallest controlled change,
6. verify startup, authentication, repository metadata, device metadata, and persistence,
7. retain the backup until verification is complete.

Never invent migration commands or environment variables. Check current project documentation or binary help.

## Backup and restore

Use the project's current backup/restore procedure for the deployed version. Preserve file ownership and restrictive permissions. During a restore, avoid booting multiple writers against the same SQLite data unless the documented procedure explicitly supports it.

## GitHub bootstrap and setup

The instance is intended to connect to a GitHub organization and organization-owned GitHub integration. Treat OAuth/App credentials as server bootstrap credentials:

- provide them through supported deployment configuration,
- never paste them into repository files,
- never expose them in logs or PRs,
- verify callback/public URL consistency,
- use `/setup` only over the intended HTTPS endpoint.

## Incident diagnosis

When an instance is unhealthy, inspect non-secret operational signals first:

- running version/image,
- container/process health,
- listener and reverse-proxy routing,
- persistent volume mount,
- filesystem permissions,
- public URL configuration,
- GitHub callback/configuration metadata,
- application logs after checking that they do not contain credentials.

Do not solve server incidents by requesting developer plaintext managed values. The server should not need those values.

## Hand off to the developer skill

After the shared instance is healthy and configured, repository and local-machine work belongs to `localenv`, including login, `repo init`, resolve, set/import, sync, diff, run, doctor, devices, and repository-key rotation.
