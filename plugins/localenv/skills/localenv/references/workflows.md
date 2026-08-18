# Developer workflow routing

Use this guide to choose a local.env workflow without loading server-administration context.

## User intent to workflow

### "My env is stale" / "sync my env"

1. `localenv status`
2. `localenv sync --dry-run`
3. `localenv diff`
4. Explain non-secret changes.
5. `localenv sync`

### "This PR added an env var" / "resolve PR #42"

1. Confirm the PR number.
2. Run `localenv resolve --pr <number>`.
3. Let the human answer interactive secret prompts directly in the terminal.
4. Do not capture or repeat entered values.

### "Set up this repo to use local.env"

1. Inspect repository structure, existing schema files, `.gitignore`, and any existing `localenv.yaml`.
2. Propose the smallest correct `localenv.yaml` mapping.
3. Ensure target dotenv files are ignored.
4. If authorized and requested, run `localenv repo init`.
5. Use `localenv doctor` to validate.

This is repository onboarding, not instance deployment. If the organization does not yet have a local.env server, route to `localenv-admin`.

### "Join our local.env instance"

1. Obtain the organization-provided instance URL from the user or repository documentation.
2. `localenv login <instance-url>`
3. `localenv status`
4. `localenv doctor`

Never guess the instance URL.

### "Why isn't local.env working?"

1. `localenv doctor`
2. `localenv status`
3. Inspect `localenv.yaml`, schema paths, target ignore rules, and non-secret filesystem metadata.
4. Use the relevant command's `--help` if syntax is unclear.
5. Do not inspect managed plaintext values.

### "Use my existing .env as the starting values"

Use `localenv import <file>` without reading the file contents into the agent context.

### "Run the app without writing .env.local"

Use:

```bash
localenv run -- <command>
```

Do not use a child command that dumps environment variables.

### "Remove a lost device"

1. Inspect with `localenv devices`.
2. Explain that revocation blocks future access but cannot erase previously received plaintext.
3. Verify exact revoke syntax via CLI help.
4. Revoke only the intended device.
5. Consider `localenv keys rotate` from an active authorized device.

## Escalate to localenv-admin when

The task mentions any of the following:

- creating or deploying a local.env instance,
- self-hosting infrastructure,
- `/setup`,
- GitHub OAuth/App bootstrap configuration,
- server environment variables,
- TLS or reverse proxy configuration,
- persistent server storage,
- SQLite/server credential files,
- backup, restore, migration, or upgrade,
- organization-wide server lifecycle or incident recovery.
