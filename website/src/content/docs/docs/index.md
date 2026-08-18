---
title: Documentation
description: Choose an administrator, developer, or coding-agent journey to get started with local.env.
---

local.env is Apache-2.0 licensed, self-hosted software for keeping a team's
**local-development** environment values aligned with its codebase.

It is not a production, staging, CI, or general-purpose credential manager.
The server stores encrypted values and device-specific wrapped repository keys;
it never stores managed secret plaintext or plaintext repository encryption
keys.

## Choose your journey

### I run an instance

Deploy and operate the service your team uses: Docker, public URL, GitHub
OAuth, GitHub App installation, optional branding, and readiness checks.

[Start self-hosting →](./self-host/prerequisites/)

### I join an instance

Install the CLI, sign in, register a device, initialize a repository, resolve
PR requirements, and sync safely to a local dotenv target.

[Start joining →](./join-an-instance/prerequisites/)

### I use a coding agent

Install the local.env plugin once in Claude Code, Codex, or Cursor, then ask the
agent to handle local.env workflows from the repository you are already working
in. You do not copy skill files into each project.

[Set up coding agents →](./use-localenv/coding-agents/)

## Product overview

Read the [overview](./overview/) for the workflow, security boundary, and what
local.env deliberately does not do.

## Reference material

- [Use local.env with coding agents](./use-localenv/coding-agents/)
- [Security model](./security/security-model/)
- [CLI commands](./reference/cli-commands/)
- [Environment variables](./reference/environment-variables/)
- [GitHub App permissions](./reference/github-app-permissions/)
