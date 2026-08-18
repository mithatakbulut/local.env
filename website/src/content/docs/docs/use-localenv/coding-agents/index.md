---
title: Use local.env with coding agents
description: Install local.env once in Claude Code, Codex, or Cursor and use agent-native workflows from any project.
---

local.env ships an installable coding-agent plugin for **Claude Code, Codex,
and Cursor**. Install it once, then ask your agent to use local.env from the
repository you are already working in.

You do not need to clone the local.env source repository into each project, and
you do not copy `SKILL.md` files between repositories. The installed plugin
contains the skills and their references. The existing `localenv` CLI remains
the execution boundary, so there is no MCP server to run.

## What the plugin includes

The package contains two skills so the agent can load the right workflow for the
job:

- `localenv` for developer work: login, repository setup, PR requirements,
  imports, sync and diff, runtime injection, diagnostics, devices, and key
  rotation.
- `localenv-admin` for instance work: deployment, `/setup`, GitHub bootstrap,
  TLS, persistent storage, upgrades, backups, restores, migrations, and server
  diagnosis.

The agent can choose between them from your request. You normally do not need to
invoke a skill name yourself.

## Before you install the plugin

Install the `localenv` CLI and make sure it is available on your `PATH`. For
workflows that talk to an instance, sign in normally with the CLI; the agent can
help with the rest of the workflow.

For across-project use, choose user scope when your agent offers an installation
scope.

## Claude Code

Add the local.env GitHub repository as a plugin marketplace, then install the
plugin:

```bash
claude plugin marketplace add mithatakbulut/local.env
claude plugin install localenv@localenv
```

After installation, start a normal Claude Code session in any application
repository and ask it to use local.env.

## Codex

Add the same GitHub repository as a marketplace and install the plugin:

```bash
codex plugin marketplace add mithatakbulut/local.env
codex plugin add localenv@localenv
```

Start a new Codex thread after installing or updating the plugin so the current
skills are included in the new session.

## Cursor

In Cursor, add the GitHub repository as a plugin source:

```text
/add-plugin https://github.com/mithatakbulut/local.env
```

Install `localenv` from the detected marketplace. Once installed, the same two
skills are available to Cursor without copying them into your application
repository.

## Use it in plain English

Once the plugin is installed, stay in your application repository and describe
the job you want done. For example:

```text
My local development environment is stale. Use local.env to check what needs to be synced.
```

```text
This PR adds a new local env key. Use local.env to resolve the requirement.
```

```text
Run this app with the managed values without writing them to disk.
```

For instance administration:

```text
Help me deploy a self-hosted local.env instance.
```

The developer skill prefers safe inspection before mutation, such as status,
diagnostics, dry-run sync, and diff when those steps fit the task.

## Secret safety still applies

The plugin teaches the agent the same boundary as the product:

- do not read, print, summarize, or transmit managed plaintext values;
- do not dump the process environment or enable shell tracing around secrets;
- enter secret values through the local CLI rather than chat or command-line
  arguments;
- keep local.env scoped to local development rather than production, staging,
  CI, or general-purpose credential storage.

The agent coordinates the workflow. The CLI still performs the local encryption,
decryption, and managed file writes.

## Continue with the CLI

For the underlying commands and manual workflows, see
[Everyday CLI workflows →](../everyday-cli-workflows/).
