---
title: "Why sharing local env values is still awkward"
description: "A new environment variable is a tiny code change, but teams still coordinate the value through Slack, DMs, docs, and memory. local.env moves that work back into the development workflow."
pubDate: 2026-08-16
draft: false
---

Adding a new environment variable is usually one line of code.

```diff
+ STRIPE_SECRET_KEY=
```

What comes after is the annoying part.

Someone opens a pull request, mentions the new key in Slack, and tells the team to DM them for the value. A few people update their `.env.local` immediately. Someone misses the message. Someone joins the project two weeks later. Someone pulls `main`, runs the app, and only then discovers that their local environment is stale.

None of this is difficult. It is just repetitive, easy-to-forget coordination.

That is the problem `local.env` is trying to remove.

## The code has a workflow. The env file usually does not.

Code changes already have a reliable path: branch, pull request, review, checks, merge, pull.

Local environment changes often happen beside that process.

The repository knows that `STRIPE_SECRET_KEY` is now required, but the value itself is passed around somewhere else: Slack, a DM, a Notion page, a password manager note, or a quick call. The code and the local configuration move through two different systems.

That separation is where the friction starts.

A chat message is temporary. A pull request is part of the history of the codebase. When secret distribution depends on a message someone happened to read, local setup slowly becomes tribal knowledge.

You start seeing the same questions again:

> Which value are we using for this?

> Can someone send me the latest `.env`?

> Did that PR add a new env variable?

> Why does the app work on your machine but not mine?

Each one takes a minute. Across a team, over time, those minutes become a recurring tax.

## The missing value should be caught before merge

The useful moment is not when a developer pulls broken code.

It is when the new dependency first appears.

If a pull request adds this:

```dotenv
STRIPE_SECRET_KEY=
```

then the pull request already tells us something important: after this code merges, developers will need a local value for that key.

`local.env` uses that point in the workflow.

```text
PR adds NEW_KEY
      ↓
local.env detects it
      ↓
readiness check fails
      ↓
developer runs `localenv resolve`
      ↓
value is encrypted locally
      ↓
readiness check passes
      ↓
merge
```

The secret itself does not go into GitHub. GitHub only knows that the key exists and whether the requirement has been resolved.

The value is entered through the CLI and encrypted on the developer machine before it is uploaded.

That keeps the workflow close to Git without turning Git into a secret store.

## Sync should be boring

After the PR merges, another developer should not need the original Slack thread.

They should be able to pull the code and run:

```bash
localenv sync
```

The CLI downloads the encrypted repository state, decrypts it on the authorized device, and updates only the block it owns inside `.env.local`.

```dotenv
MY_DEBUG_FLAG=true

# >>> local.env managed - do not edit manually
DATABASE_URL="..."
STRIPE_SECRET_KEY="..."
# <<< local.env managed
```

Everything outside that block remains local to the developer.

For teams that do not want managed secrets written to disk at all, the same idea can stop one step earlier:

```bash
localenv run -- npm run dev
```

The values are decrypted in the CLI and passed directly to the child process environment.

## The goal is not another secret manager

There are already mature tools for production secrets, infrastructure credentials, and company-wide vaults.

`local.env` is narrower.

It focuses on one boring problem: keeping local development environment requirements synchronized with the code changes that introduce them.

The ideal workflow is small enough to disappear:

```text
change schema
→ resolve value
→ merge
→ sync
→ keep working
```

No “DM me for the key.”

No full `.env` file in Slack.

No old setup message that becomes unofficial documentation.

No pulling `main` and discovering ten minutes later that the code was fine; your local environment was just out of date.

Local environment setup should not require a team ritual every time one line is added to `.env.example`.
