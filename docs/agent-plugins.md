# Agent plugin distribution

local.env ships one plugin package for Cursor, Claude Code, and Codex. The
canonical skill content lives under `plugins/localenv/skills/`; platform
manifests only describe how each host discovers that same package.

Developers using local.env do not need to clone this repository or copy skill
files into each application repository. Install the plugin once at user scope
where the host supports it, then use local.env naturally from any project.

## Package layout

```text
.cursor-plugin/marketplace.json
.claude-plugin/marketplace.json
.agents/plugins/marketplace.json

plugins/localenv/
├── .cursor-plugin/plugin.json
├── .claude-plugin/plugin.json
├── .codex-plugin/plugin.json
└── skills/
    ├── localenv/
    │   ├── SKILL.md
    │   └── references/
    │       ├── security.md
    │       └── workflows.md
    └── localenv-admin/
        ├── SKILL.md
        └── references/
            └── operations.md
```

`localenv` handles developer and day-to-day repository workflows.
`localenv-admin` handles self-hosting and shared-instance administration. The
host selects the relevant skill from the user's intent.

## Cursor

For local plugin development, copy the package so the plugin manifest ends up at
`~/.cursor/plugins/local/localenv/.cursor-plugin/plugin.json`:

```bash
rm -rf ~/.cursor/plugins/local/localenv
cp -R plugins/localenv ~/.cursor/plugins/local/localenv
```

Do not rely on a symlink for local plugin testing; use a real copied directory.
Reload Cursor after replacing the package.

For public distribution, submit the repository to the Cursor Marketplace. The
root `.cursor-plugin/marketplace.json` points Cursor at `plugins/localenv`.
Once published, users install the local.env plugin rather than copying skill
files into their repositories.

## Claude Code

Add this repository as a marketplace:

```text
/plugin marketplace add mithatakbulut/local.env
```

Then install the plugin:

```text
/plugin install localenv@localenv
```

Choose user scope to make the plugin available across projects. The marketplace
uses `.claude-plugin/marketplace.json`; the installed package uses
`plugins/localenv/.claude-plugin/plugin.json` and the shared `skills/` tree.

For development without marketplace installation, Claude Code can load the
package directory directly with its plugin development flow.

## Codex

Add this repository as a Git marketplace:

```bash
codex plugin marketplace add mithatakbulut/local.env
```

Then install local.env from that marketplace:

```bash
codex plugin add localenv@localenv
```

The repo marketplace is defined at `.agents/plugins/marketplace.json` and points
to `plugins/localenv`. The package has a native `.codex-plugin/plugin.json`
manifest and uses the same shared `skills/` tree as Cursor and Claude Code.

After changing an installed plugin, reinstall or update it and start a new Codex
thread so the refreshed skills are included in the new prompt.

## Source of truth

Do not maintain platform-specific copies of `SKILL.md` or its references.
Changes to developer or administrator behavior belong under
`plugins/localenv/skills/`. Platform manifests should remain thin packaging and
discovery metadata.

This means files such as
`plugins/localenv/skills/localenv/references/workflows.md` are part of the
installed plugin payload. A developer working in another repository does not
need access to the local.env source checkout for the agent to read them.

## No MCP dependency

The plugin intentionally has no MCP server. The `localenv` CLI remains the
execution boundary for local-development workflows, including interactive
secret entry. The skills teach coding agents when and how to use that CLI
without exposing managed plaintext values.
