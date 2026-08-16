# Contributing to the public website

This guide covers blog posts and other `website/` content. Product protocol
changes still belong in `docs/plan.md` and the Go application, not here.

## Frontmatter

Blog posts live in `website/src/content/blog/` and must validate against the
collection schema:

```yaml
title: "..."
description: "..."
pubDate: 2026-08-16
draft: false
```

Keep copy in English for this release.

## Drafts

Set `draft: true` while a post is unfinished. Drafts are excluded from `/blog/`,
`/rss.xml`, the sitemap, and the production static build. Do
not rely on an editor account or CMS; unpublished work stays in a branch or
pull request.

A post becomes public only after `draft: false` is reviewed and the change
merges to `main`.

## Review expectations

- No managed secret plaintext, plaintext repository encryption keys, OAuth
  tokens, webhook secrets, live customer metadata, or real instance data.
- Use placeholders such as `example.localenv.test` when a hostname is required.
- Do not overclaim security properties. Prefer statements that already exist
  in `docs/plan.md` or `docs/security-model.md`.
- Do not describe local.env as a production, staging, CI, or general-purpose
  secret manager.

## Release notes

Link GitHub Releases for artifact lists, checksums, and signatures. A
release note should explain what operators should verify, not paste
binaries or credential material.

## Security advisories

Report vulnerabilities through [`SECURITY.md`](../SECURITY.md) and GitHub's
private reporting form. Public security-advisory posts are published only
after coordinated review. They must include affected versions, impact,
mitigation, and fixed version. They must not include exploit credentials,
unredacted customer incident details, or reproduction steps that disclose
secrets.
