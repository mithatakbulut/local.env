# Public Website, Documentation, and Blog Plan

## Status

**Proposed — no implementation has begun.** This is a separate publication
project, not a change to the v1 application protocol. `docs/plan.md` remains
the product and security source of truth; `docs/v1-progress.md` remains the
implementation tracker for the active application work.

## Decisions already made

| Area | Decision |
| --- | --- |
| Public origin | `https://www.local.env.best` |
| Routes | `/` landing page, `/docs/` documentation, `/blog/` blog |
| Existing instance | `https://local.env.best` remains the Go application behind its existing Cloudflare Tunnel, unchanged |
| Runtime | A separate Cloudflare Worker using Workers Static Assets; no origin server, database, or tunnel for the public site |
| Source boundary | Add a new `website/` project. Keep `frontend/` exclusively for the authenticated dashboard embedded in `localenv-server`. |
| Site framework | Astro static output with Starlight for documentation; Markdown/MDX content is versioned in this repository |
| Language | English only for the first release |
| Documentation journeys | Separate administrator/self-hosting and developer/joining-an-instance paths |
| Blog scope | Release notes, security advisories, and short product updates only; no comments, accounts, newsletter, CMS, or dynamic backend |
| Publishing | Pull requests receive a preview; merges to `main` publish production automatically |
| Visual direction | A distinct local.env identity using the supplied asterisk logo, rather than copying the neutral white-label dashboard style |
| Product proof | Use only reproducible screenshots of a controlled demo instance with explicitly non-secret metadata |

## Goals

1. Explain local.env as an Apache-2.0 licensed, self-hosted tool for keeping a
   team's **local-development** environment values aligned with its codebase.
2. Make the first installation and first developer sync easy to understand
   without hiding security-critical choices.
3. Give operators, contributors, and prospective users stable, fast,
   linkable documentation that remains available when an individual hosted
   local.env instance or its tunnel is unavailable.
4. Publish concise release, security, and product updates without adopting an
   external documentation service or CMS.
5. Preserve the v1 security boundary: no managed secret plaintext, plaintext
   repository encryption key, production credential, access token, live
   customer metadata, or real instance data is added to the public site,
   build output, screenshots, CI logs, or repository fixtures.

## Non-goals

- Do not move, proxy, wrap, or otherwise modify the existing
  `local.env.best` Go application, OAuth callbacks, GitHub webhook URL, CLI
  login endpoint, cookies, tunnel, or `LOCALENV_PUBLIC_URL`.
- Do not make the public Worker an API gateway, authentication layer, secret
  service, analytics collector, contact form handler, or customer dashboard.
- Do not claim that hosting, domains, GitHub, or optional Cloudflare services
  are cost-free. The software is free and self-hosted; each operator owns its
  infrastructure and related costs.
- Do not use a hosted docs provider, third-party tracking script, Google font,
  comment system, newsletter service, or user-generated content in v1.
- Do not describe local.env as a production, staging, CI, or general-purpose
  secret manager, and do not call it a password manager or make unreviewed
  security guarantees.

## Target architecture

```text
Browser
  ├─ https://www.local.env.best/*
  │    └─ Cloudflare Worker: immutable static Astro/Starlight build
  │         ├─ /        landing page
  │         ├─ /docs/   Markdown/MDX documentation
  │         └─ /blog/   Markdown/MDX posts + RSS
  │
  └─ https://local.env.best/*
       └─ existing Cloudflare Tunnel → localenv-server
          (unchanged application, OAuth, webhook, CLI, and dashboard routes)
```

The public Worker has no bindings and no Worker `fetch` handler in the first
release. It serves the generated `website/dist/` directory directly. Configure
`html_handling` for canonical trailing-slash pages and `not_found_handling` as
`404-page`; this is a multi-page static site, not an SPA fallback.

Cloudflare recommends Workers Static Assets for new static sites, and assets
are served/cached without invoking Worker code. Keep the public Worker
separate from the stateful self-hosted product. See the
[Workers Static Assets documentation](https://developers.cloudflare.com/workers/static-assets/)
and [custom-domain documentation](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).

### Source layout

```text
website/
├── package.json
├── package-lock.json
├── astro.config.mjs
├── tsconfig.json
├── wrangler.jsonc
├── public/
│   ├── _headers
│   ├── robots.txt
│   └── site.webmanifest
├── src/
│   ├── assets/brand/             # committed local logo/favicon/social assets
│   ├── components/               # Astro-only shared site components
│   ├── content/
│   │   ├── docs/docs/            # maps to /docs/*
│   │   └── blog/                 # maps to /blog/*
│   ├── layouts/
│   ├── pages/
│   │   ├── index.astro
│   │   ├── blog/index.astro
│   │   ├── blog/[...slug].astro
│   │   ├── rss.xml.ts
│   │   └── 404.astro
│   └── styles/
└── tests/
```

Starlight will render Markdown/MDX documentation with a generated sidebar,
table of contents, accessible search, syntax highlighting, and edit links.
Astro custom pages provide the distinct landing and the intentionally simple
blog. Keep the docs content under the `docs/` content subdirectory so its
generated paths are rooted at `/docs/`, while the Astro landing remains `/`.

Use Astro components and local CSS tokens for the public site. Do not import
dashboard React code, dashboard CSS, Go templates, internal packages, or
server data into `website/`.

## Message and content rules

### Positioning

The landing page should lead with a concise English proposition such as:

> Keep local development environments in sync — on infrastructure you control.

The supporting copy must make these points plain:

- local.env is Apache-2.0 licensed, free software, and self-hosted;
- operators choose and pay for their own hosting, domain, and optional
  platform services;
- it integrates with GitHub and a local CLI for local-development workflows;
- white-label configuration is specifically the instance display name, logo,
  and favicon; do not imply arbitrary code/CSS branding;
- the server handles encrypted values and device-specific wrapped repository
  keys, and does not persist managed secret plaintext or plaintext repository
  encryption keys;
- the product is not for production, staging, CI, or general-purpose
  credential storage.

Every security assertion must be traceable to `docs/plan.md`,
`docs/security-model.md`, or an automated test. Prefer precise statements to
marketing shorthand such as “zero knowledge,” “unbreakable,” or “free
forever.”

### Landing-page information architecture

1. **Hero:** product statement, a short self-hosting/cost disclosure, and
   `Read the docs` plus `View on GitHub` calls to action. Link an `Open your
   instance` action to `https://local.env.best/login`; it is an external
   navigation, never a cross-origin API call.
2. **Problem and workflow:** show how repository changes, PR readiness, local
   CLI resolution, and safe sync fit together without presenting a secret
   value field or value example.
3. **Security boundary:** compact factual summary linked to the full Security
   model; include the local-development-only limitation.
4. **Self-hosted and white-label:** Docker/GitHub integration summary and the
   exact display-name/logo/favicon branding scope.
5. **Real product proof:** three labelled, responsive screenshots: repository
   readiness, device access, and branding/settings. Each links to the relevant
   docs page.
6. **Getting started:** two equal cards for `I run an instance` and `I join an
   instance`, each linking to its first docs step.
7. **Footer:** Docs, Blog, GitHub, Apache-2.0 license, Security policy, and
   the infrastructure-cost disclosure.

### Documentation information architecture

Write these pages afresh in English. The existing root `docs/installation.md`,
`docs/cli.md`, and `docs/security-model.md` remain factual source material
until their public replacements have been reviewed; do not delete them during
this work.

```text
/docs/
├── overview/
├── self-host/                         # administrator journey
│   ├── prerequisites/
│   ├── deploy-with-docker/
│   ├── configure-public-url-and-tls/
│   ├── configure-github-oauth/
│   ├── create-and-install-github-app/
│   ├── configure-instance-branding/
│   └── verify-your-instance/
├── join-an-instance/                  # developer journey
│   ├── prerequisites/
│   ├── install-the-cli/
│   ├── sign-in-and-register-device/
│   ├── initialize-a-repository/
│   ├── resolve-pr-requirements/
│   ├── sync-safely/
│   └── verify-your-first-sync/
├── use-localenv/
│   ├── everyday-cli-workflows/
│   ├── runtime-mode/
│   ├── device-approval-and-revocation/
│   └── key-rotation/
├── operate/
│   ├── backup-restore-and-upgrades/
│   └── troubleshooting/
├── security/
│   ├── security-model/
│   ├── threat-model-and-limitations/
│   └── security-advisories/
└── reference/
    ├── cli-commands/
    ├── environment-variables/
    └── github-app-permissions/
```

The docs homepage presents the two journeys first. Each task page has one
goal, preconditions, exact non-secret commands or configuration, an expected
result, a verification step, and explicit next/previous links. Use tabs only
for short alternatives on the same task (for example, operating system-specific
CLI installation); do not hide sequential setup phases inside visual tabs.

Never place the GitHub OAuth client secret, GitHub App credential encryption
key, webhook secret, a real hostname, a production command line, or a managed
secret in docs snippets. Declare a stable, obviously non-secret placeholder
convention (for example, `example.localenv.test`, `EXAMPLE_VALUE_DO_NOT_USE`)
and test it.

### Blog model

Use an Astro content collection validated at build time:

```yaml
title: "..."
description: "..."
pubDate: 2026-08-16
category: release-notes # release-notes | security-advisory | product-update
draft: false
```

- `/blog/` lists published posts newest first and filters by the three fixed
  categories.
- `/blog/<slug>/` is a static post page with canonical metadata.
- `/rss.xml` contains published posts only.
- `draft: true` posts are excluded from the index, feeds, sitemap, and
  production build. Draft work stays in a branch/PR rather than relying on an
  editor account.
- A security advisory uses clear affected-version, impact, mitigation, and
  fixed-version sections. Follow `SECURITY.md`; never publish exploit
  credentials or unredacted customer incident details.

## Brand, media, and accessibility

1. Move the user-provided `local_env_logo_asterisk.png` (a 1254×1254 RGBA
   source image) into `website/src/assets/brand/` and commit it as the source
   asset. Generate local, optimized PNG/WebP derivatives for the header,
   social card, and favicon/manifest; do not hotlink it or depend on an image
   CDN.
2. Establish a distinct dark, high-contrast developer-tool visual system:
   named color/spacing/type tokens, strong accent color, restrained
   configuration-grid/terminal motifs, and a logo-safe clear space. The
   dashboard remains neutral and white-label; this does not change it.
3. Use self-hosted or system fonts only. Respect `prefers-reduced-motion`,
   ensure keyboard-visible focus states, semantic landmarks, descriptive alt
   text, and legible mobile/desktop layouts.
4. Build social preview images locally. Use a static `og:image`, canonical
   URLs, page titles/descriptions, sitemap, and `robots.txt`. The production
   hostname is indexable; Worker preview and `*.workers.dev` hosts are
   explicitly `noindex`.
5. Create screenshots from a dedicated temporary demo server/database with
   synthetic organization, repository, PR, user, device, and branding labels.
   Capture only approved dashboard metadata views at desktop and mobile sizes.
   Add a reproducible screenshot script/fixture and an automated text scan for
   prohibited terms/known sentinels before committing the image files.

## Security, privacy, and caching

- Static output only: no visitor identity, cookie, form submission, analytics
  event, secret, or application request reaches the public Worker.
- Set static headers through `website/public/_headers`: a final CSP that
  permits only the site’s own scripts/styles/images/fonts, `base-uri 'self'`,
  `object-src 'none'`, `frame-ancestors 'none'`, `X-Content-Type-Options:
  nosniff`, restrictive `Referrer-Policy`, and a restrictive
  `Permissions-Policy`. Do not allow `unsafe-inline`, third-party hosts, or
  broad CORS without a reviewed requirement.
- Verify the generated Astro/Starlight output before finalizing CSP. If a
  dependency requires an inline script/style or an external host, remove or
  replace it unless a separately approved exception documents the exact
  source and risk.
- Fingerprinted build assets receive long immutable browser caching; HTML,
  docs, feed, sitemap, and `robots.txt` revalidate so a new publish becomes
  discoverable promptly. Cloudflare's static-assets defaults and `_headers`
  support this policy. See [Workers static-asset headers](https://developers.cloudflare.com/workers/static-assets/headers/).
- Do not enable Cloudflare Web Analytics in the initial release. Adding any
  analytics later requires an explicit privacy/CSP decision.

## Deployment and DNS

### Cloudflare setup (one-time, manual)

1. Confirm `local.env.best` is an active Cloudflare zone and inspect DNS. Do
   not alter the existing `local.env.best` tunnel hostname or its ingress
   rules.
2. Confirm that `www.local.env.best` has no conflicting CNAME/custom-domain
   assignment. Attach it as the custom domain of a new, dedicated Worker,
   named `localenv-public-site`. Cloudflare creates the required DNS record
   and certificate when the custom-domain attachment is completed.
3. Keep `workers.dev` available for deploy previews, but prevent indexing of
   it. Do not attach `docs.local.env.best` or `blog.local.env.best`: their
   canonical homes are the `/docs/` and `/blog/` paths on `www`.
4. Confirm production TLS, custom-domain certificate issuance, `/`, `/docs/`,
   `/blog/`, `/rss.xml`, `/robots.txt`, and an intentional 404 before calling
   the site live.

### Worker configuration

Create `website/wrangler.jsonc` only after the Worker name/account is known.
It should set a current deployment `compatibility_date`, `workers_dev: true`
for preview URLs, a `www.local.env.best` custom-domain route, and:

```jsonc
{
  "assets": {
    "directory": "./dist",
    "html_handling": "auto-trailing-slash",
    "not_found_handling": "404-page"
  }
}
```

The first release intentionally has no `main`, bindings, secrets, database,
KV, R2, or Durable Object. Update the date at implementation time rather than
copying a stale date from this document.

### CI and preview model

Use two independent mechanisms:

1. **Repository verification:** extend `.github/workflows/test.yml` with a
   separate `website` job. It performs deterministic `npm ci`, content/type
   checks, production build, internal-link/frontmatter checks, output/header
   assertions, and the public-site sensitive-data scan on pull requests and
   `main`. It receives no Cloudflare credentials.
2. **Publishing:** connect the `website/` Worker to **Cloudflare Workers
   Builds** Git integration. Configure its root directory, build command, and
   deploy command to build `website/` and run `wrangler deploy`. It publishes
   an isolated preview for each pull request and production after merges to
   protected `main`. Require the repository verification workflow in branch
   protection before `main` can be merged.

This native Git integration avoids storing Cloudflare deployment credentials
in this repository while still providing the requested preview/production
flow. Cloudflare supports GitHub-backed Worker builds and pull-request
statuses/previews. See [Workers Git integration](https://developers.cloudflare.com/workers/ci-cd/builds/git-integration/).

If Workers Builds cannot be used, use the documented GitHub Actions fallback:
a Cloudflare API token and account ID stored only as GitHub Actions secrets,
with the token restricted to the single account/Worker/zone operations needed
for deployment. Do **not** substitute GitHub OIDC for this flow; Cloudflare's
current GitHub Actions guidance specifies an API token and account ID. See
[Cloudflare's GitHub Actions guide](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/).

## Phased implementation plan

### W0 — Prerequisites and deployment boundary

1. Record the public-site decisions above in the implementation handoff and
   leave the active dashboard phase untouched.
2. Verify the Cloudflare zone, existing tunnel mapping, and `www` DNS
   availability with read-only checks.
3. Create the Worker/custom-domain association and Workers Builds Git
   connection, but do not repoint `local.env.best` or change any GitHub
   application configuration.
4. Configure branch protection so the future `website` verification job is
   required for `main`.

**Exit:** `www.local.env.best` is reserved for the new Worker without changing
the behavior of `local.env.best`; a test Worker preview is reachable and
`noindex`.

### W1 — Static-site foundation

1. Create the isolated `website/` Astro/Starlight project and deterministic
   package lock.
2. Add content schemas, static routing, custom 404, navigation shell,
   `robots.txt`, sitemap, RSS endpoint, manifest, and initial `wrangler.jsonc`.
3. Add local development, type/content validation, production build, and
   Worker-compatible preview commands.
4. Add the public static-header policy and assertions that it lands in the
   deploy output.

**Exit:** a clean install/build produces a static, navigable `/`, `/docs/`,
`/blog/`, feed, and 404 locally; no Go/dashboard artifacts or remote runtime
dependencies are required.

### W2 — Brand system and landing page

1. Commit and optimize the supplied logo plus derived local icon/social assets.
2. Implement the distinctive visual system, responsive header/footer, hero,
   workflow/security/self-hosting sections, two journey cards, and canonical
   CTA links.
3. Add the exact cost and scope disclosures, Apache-2.0/GitHub/Security links,
   metadata, and accessibility semantics.
4. Capture approved demo screenshots from synthetic data and integrate them
   with descriptive captions/alt text.

**Exit:** the landing page is responsive, accessible, truthful to the product
contract, and contains no live customer/app data or secret-like material.

### W3 — Fresh documentation

1. Author the documentation tree above from scratch, beginning with the two
   journey selector pages and their complete happy paths.
2. Add explicit verification/next-step blocks to every setup task and concise
   safe placeholders for all configuration examples.
3. Cover the CLI, runtime mode, device approval/revocation, rotation,
   operations, backups/restores, branding limits, GitHub permissions, and the
   security model/threat limits from source requirements.
4. Enable generated navigation, search, edit links, page metadata, and a
   visible link back to the landing/product instance.

**Exit:** an administrator can deploy and verify an instance, and a developer
can join, register a device, initialize/sync a repository, and understand the
safe daily workflow without relying on the legacy short docs.

### W4 — Blog and editorial guardrails

1. Implement the validated blog collection, published/draft filtering,
   category views, post layout, archive, canonical metadata, and RSS.
2. Add one representative post for each permitted category, using only public,
   non-sensitive information.
3. Add a short contributor guide for frontmatter, drafts, review expectations,
   release-note links, and security-advisory coordination through `SECURITY.md`.

**Exit:** a draft cannot leak into a production page/feed/sitemap, and a
reviewed post publishes automatically only after its PR merges.

### W5 — Verification, preview, and production release

1. Add website verification to repository CI and turn on Cloudflare Workers
   Builds PR previews/production deploys.
2. Test all canonical/public routes, redirects/trailing slashes, preview
   `noindex`, custom-domain TLS, cache headers, CSP, security headers, sitemap,
   RSS, social metadata, mobile navigation, keyboard navigation, and reduced
   motion.
3. Scan generated HTML/assets/screenshots and CI logs with explicit
   non-secret sentinels; assert the public site never contains application
   secrets, ciphertext, wrapped keys, OAuth credentials, server database data,
   or dashboard bootstrap payloads.
4. Test failure behavior: an invalid content schema, broken internal link,
   unexpected external asset, failed build, and failed deploy must block the
   corresponding publish. Confirm a failed public-site deployment cannot
   affect `local.env.best`.
5. Record deployment configuration (Worker name, zone/domain attachment,
   build commands, preview behavior, rollback procedure, and external manual
   evidence) in the implementation tracker when a website implementation
   phase is formally scheduled.

**Exit:** a reviewed PR has a noindex preview, a merge to `main` deploys the
verified build to `www.local.env.best`, and the existing application origin is
provably unchanged.

## Acceptance checklist

- [ ] `local.env.best` continues to serve the existing application, and its
      tunnel/OAuth/webhook/CLI behavior is unchanged.
- [ ] `www.local.env.best` serves only the static public site on valid TLS.
- [ ] `/`, `/docs/`, `/blog/`, individual docs/posts, `/rss.xml`, sitemap,
      `robots.txt`, and a 404 page work with canonical URLs.
- [ ] Administrator and developer onboarding are separate, complete, and
      safely linkable task-by-task flows.
- [ ] Product, license, security, white-label, and cost statements match the
      repository's actual contract and do not overclaim.
- [ ] The supplied logo is locally served; no third-party font, image,
      analytics, or script is required.
- [ ] All screenshots are synthetic and pass the sensitive-data scan.
- [ ] CSP, security headers, cache policy, accessibility checks, and SEO
      metadata pass against the generated production output.
- [ ] PR previews are non-indexable; `main` deployment is automatic only
      after required repository checks pass.
- [ ] No Cloudflare credential is committed, and publishing cannot mutate the
      product application or its persistent data.

## Deferred decisions

- Additional languages, full-text external search, versioned documentation,
  email/newsletter, comments, contact forms, telemetry, and hosted customer
  examples require separate scope, privacy, security, and operational
  decisions.
- Moving the product application to `app.local.env.best` and repurposing the
  apex `local.env.best` as marketing is explicitly out of scope for this
  release.
