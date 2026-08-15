# Dashboard UI Refresh Plan

## Purpose

Deliver the first-party, white-label dashboard that every self-hosted
`local.env` customer can use without building a separate UI. The dashboard is
an operational view of repository readiness, devices, and audit data. It is
not a secret-management interface.

This document is an implementation plan for the existing v1 dashboard. It
does not change the product or security requirements in `docs/plan.md`.

## Product Decision

Each company runs its own `local.env` instance and uses the bundled dashboard
at its own domain. The instance can display its configured name, logo, and
favicon, while the CLI remains named `localenv`.

Customers should not need to build their own dashboard for normal use. A
custom dashboard is an optional future API consumer, not a prerequisite for
self-hosting.

## Goals

- Replace the current unstyled server-rendered HTML with a polished,
  responsive dashboard.
- Use a simple black-and-white visual system with green reserved for positive
  readiness, successful actions, and the primary brand accent.
- Make branding configuration visible and reliable across the setup and
  dashboard pages.
- Keep a single deployable container and retain the Go server as the authority
  for sessions, authorization, routing, and data access.
- Preserve the metadata-only dashboard contract: no secret plaintext or
  plaintext repository encryption key is rendered, accepted, persisted, or
  logged.

## Non-goals

- A hosted multi-tenant SaaS dashboard.
- A web secret editor, secret reveal UI, or browser-side secret encryption.
- Customer-specific feature forks or arbitrary CSS/JavaScript injection.
- A Node.js runtime in the production container.
- Replacing the CLI workflows for `set`, `resolve`, `sync`, device approval,
  or key rotation.

## Technical Architecture

### Source and build layout

Create a `frontend/` workspace for the UI source and an embedded asset output
inside the Go server package:

```text
frontend/
  src/
  components/
  lib/
  package.json
  vite.config.ts
internal/server/
  ui/
    dist/                 # Vite build output; embedded by Go
  dashboard.go
  dashboard_assets.go
```

Use React + TypeScript with Vite, Tailwind CSS, and selected shadcn/ui
components. Vite produces content-hashed JavaScript and CSS in
`internal/server/ui/dist`. Go serves those files from `/assets/` and embeds
them with `go:embed`, so the release still ships as one `localenv-server`
binary.

The Dockerfile may use a Node build stage to compile assets. The final runtime
stage contains neither Node nor `node_modules`.

### Rendering model

Keep the existing Go server-rendered routes and auth model. Each protected
route renders a small HTML shell containing page metadata and the root UI
element; the Vite bundle renders the visual interface.

The initial refresh should use the server-rendered metadata already available
to each route, rather than adding broad new browser APIs. Add narrow,
read-only JSON endpoints only where client-side navigation or refresh creates
a real UX need. Such endpoints must reuse the same dashboard session,
organization checks, repository permission checks, rate limits, and response
redaction as their HTML counterparts.

## Visual System

- **Base:** white canvas, near-black text, gray borders and muted surfaces.
- **Accent:** one accessible green token for primary actions and successful
  readiness. Green must not be the only indication of state; use text and an
  icon or badge label as well.
- **Status:** neutral gray for informational state, black/gray for inactive
  state, green for ready/success, and a high-contrast non-green warning/error
  treatment for missing requirements.
- **Typography:** a system font stack; do not require remote font providers.
- **Layout:** persistent desktop sidebar, compact mobile navigation, a narrow
  readable content column, cards for summary metrics, and responsive tables.
- **Motion:** brief, reduced-motion-respecting transitions only.

Tailwind theme tokens should be semantic (`background`, `foreground`,
`border`, `muted`, `success`, `warning`) rather than page-specific colors.
Use shadcn/ui primitives as a controlled local component source, not as a
runtime dependency on an external CDN.

## Page Scope

| Route | UI outcome |
| --- | --- |
| `/setup` | Branded setup flow, clear state messages, organization selection, and safe GitHub handoff. |
| `/repos` | Repository list with readiness summary, managed-key count, open PR count, empty state, and loading/error states where applicable. |
| `/repos/{owner}/{repo}` | Repository overview with summary cards, file mappings, open environment-change PRs, and CLI-only secret guidance. |
| `/repos/{owner}/{repo}/pulls/{number}` | Requirement table with explicit ready/missing states and a visible `localenv resolve` instruction; never a value field. |
| `/devices` | Device identity and repository-key access table with clear active/revoked semantics. |
| `/audit` | Readable timestamped audit table, metadata formatting, and empty state. |
| `/settings` | Instance name, public URL, branding preview, telemetry statement, and no-secret-policy reminder. |

## White-label Rules

- `LOCALENV_DISPLAY_NAME` appears in the title, navigation, setup flow, and
  settings page.
- `LOCALENV_LOGO_URL` and `LOCALENV_FAVICON_URL` are validated configuration,
  not user-controlled dashboard inputs.
- Prefer a text mark when no logo is configured or a logo cannot load.
- Do not permit arbitrary custom CSS, HTML, JavaScript, or customer-supplied
  inline SVG. Branding is limited to the configured name, logo, favicon, and
  a small approved color-token set.
- When an external logo is supported, derive a narrowly scoped `img-src`
  Content-Security-Policy allowlist from its validated HTTPS origin. Do not
  loosen `script-src`, `style-src`, or other CSP directives.

## Security Requirements

- Keep Go responsible for OAuth, signed cookies, CSRF validation, authorization
  checks, and error responses.
- Serve only embedded, hashed same-origin assets with explicit content types,
  immutable caching for hashed files, and no directory listing.
- Keep CSP strict: self-hosted scripts and styles only; no inline scripts or
  inline styles; no CDN JavaScript, CSS, or fonts.
- Treat all repository names, device names, audit metadata, configuration
  values, and URL-derived values as untrusted display data. Continue to escape
  server-rendered content and avoid unsafe HTML rendering in React.
- Do not place OAuth tokens, session values, private keys, ciphertext payloads,
  secret values, or plaintext REKs in the DOM, browser storage, client logs,
  error telemetry, snapshots, or analytics.
- Preserve the existing session expiry, security headers, request limits, and
  same-origin protections. Add focused regression tests before changing any
  of them.

## Delivery Phases

### D1 — Foundation and asset pipeline

1. Add the Vite, React, TypeScript, Tailwind, and shadcn/ui source workspace.
2. Configure production output under `internal/server/ui/dist` and embed it
   with Go.
3. Add `/assets/` serving with cache headers, correct MIME types, and traversal
   protection.
4. Update the multi-stage Docker build and CI to build frontend assets before
   Go compilation.
5. Test a clean build and confirm the final image has no Node runtime.

### D2 — Shared shell and branding

1. Implement the application shell, navigation, mobile layout, typography,
   status badges, tables, cards, empty states, and error presentation.
2. Wire display name, favicon, logo fallback, and the narrowly scoped logo CSP
   behavior.
3. Add visual regression coverage for the shared shell at desktop and mobile
   widths.

### D3 — Repository and PR views

1. Build `/repos`, repository detail, and PR requirement views from existing
   metadata contracts.
2. Make all readiness states understandable without color alone.
3. Verify that no secret value input, value display, or sensitive payload is
   introduced.

### D4 — Devices, audit, settings, and setup

1. Apply the shared system to devices, audit, settings, and setup.
2. Improve dense tables with responsive behavior and empty states.
3. Keep setup forms server-authorized and CSRF-protected; the frontend must
   not bypass the existing GitHub handoff.

### D5 — Hardening and release evidence

1. Run Go unit/integration/security tests and frontend unit/build checks.
2. Add browser coverage for login redirect, authorized/unauthorized dashboard
   access, every dashboard route, mobile navigation, and asset CSP behavior.
3. Scan rendered HTML, browser logs, and API responses using explicit
   non-secret sentinels to prove sensitive values do not appear.
4. Manually test a branded self-hosted instance and a no-branding fallback.
5. Record verification evidence in `docs/v1-progress.md` only when this work
   is scheduled as its own implementation phase.

## Acceptance Criteria

- A fresh Docker build serves the dashboard assets and all listed pages from
  one container.
- The interface is usable at mobile and desktop widths and follows the
  black/white/green visual system.
- A configured company name, logo, and favicon appear safely; absent branding
  has a polished fallback.
- Existing dashboard authorization, CSRF, cookie, and security-header tests
  remain green.
- A browser cannot load an unapproved third-party script, stylesheet, or font.
- The dashboard continues to expose only approved metadata and never accepts
  or displays secret plaintext.
- Go tests, frontend checks, container build, and production-asset smoke tests
  pass before release.

## Open Decisions Before D1

1. Confirm whether the UI should remain server-rendered with progressive React
   islands, or use the same server-authenticated full React shell for all
   dashboard pages. The default recommendation is the full shell with Go
   ownership of the route and data contract.
2. Define the approved optional branding tokens beyond the fixed green accent;
   do not expose free-form CSS.
3. Decide whether external logo URLs remain supported. If yes, enforce HTTPS,
   a single validated origin, and CSP `img-src` allowlisting; otherwise accept
   only a locally served uploaded/admin-provisioned image in a later scoped
   design.
