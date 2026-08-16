---
title: "The dashboard is supposed to be a little boring"
description: "local.env keeps secret work in the CLI on purpose. The public docs, the white-label dashboard, and even the landing-page previews follow from that choice."
pubDate: 2026-08-16
draft: false
---

Some environment tools offer browser-based editing. local.env makes a
different trade-off: managed values are handled on the developer machine by
the CLI. The website and dashboard support that workflow without becoming a
secret store in the browser.

## Two journeys, one boundary

The public docs now split the product into the two jobs people actually have:

- [I run an instance](/docs/self-host/prerequisites/): Docker, a public
  HTTPS URL, a bootstrap GitHub OAuth App, the company-owned GitHub App, and
  a narrow branding surface.
- [I join an instance](/docs/join-an-instance/prerequisites/): install the
  CLI, sign in, register a device, initialize a repository, resolve a pull
  request, and sync a marker-bounded block into `.env.local`.

Those pages live on this site so they remain readable when a particular
self-hosted instance, or its tunnel, is down. They are not a control plane
for anyone else’s secrets.

## What the dashboard is allowed to know

The bundled dashboard is an operational view. It can show that
`demo-lab/api` has a missing pull-request requirement, that two devices are
active, or that the instance display name is set. It cannot accept a value,
reveal a value, or hold a plaintext repository encryption key.

This means the dashboard is intentionally not a browser-based editor.
Encryption, device wrapping, and dotenv writes stay in `localenv`; the server
coordinates ciphertext and metadata. A value-input field would give the
browser a job the security model explicitly excludes.

White-labeling follows the same restraint. An operator can set a display
name, logo, and favicon. They cannot inject CSS or JavaScript. A company
should look like itself on a page that still cannot see its secrets.

