---
title: Configure instance branding
description: Set display name, logo, and favicon for your white-label dashboard.
---

## Goal

Configure the narrow white-label surface local.env supports: display name, logo,
and favicon.

## Preconditions

- A ready instance from
  [create and install the GitHub App](../create-and-install-github-app/).

## Supported branding

| Setting | Variable | Notes |
| --- | --- | --- |
| Display name | `LOCALENV_DISPLAY_NAME` | Shown in titles, navigation, setup, and settings |
| Logo | `LOCALENV_LOGO_URL` | Optional HTTPS URL; text mark fallback when unset or unavailable |
| Favicon | `LOCALENV_FAVICON_URL` | Optional HTTPS URL |

Branding is limited to these three settings. local.env does not support
arbitrary custom CSS, HTML, JavaScript, or customer-supplied inline SVG in
the dashboard.

## Steps

1. Set a display name:

```bash
LOCALENV_DISPLAY_NAME="Example Local Env"
```

2. Optionally set HTTPS logo and favicon URLs hosted on a single validated
   origin, for example:

```bash
LOCALENV_LOGO_URL=https://assets.example.test/localenv-logo.png
LOCALENV_FAVICON_URL=https://assets.example.test/localenv-favicon.png
```

3. Restart the container and open the dashboard to confirm the text mark
   fallback appears when no logo is configured or a logo cannot load.

## Expected result

- The dashboard title and navigation show your configured display name.
- When logo URLs are valid HTTPS links, the dashboard CSP allows only those
  image origins in addition to `'self'`.
- Scripts, styles, and fonts remain same-origin only.

## Verify

Load `/settings` while signed in and confirm the branding preview shows only
the configured name and validated logo/favicon URLs, never secret values.

## Next step

[Verify your instance →](../verify-your-instance/)
