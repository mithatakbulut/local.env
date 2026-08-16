import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = new URL("..", import.meta.url).pathname;
const output = (path) => join(root, "dist", path);

const docRoutes = [
  "docs/index.html",
  "docs/overview/index.html",
  "docs/self-host/prerequisites/index.html",
  "docs/self-host/verify-your-instance/index.html",
  "docs/join-an-instance/prerequisites/index.html",
  "docs/join-an-instance/verify-your-first-sync/index.html",
  "docs/use-localenv/everyday-cli-workflows/index.html",
  "docs/operate/backup-restore-and-upgrades/index.html",
  "docs/security/security-model/index.html",
  "docs/reference/cli-commands/index.html",
  "docs/reference/environment-variables/index.html",
  "docs/reference/github-app-permissions/index.html"
];

test("build emits the public static routes and custom 404", () => {
  for (const path of ["index.html", "blog/index.html", "rss.xml", "404.html", "sitemap-index.xml", ...docRoutes]) {
    assert.equal(existsSync(output(path)), true, `${path} is emitted`);
  }
});

test("the static header policy is copied to deploy output", () => {
  const headers = readFileSync(output("_headers"), "utf8");
  for (const policy of ["Content-Security-Policy", "base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'", "X-Content-Type-Options: nosniff", "Referrer-Policy", "Permissions-Policy", "max-age=31536000, immutable", "/_localenv/*"]) {
    assert.match(headers, new RegExp(policy.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(headers, /unsafe-inline|https?:\/\//);
});

test("generated static HTML has no remote runtime dependency", () => {
  const pages = ["index.html", "docs/index.html", "docs/overview/index.html", "blog/index.html", "404.html"];
  for (const page of pages) {
    const html = readFileSync(output(page), "utf8");
    assert.doesNotMatch(html, /<(?:script|img)\b[^>]+https?:\/\//i, `${page} contains no remote script or image`);
    assert.doesNotMatch(html, /<link\b(?=[^>]*\brel=["'](?:stylesheet|icon)["'])[^>]+https?:\/\//i, `${page} contains no remote stylesheet or icon`);
    assert.doesNotMatch(html, /<style\b[^>]*>/i, `${page} contains no inline style`);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, `${page} contains no inline script`);
    assert.doesNotMatch(html, /\sstyle=(['"])/i, `${page} contains no inline style attribute`);
  }
});

test("landing page has the required truthful calls to action and local brand assets", () => {
  const landing = readFileSync(output("index.html"), "utf8");
  for (const text of [
    "Keep local development environments in sync",
    "Read the docs",
    "View on GitHub",
    "Open your instance",
    "Apache-2.0 licensed free software",
    "not production, staging, CI, or general-purpose credential storage",
    "display name, logo, and favicon",
    "Synthetic product previews"
  ]) assert.match(landing, new RegExp(text));
  assert.match(landing, /https:\/\/local\.env\.best\/login/);
  assert.match(landing, /\/images\/local-env-asterisk-192\.png/);
  assert.match(landing, /\/images\/local-env-og\.png/);
  assert.doesNotMatch(landing, /<input\b|<textarea\b|<form\b/i);
  assert.doesNotMatch(landing, /D5-NON-SECRET-BROWSER-SENTINEL|EXAMPLE_VALUE_DO_NOT_USE/);
  for (const asset of ["favicon.png", "images/local-env-asterisk-192.png", "images/local-env-asterisk-512.png", "images/local-env-og.png"]) {
    assert.equal(existsSync(output(asset)), true, `${asset} is emitted`);
  }
});

test("documentation uses safe placeholders and excludes sensitive sentinels", () => {
  const pages = docRoutes.filter((path) => path.startsWith("docs/") && path !== "docs/index.html");
  let sawPlaceholder = false;
  for (const page of pages) {
    const html = readFileSync(output(page), "utf8");
    if (/example\.localenv\.test|EXAMPLE_/i.test(html)) sawPlaceholder = true;
    assert.doesNotMatch(html, /D5-NON-SECRET-BROWSER-SENTINEL|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|ghp_[A-Za-z0-9]+/, `${page} must not contain sensitive sentinels`);
  }
  assert.equal(sawPlaceholder, true, "at least one documentation page includes approved placeholder examples");
});

test("landing page journey links point at the documented happy paths", () => {
  const landing = readFileSync(output("index.html"), "utf8");
  assert.match(landing, /\/docs\/self-host\/prerequisites\//);
  assert.match(landing, /\/docs\/join-an-instance\/prerequisites\//);
  assert.match(landing, /\/docs\/security\/security-model\//);
});

test("draft blog content is absent from every generated public output", () => {
  const draftIdentifier = "w1-foundation-draft";
  for (const page of ["blog/index.html", "rss.xml", "sitemap-index.xml"]) {
    assert.doesNotMatch(readFileSync(output(page), "utf8"), new RegExp(draftIdentifier));
  }
  assert.equal(existsSync(output(`blog/${draftIdentifier}/index.html`)), false);
});
