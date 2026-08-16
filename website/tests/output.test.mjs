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
  const pages = ["index.html", "docs/index.html", "docs/overview/index.html", "blog/index.html", "blog/localenv-security-model/index.html", "404.html"];
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
  const stylesheets = [...landing.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*>/gi)].map((match) => {
    const href = match[0].match(/href="(\/_astro\/[^"]+\.css)"/);
    return href ? readFileSync(output(href[1].slice(1)), "utf8") : "";
  }).join("\n");
  assert.match(stylesheets, /Outfit Variable/);
  assert.match(stylesheets, /Figtree Variable/);
  assert.match(stylesheets, /url\([^)]+\.woff2\)/);
  assert.doesNotMatch(stylesheets, /https?:\/\/fonts\./);
  assert.doesNotMatch(stylesheets, /Source Serif 4/);
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

test("documentation uses the landing-page palette and defaults to dark", () => {
  const docs = readFileSync(output("docs/overview/index.html"), "utf8");
  assert.match(docs, /data-theme="dark"/);
  assert.match(docs, /<option[^>]*value="dark"[^>]*selected/);
  const stylesheets = [...docs.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*>/gi)].map((match) => {
    const href = match[0].match(/href="(\/_astro\/[^"]+\.css)"/);
    return href ? readFileSync(output(href[1].slice(1)), "utf8") : "";
  }).join("\n");
  for (const token of ["#101311", "#171b18", "#b9f957", "#172004", "#a9baff", "#ffe08b", "Outfit Variable", "Figtree Variable"]) {
    assert.match(stylesheets, new RegExp(token.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")));
  }
  const scripts = [...docs.matchAll(/<script\b[^>]*src="([^"]+)"/gi)].map((match) => readFileSync(output(match[1].slice(1)), "utf8")).join("\n");
  assert.match(scripts, /starlight-theme/);
  assert.match(scripts, /: "dark"/);
  assert.doesNotMatch(scripts, /prefers-color-scheme: light'\)\.matches \? 'light' : 'dark'/);
});

test("landing page journey links point at the documented happy paths", () => {
  const landing = readFileSync(output("index.html"), "utf8");
  assert.match(landing, /\/docs\/self-host\/prerequisites\//);
  assert.match(landing, /\/docs\/join-an-instance\/prerequisites\//);
  assert.match(landing, /\/docs\/security\/security-model\//);
});

test("published blog posts and RSS exclude drafts", () => {
  const draftIdentifier = "w1-foundation-draft";
  const published = [
    "blog/public-docs-and-metadata-only-dashboard/index.html",
    "blog/for-the-curious-algorithms-and-cryptography/index.html",
    "blog/localenv-security-model/index.html"
  ];
  for (const path of published) {
    assert.equal(existsSync(output(path)), true, `${path} is emitted`);
  }
  const rss = readFileSync(output("rss.xml"), "utf8");
  const index = readFileSync(output("blog/index.html"), "utf8");
  for (const page of ["blog/index.html", "rss.xml", "sitemap-index.xml"]) {
    assert.doesNotMatch(readFileSync(output(page), "utf8"), new RegExp(draftIdentifier));
  }
  assert.equal(existsSync(output(`blog/${draftIdentifier}/index.html`)), false);
  assert.match(index, /The dashboard is supposed to be a little boring/);
  assert.match(index, /For the curious: how algorithms and cryptography do different jobs/);
  assert.match(index, /How are secrets protected before they ever reach the server/);
  assert.match(rss, /\/blog\/for-the-curious-algorithms-and-cryptography\//);
  assert.match(rss, /\/blog\/localenv-security-model\//);
  assert.doesNotMatch(rss, new RegExp(draftIdentifier));
  assert.doesNotMatch(index, /No active advisory/);
  assert.doesNotMatch(rss, /No active advisory/);
  assert.doesNotMatch(index, /Release notes/);
  assert.doesNotMatch(index, /Security advisory/);
  assert.doesNotMatch(index, /Product updates/);
  assert.doesNotMatch(index, /v1\.0\.1: corrected release verification artifacts/);
  assert.doesNotMatch(rss, /\/blog\/v1-0-1-signed-release-artifacts\//);
  assert.equal(existsSync(output("blog/advisory-process-no-active-advisory/index.html")), false);
  assert.equal(existsSync(output("blog/v1-0-1-signed-release-artifacts/index.html")), false);
  assert.equal(existsSync(output("blog/category/release-notes/index.html")), false);
  assert.equal(existsSync(output("blog/category/security-advisory/index.html")), false);
  assert.equal(existsSync(output("blog/category/product-update/index.html")), false);
  assert.match(readFileSync(output("docs/security/security-advisories/index.html"), "utf8"), /Our publication process/);
  const curiousPost = readFileSync(output("blog/for-the-curious-algorithms-and-cryptography/index.html"), "utf8");
  assert.match(curiousPost, /XChaCha20-Poly1305/);
  assert.match(curiousPost, /age X25519/);
  assert.match(curiousPost, /not production, staging, CI, or\s+general-purpose credential storage/);
  const securityPost = readFileSync(output("blog/localenv-security-model/index.html"), "utf8");
  assert.equal([...securityPost.matchAll(/<figure class="diagram">/g)].length, 8);
  assert.equal([...securityPost.matchAll(/<svg\b[^>]*\bid="mermaid-/g)].length, 8);
  assert.doesNotMatch(securityPost, /language-mermaid/);
  assert.doesNotMatch(index, /D5-NON-SECRET-BROWSER-SENTINEL|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|ghp_/);
});
