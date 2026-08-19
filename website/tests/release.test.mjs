import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const websiteRoot = new URL("..", import.meta.url).pathname;
const repoRoot = join(websiteRoot, "..");
const output = (path) => join(websiteRoot, "dist", path);

test("release workflow publishes signed archives and a multi-platform GHCR image", () => {
  const release = readFileSync(join(repoRoot, ".github/workflows/release.yml"), "utf8");

  for (const expected of [
    "packages: write",
    "^v[0-9]+\\.[0-9]+\\.[0-9]+$",
    "checksums.txt.bundle",
    "cosign sign-blob",
    "docker/login-action@v3",
    "docker/build-push-action@v6",
    "linux/amd64,linux/arm64",
    "ghcr.io/${{ github.repository }}",
    "container-image-digest.txt"
  ]) {
    assert.equal(release.includes(expected), true, `release workflow contains ${expected}`);
  }

  assert.doesNotMatch(release, /ghcr\.io\/localenv\/localenv/);
});

test("local secret material is excluded from Git and Docker build contexts", () => {
  const gitignore = readFileSync(join(repoRoot, ".gitignore"), "utf8").split(/\r?\n/);
  const dockerignore = readFileSync(join(repoRoot, ".dockerignore"), "utf8").split(/\r?\n/);

  for (const pattern of [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx"]) {
    assert.equal(gitignore.includes(pattern), true, `.gitignore contains ${pattern}`);
    assert.equal(dockerignore.includes(pattern), true, `.dockerignore contains ${pattern}`);
  }

  assert.equal(gitignore.includes("!.env.example"), true);
});

test("self-hosting docs use the release image owned by this repository", () => {
  const deploy = readFileSync(output("docs/self-host/deploy-with-docker/index.html"), "utf8");
  assert.match(deploy, /ghcr\.io\/mithatakbulut\/local\.env/);
  assert.match(deploy, /container-image-digest\.txt/);
  assert.match(deploy, /127\.0\.0\.1:8080\/healthz/);
  assert.doesNotMatch(deploy, /ghcr\.io\/localenv\/localenv/);
});
