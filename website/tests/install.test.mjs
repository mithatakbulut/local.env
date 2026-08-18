import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = new URL("..", import.meta.url).pathname;
const output = (path) => join(root, "dist", path);

test("build emits a syntax-valid verified installer", () => {
  const installerPath = output("install.sh");
  assert.equal(existsSync(installerPath), true, "install.sh is emitted");

  const syntax = spawnSync("sh", ["-n", installerPath], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr || "installer must pass sh -n");

  const installer = readFileSync(installerPath, "utf8");
  for (const required of [
    'REPO="mithatakbulut/local.env"',
    "/releases/latest",
    "checksums.txt.bundle",
    "cosign verify-blob",
    "--certificate-identity",
    "--certificate-oidc-issuer",
    "sha256sum",
    "shasum -a 256",
    "LOCALENV_INSTALL_DIR",
    "LOCALENV_VERSION",
    ".local/bin"
  ]) {
    assert.equal(installer.includes(required), true, `installer contains ${required}`);
  }

  assert.doesNotMatch(installer, /\bsudo\b/);
  assert.doesNotMatch(installer, /http:\/\//);
});

test("install documentation points developers at the canonical installer", () => {
  const docs = readFileSync(output("docs/join-an-instance/install-the-cli/index.html"), "utf8");
  assert.match(docs, /curl -fsSL https:\/\/local\.env\.best\/install\.sh \| sh/);
  assert.match(docs, /Sigstore/);
  assert.match(docs, /LOCALENV_INSTALL_DIR/);
  assert.match(docs, /LOCALENV_VERSION/);
  assert.match(docs, /Update now\? \[y\/N\]/);
});
