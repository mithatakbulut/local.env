import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const docsCss = readFileSync(new URL("../src/styles/docs.css", import.meta.url), "utf8");

test("docs header keeps utility controls out of the site-title column", () => {
  assert.match(
    docsCss,
    /\.header > \.right-group\s*\{[^}]*margin-inline-start:\s*auto;/s
  );
  assert.match(
    docsCss,
    /@media \(min-width: 50rem\)[\s\S]*\.header > \.title-wrapper\s*\{[^}]*grid-column:\s*1;[^}]*\}[\s\S]*\.header > \.right-group\s*\{[^}]*grid-column:\s*3;[^}]*justify-self:\s*end;/s
  );
});
