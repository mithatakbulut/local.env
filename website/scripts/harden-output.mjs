import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

const dist = new URL("../dist/", import.meta.url);
const assetDirectory = new URL("_localenv/", dist);
const attributeStyles = new Map();

const digest = (content) => createHash("sha256").update(content).digest("hex").slice(0, 16);

async function htmlFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return htmlFiles(path);
    return entry.isFile() && entry.name.endsWith(".html") ? [path] : [];
  }));
  return files.flat();
}

async function writeAsset(extension, content) {
  const filename = `inline-${digest(content)}.${extension}`;
  await writeFile(new URL(filename, assetDirectory), content, "utf8");
  return `/_localenv/${filename}`;
}

function withClass(attributes, className) {
  const classMatch = attributes.match(/\sclass=(['"])(.*?)\1/i);
  if (!classMatch) return `${attributes} class="${className}"`;
  return attributes.replace(classMatch[0], ` class=${classMatch[1]}${classMatch[2]} ${className}${classMatch[1]}`);
}

await mkdir(assetDirectory, { recursive: true });
const files = await htmlFiles(dist.pathname);

for (const file of files) {
  let html = await readFile(file, "utf8");

  html = await replaceAsync(html, /<script(\s[^>]*)?>([\s\S]*?)<\/script>/gi, async (match, attributes = "", content) => {
    if (/\ssrc\s*=/i.test(attributes)) return match;
    const source = await writeAsset("js", content);
    return `<script${attributes} src="${source}"></script>`;
  });

  const extractedStyles = [];
  html = await replaceAsync(html, /<style(\s[^>]*)?>([\s\S]*?)<\/style>/gi, async (_match, _attributes = "", content) => {
    extractedStyles.push(await writeAsset("css", content));
    return "";
  });
  if (extractedStyles.length > 0) {
    const links = extractedStyles.map((source) => `<link rel="stylesheet" href="${source}">`).join("");
    html = html.includes("</head>") ? html.replace("</head>", `${links}</head>`) : `${links}${html}`;
  }

  html = html.replace(/\sstyle=(['"])(.*?)\1/gi, (_match, _quote, declarations) => {
    const className = `localenv-style-${digest(declarations)}`;
    attributeStyles.set(className, declarations);
    return ` data-localenv-style="${className}"`;
  });

  await writeFile(file, html, "utf8");
}

if (attributeStyles.size > 0) {
  const css = [...attributeStyles].map(([className, declarations]) => `.${className}{${declarations}}`).join("\n");
  const source = await writeAsset("css", css);
  for (const file of files) {
    let html = await readFile(file, "utf8");
    html = html.replace(/(<[^>]*?)\sdata-localenv-style=(['"])(.*?)\2/gi, (_match, tagStart, _quote, className) => withClass(tagStart, className));
    html = html.replace("</head>", `<link rel="stylesheet" href="${source}"></head>`);
    await writeFile(file, html, "utf8");
  }
}

process.stdout.write(`Hardened ${files.length} HTML files with same-origin assets in ${relative(process.cwd(), assetDirectory.pathname)}.\n`);

async function replaceAsync(input, expression, replacer) {
  const matches = [...input.matchAll(expression)];
  if (matches.length === 0) return input;
  const replacements = await Promise.all(matches.map((match) => replacer(...match)));
  let output = input;
  for (let index = matches.length - 1; index >= 0; index -= 1) {
    const match = matches[index];
    output = `${output.slice(0, match.index)}${replacements[index]}${output.slice(match.index + match[0].length)}`;
  }
  return output;
}
