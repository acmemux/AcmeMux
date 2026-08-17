import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { JSDOM } from "jsdom";

import { pages } from "../../site/src/pages.mjs";

const toolDirectory = dirname(fileURLToPath(import.meta.url));
const webDirectory = resolve(toolDirectory, "..");
const applicationDirectory = resolve(webDirectory, "..");
const outputDirectory = join(applicationDirectory, "site/dist");

const failures = [];
const fail = (message) => failures.push(message);

function pageOutput(page) {
  if (page.route === "/") return "index.html";
  if (page.route.endsWith(".html")) return page.route.slice(1);
  return join(page.route.slice(1), "index.html");
}

async function filesBelow(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relativePath = join(prefix, entry.name);
    if (entry.isDirectory()) {
      files.push(
        ...(await filesBelow(join(directory, entry.name), relativePath)),
      );
    } else if (entry.isFile()) {
      files.push(relativePath);
    }
  }
  return files.sort();
}

function meta(document, selector) {
  return (
    document.querySelector(selector)?.getAttribute("content")?.trim() ?? ""
  );
}

function outputForPath(pathname) {
  if (pathname === "/") return "index.html";
  if (pathname.endsWith("/")) return join(pathname.slice(1), "index.html");
  return pathname.slice(1);
}

async function exists(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

const expectedPageFiles = pages.map(pageOutput).sort();
const indexablePages = pages.filter((page) => page.indexable !== false);
const pageDocuments = new Map();
const seenTitles = new Map();
const seenDescriptions = new Map();
const seenCanonicals = new Map();

for (const page of pages) {
  const relativePath = pageOutput(page);
  const html = await readFile(join(outputDirectory, relativePath), "utf8");
  const dom = new JSDOM(html);
  const { document } = dom.window;
  pageDocuments.set(page.route, { document, html });

  if (document.documentElement.lang !== "en")
    fail(`${page.route}: lang must be en`);
  if (document.querySelectorAll("h1").length !== 1)
    fail(`${page.route}: requires exactly one h1`);
  if (!document.querySelector("[data-dogfood-dock]"))
    fail(`${page.route}: dogfood dock is missing`);
  if (!document.querySelector("[data-dock-toggle][aria-expanded='false']")) {
    fail(`${page.route}: dogfood dock must build collapsed`);
  }
  if (!document.querySelector("[data-dock-panel][hidden]")) {
    fail(`${page.route}: dogfood panel must build hidden`);
  }

  const title = document.title.trim();
  const description = meta(document, "meta[name='description']");
  const canonical = document.querySelector("link[rel='canonical']")?.href ?? "";
  const expectedCanonical = `https://acmemux.com${page.route}`;
  if (!title || title.length > 60)
    fail(`${page.route}: title must be 1-60 characters`);
  if (!description || description.length > 155) {
    fail(`${page.route}: description must be 1-155 characters`);
  }
  if (canonical !== expectedCanonical)
    fail(`${page.route}: canonical is not ${expectedCanonical}`);
  for (const [value, collection, kind] of [
    [title, seenTitles, "title"],
    [description, seenDescriptions, "description"],
    [canonical, seenCanonicals, "canonical"],
  ]) {
    if (collection.has(value))
      fail(
        `${page.route}: duplicate ${kind} also used by ${collection.get(value)}`,
      );
    collection.set(value, page.route);
  }

  const requiredMeta = [
    ["meta[property='og:type']", "og:type"],
    ["meta[property='og:site_name']", "og:site_name"],
    ["meta[property='og:title']", "og:title"],
    ["meta[property='og:description']", "og:description"],
    ["meta[property='og:url']", "og:url"],
    ["meta[property='og:image']", "og:image"],
    ["meta[property='og:image:alt']", "og:image:alt"],
    ["meta[name='twitter:card']", "twitter:card"],
    ["meta[name='twitter:title']", "twitter:title"],
    ["meta[name='twitter:description']", "twitter:description"],
    ["meta[name='twitter:image']", "twitter:image"],
    ["meta[name='twitter:image:alt']", "twitter:image:alt"],
  ];
  for (const [selector, name] of requiredMeta) {
    if (!meta(document, selector)) fail(`${page.route}: ${name} is missing`);
  }
  if (meta(document, "meta[property='og:url']") !== expectedCanonical) {
    fail(`${page.route}: og:url does not match canonical`);
  }

  const schemas = [
    ...document.querySelectorAll("script[type='application/ld+json']"),
  ];
  if (schemas.length !== 1) fail(`${page.route}: requires one JSON-LD graph`);
  for (const schema of schemas) {
    try {
      const value = JSON.parse(schema.textContent);
      if (
        value["@context"] !== "https://schema.org" ||
        !Array.isArray(value["@graph"])
      ) {
        fail(`${page.route}: JSON-LD must use a schema.org graph`);
        continue;
      }
      const types = value["@graph"].map((entry) => entry["@type"]);
      if (!types.includes("Organization") || !types.includes("WebSite")) {
        fail(`${page.route}: JSON-LD lacks Organization or WebSite`);
      }
      if (
        page.route !== "/" &&
        page.indexable !== false &&
        !types.includes("BreadcrumbList")
      ) {
        fail(`${page.route}: JSON-LD lacks BreadcrumbList`);
      }
      if (page.kind === "article" && !types.includes("Article")) {
        fail(`${page.route}: article JSON-LD is missing`);
      }
    } catch (error) {
      fail(`${page.route}: invalid JSON-LD (${error.message})`);
    }
  }

  const robots = meta(document, "meta[name='robots']");
  if (page.indexable === false) {
    if (!robots.includes("noindex"))
      fail(`${page.route}: non-indexable page lacks noindex`);
  } else if (robots.includes("noindex")) {
    fail(`${page.route}: indexable page unexpectedly has noindex`);
  }

  const currentLinks = document.querySelectorAll(
    "[data-site-nav] a[aria-current='page']",
  );
  if (page.nav && currentLinks.length !== 1)
    fail(`${page.route}: must have one current navigation link`);
  if (!page.nav && currentLinks.length !== 0)
    fail(`${page.route}: must not inherit a current navigation link`);

  for (const element of document.querySelectorAll(
    "a[href], img[src], script[src], link[rel='stylesheet'][href], link[rel='icon'][href], link[rel='manifest'][href]",
  )) {
    const attribute = element.hasAttribute("href") ? "href" : "src";
    const value = element.getAttribute(attribute);
    if (!value || value === "#") {
      fail(`${page.route}: empty ${attribute}`);
      continue;
    }
    const url = new URL(value, expectedCanonical);
    if (url.origin !== "https://acmemux.com") {
      if (element.tagName !== "A") {
        fail(`${page.route}: external asset is not allowed: ${value}`);
      } else if (url.protocol !== "https:") {
        fail(`${page.route}: external URL is not HTTPS: ${value}`);
      }
      continue;
    }
    const target = outputForPath(url.pathname);
    if (!(await exists(join(outputDirectory, target)))) {
      fail(`${page.route}: unresolved internal ${attribute} ${value}`);
      continue;
    }
    if (url.hash && extname(target) === ".html") {
      const targetHtml = await readFile(join(outputDirectory, target), "utf8");
      const targetDocument = new JSDOM(targetHtml).window.document;
      if (
        !targetDocument.getElementById(decodeURIComponent(url.hash.slice(1)))
      ) {
        fail(`${page.route}: unresolved fragment ${value}`);
      }
    }
  }

  const reminderForms = document.querySelectorAll("form[data-reminder-form]");
  if (reminderForms.length !== 1) {
    fail(`${page.route}: requires exactly one reminder form`);
  } else {
    const action = new URL(
      reminderForms[0].getAttribute("action"),
      expectedCanonical,
    );
    if (
      action.origin !== "https://acmemux.com" ||
      action.pathname !== "/api/renewal-alerts/subscriptions"
    ) {
      fail(
        `${page.route}: reminder form action is outside the public allowlist`,
      );
    }
  }
}

const sitemap = new JSDOM(
  await readFile(join(outputDirectory, "sitemap.xml"), "utf8"),
  {
    contentType: "application/xml",
  },
).window.document;
const sitemapUrls = [...sitemap.querySelectorAll("loc")].map((node) =>
  node.textContent.trim(),
);
const expectedUrls = indexablePages.map(
  (page) => `https://acmemux.com${page.route}`,
);
if (JSON.stringify(sitemapUrls) !== JSON.stringify(expectedUrls)) {
  fail("sitemap routes or order do not match the indexable page manifest");
}
if (sitemapUrls.includes("https://acmemux.com/404.html"))
  fail("404 appears in sitemap");

const robots = await readFile(join(outputDirectory, "robots.txt"), "utf8");
if (
  !robots.includes("Allow: /") ||
  !robots.includes("Sitemap: https://acmemux.com/sitemap.xml")
) {
  fail("robots.txt does not allow the site and name the canonical sitemap");
}

const manifest = JSON.parse(
  await readFile(join(outputDirectory, "site.webmanifest"), "utf8"),
);
if (manifest.name !== "AcmeMux" || manifest.start_url !== "/")
  fail("web manifest identity is invalid");
for (const icon of manifest.icons ?? []) {
  if (!(await exists(join(outputDirectory, outputForPath(icon.src))))) {
    fail(`web manifest icon does not exist: ${icon.src}`);
  }
}

const buildManifest = JSON.parse(
  await readFile(join(outputDirectory, "BUILD.json"), "utf8"),
);
const emittedFiles = (await filesBelow(outputDirectory)).filter(
  (path) => path !== "BUILD.json",
);
const manifestedFiles = buildManifest.files.map((entry) => entry.path).sort();
if (JSON.stringify(emittedFiles) !== JSON.stringify(manifestedFiles)) {
  fail("BUILD.json does not enumerate the exact emitted package");
}
for (const entry of buildManifest.files) {
  const contents = await readFile(join(outputDirectory, entry.path));
  const digest = createHash("sha256").update(contents).digest("hex");
  if (digest !== entry.sha256 || contents.length !== entry.size) {
    fail(`BUILD.json hash or size mismatch: ${entry.path}`);
  }
}
for (const pageFile of expectedPageFiles) {
  if (!manifestedFiles.includes(pageFile))
    fail(`built page absent from BUILD.json: ${pageFile}`);
}

const packageText = (
  await Promise.all(
    emittedFiles
      .filter((path) => ![".png"].includes(extname(path)))
      .map((path) => readFile(join(outputDirectory, path), "utf8")),
  )
).join("\n");
for (const [pattern, message] of [
  [/@certleap\.net/i, "legacy CertLeap email"],
  [/sgurden@/i, "legacy personal email"],
  [/signed release artifacts?/i, "unsupported signed release claim"],
  [
    /AcmeMux (?:deploys|activates) (?:the |your )?certificates?/i,
    "AcmeMux-owned deployment claim",
  ],
  [
    /(?:google-analytics|googletagmanager|plausible\.io|segment\.com|hotjar)/i,
    "tracking service",
  ],
  [
    /(?:sk_live_|AKIA[0-9A-Z]{16}|BEGIN (?:RSA |EC )?PRIVATE KEY)/,
    "credential-like content",
  ],
  [/\/(?:api\/v1|admin\/api)\b/i, "private administration API path"],
]) {
  if (pattern.test(packageText)) fail(`built package contains ${message}`);
}
if (!packageText.includes("Current foundation - pre-release"))
  fail("current pre-release state label is missing");
if (!packageText.includes("Long-term direction"))
  fail("long-term direction label is missing");
if (!packageText.includes("Debian 13 amd64"))
  fail("current platform boundary is missing");
if (!packageText.includes("GitHub private vulnerability reporting")) {
  fail("private vulnerability reporting route is not explained");
}
if (!packageText.includes("No product or website telemetry"))
  fail("no-telemetry statement is missing");
if (!packageText.includes("separate") || !packageText.includes("activation")) {
  fail("separate certificate activation boundary is missing");
}

const siteJavaScript = await readFile(
  join(outputDirectory, "assets/site.js"),
  "utf8",
);
const siteStyles = await readFile(
  join(outputDirectory, "assets/styles.css"),
  "utf8",
);
if (/(?:@import|url\(\s*["']?(?:https?:)?\/\/)/i.test(siteStyles)) {
  fail("site CSS contains an external import or asset URL");
}
if (!siteJavaScript.includes('"/certificate-status.json"'))
  fail("status feed fetch is missing");
if (!siteJavaScript.includes("reminderForm.action"))
  fail("same-origin reminder submission is missing");
if (/https?:\/\//.test(siteJavaScript))
  fail("site JavaScript contains an absolute network destination");
if ((siteJavaScript.match(/\bfetch\s*\(/g) ?? []).length !== 1) {
  fail(
    "site JavaScript must route its only fetch primitive through the timeout helper",
  );
}
if ((siteJavaScript.match(/\bfetchWithin\s*\(/g) ?? []).length !== 3) {
  fail("site JavaScript has a network call outside the two public contracts");
}
if (
  /(?:XMLHttpRequest|sendBeacon|WebSocket|EventSource)/.test(siteJavaScript)
) {
  fail("site JavaScript contains a non-allowlisted network primitive");
}

const totalSize = buildManifest.files.reduce(
  (sum, entry) => sum + entry.size,
  0,
);
if (totalSize > 1_500_000)
  fail(`site package exceeds 1.5 MB (${totalSize} bytes)`);

try {
  const packageData = JSON.parse(
    execFileSync("go", ["list", "-json", "./internal/webassets"], {
      cwd: applicationDirectory,
      encoding: "utf8",
    }),
  );
  if (
    JSON.stringify(packageData.EmbedPatterns) !== JSON.stringify(["all:dist"])
  ) {
    fail("admin embed pattern changed from its package-local dist boundary");
  }
  for (const file of packageData.EmbedFiles ?? []) {
    if (!file.startsWith("dist/") || /(?:site|public|marketing)/i.test(file)) {
      fail(`public site entered the admin embed boundary: ${file}`);
    }
  }
} catch (error) {
  fail(`could not verify the admin embed boundary: ${error.message}`);
}

if (await exists(join(webDirectory, "dist/index.html"))) {
  const adminFiles = await filesBelow(join(webDirectory, "dist"));
  const adminText = (
    await Promise.all(
      adminFiles
        .filter((path) => [".html", ".js", ".css"].includes(extname(path)))
        .map((path) => readFile(join(webDirectory, "dist", path), "utf8")),
    )
  ).join("\n");
  if (adminText.includes("See the whole lifecycle ahead")) {
    fail("public website content entered the embedded administration bundle");
  }
}

if (failures.length > 0) {
  console.error(`Public site static verification failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(
    `Verified ${pages.length} pages, ${emittedFiles.length} package files, and the native embed boundary (${totalSize} bytes).`,
  );
}
