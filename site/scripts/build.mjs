import { createHash } from "node:crypto";
import { cp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { pages } from "../src/pages.mjs";
import { renderPage } from "../src/render.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const siteDirectory = resolve(scriptDirectory, "..");
const applicationDirectory = resolve(siteDirectory, "..");
const sourceDirectory = join(siteDirectory, "src");
const finalOutputDirectory = join(siteDirectory, "dist");
const outputDirectory = join(siteDirectory, ".dist-build");

const assetCopies = [
  [join(sourceDirectory, "styles.css"), "assets/styles.css"],
  [join(sourceDirectory, "site.js"), "assets/site.js"],
  [join(sourceDirectory, "favicon.svg"), "favicon.svg"],
  [join(sourceDirectory, "social-card.png"), "assets/social-card.png"],
  [
    join(
      applicationDirectory,
      "web/tests/visual.spec.ts-snapshots/application-shell-wide-linux.png",
    ),
    "assets/acmemux-application.png",
  ],
];

async function write(relativePath, contents) {
  const destination = join(outputDirectory, relativePath);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, contents, "utf8");
}

function pageOutput(page) {
  if (page.route === "/") return "index.html";
  if (page.route.endsWith(".html")) return page.route.slice(1);
  return join(page.route.slice(1), "index.html");
}

function sitemap() {
  const entries = pages
    .filter((page) => page.indexable !== false)
    .map(
      (page) =>
        `  <url><loc>https://acmemux.com${page.route}</loc><changefreq>${
          page.kind === "article" ? "monthly" : "weekly"
        }</changefreq></url>`,
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries}\n</urlset>\n`;
}

async function buildManifest() {
  const files = [];
  async function add(relativePath) {
    const contents = await readFile(join(outputDirectory, relativePath));
    files.push({
      path: relativePath,
      sha256: createHash("sha256").update(contents).digest("hex"),
      size: contents.length,
    });
  }

  for (const page of pages) await add(pageOutput(page));
  for (const [, destination] of assetCopies) await add(destination);
  for (const path of ["robots.txt", "sitemap.xml", "site.webmanifest"]) {
    await add(path);
  }
  files.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  await write(
    "BUILD.json",
    `${JSON.stringify(
      {
        canonicalOrigin: "https://acmemux.com",
        files,
        format: 1,
      },
      null,
      2,
    )}\n`,
  );
}

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

for (const page of pages) await write(pageOutput(page), renderPage(page));
for (const [source, destination] of assetCopies) {
  const target = join(outputDirectory, destination);
  await mkdir(dirname(target), { recursive: true });
  await cp(source, target);
}

await write(
  "robots.txt",
  "User-agent: *\nAllow: /\n\nSitemap: https://acmemux.com/sitemap.xml\n",
);
await write("sitemap.xml", sitemap());
await write(
  "site.webmanifest",
  `${JSON.stringify(
    {
      background_color: "#071015",
      description:
        "AcmeMux is a self-hosted control plane for upstream lego certificate operations.",
      display: "standalone",
      icons: [
        {
          sizes: "any",
          src: "/favicon.svg",
          type: "image/svg+xml",
        },
      ],
      name: "AcmeMux",
      short_name: "AcmeMux",
      start_url: "/",
      theme_color: "#071015",
    },
    null,
    2,
  )}\n`,
);
await buildManifest();

await rm(finalOutputDirectory, { recursive: true, force: true });
await rename(outputDirectory, finalOutputDirectory);

const relativeOutput = relative(applicationDirectory, finalOutputDirectory);
console.log(`Built ${pages.length} pages in ${relativeOutput}`);
