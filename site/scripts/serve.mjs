import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = resolve(scriptDirectory, "../dist");
const port = Number.parseInt(process.env.ACMEMUX_SITE_PORT ?? "4174", 10);

const types = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webmanifest", "application/manifest+json; charset=utf-8"],
  [".xml", "application/xml; charset=utf-8"],
]);

const fixtureStatus = JSON.stringify({
  estimateBasis:
    "Expected public replacement window from dogfood schedule evidence.",
  expiresAt: "2026-11-15T01:05:34Z",
  fingerprintSha256:
    "3564029b1580f99ed3b91d8a9c2160ba33260cda00955812ed95eefc74e8cbe7",
  issuedAt: "2026-08-17T01:05:35Z",
  lastDeployedAt: "2026-08-17T03:20:35Z",
  managedBy: "AcmeMux",
  nextRenewalAt: "2026-08-20T09:35:00Z",
  profile: "Classic Let's Encrypt profile",
});

function resolveRequest(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  let relativePath = decoded.replace(/^\/+/, "");
  if (!relativePath || decoded.endsWith("/")) relativePath += "index.html";
  const candidate = normalize(join(outputDirectory, relativePath));
  if (
    candidate !== outputDirectory &&
    !candidate.startsWith(`${outputDirectory}${sep}`)
  ) {
    return null;
  }
  return candidate;
}

const server = createServer(async (request, response) => {
  let url;
  try {
    url = new URL(
      request.url ?? "/",
      `http://${request.headers.host ?? "127.0.0.1"}`,
    );
  } catch {
    response.writeHead(400);
    response.end("Bad request");
    return;
  }
  if (url.pathname === "/certificate-status.json") {
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { Allow: "GET, HEAD" });
      response.end("Method not allowed");
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
    });
    response.end(request.method === "HEAD" ? undefined : fixtureStatus);
    return;
  }
  if (url.pathname === "/api/renewal-alerts/subscriptions") {
    if (request.method !== "POST") {
      response.writeHead(405, { Allow: "POST" });
      response.end("Method not allowed");
      return;
    }
    if (
      request.headers["content-type"]?.split(";", 1)[0] !== "application/json"
    ) {
      response.writeHead(415);
      response.end("JSON required");
      return;
    }
    let body = "";
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 8192) {
        response.writeHead(413);
        response.end("Request too large");
        return;
      }
    }
    let value;
    try {
      value = JSON.parse(body);
    } catch {
      response.writeHead(400);
      response.end("Invalid JSON");
      return;
    }
    if (
      !value ||
      typeof value.email !== "string" ||
      value.email.length > 254 ||
      !value.email.includes("@") ||
      typeof value.website !== "string" ||
      value.website.length > 1024
    ) {
      response.writeHead(400);
      response.end("Invalid request");
      return;
    }
    response.writeHead(202, {
      "Content-Type": "application/json; charset=utf-8",
    });
    response.end(
      JSON.stringify({
        message: "Check your inbox and confirm the one-time reminder.",
      }),
    );
    return;
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" });
    response.end("Method not allowed");
    return;
  }

  const path = resolveRequest(url.pathname);
  if (!path) {
    response.writeHead(400);
    response.end("Bad request");
    return;
  }
  try {
    const details = await stat(path);
    if (!details.isFile()) throw new Error("not a file");
    response.writeHead(200, {
      "Content-Type": types.get(extname(path)) ?? "application/octet-stream",
    });
    if (request.method === "HEAD") response.end();
    else createReadStream(path).pipe(response);
  } catch {
    const notFound = join(outputDirectory, "404.html");
    response.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
    createReadStream(notFound).pipe(response);
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`AcmeMux public site preview: http://127.0.0.1:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
