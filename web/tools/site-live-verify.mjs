import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, posix, resolve } from "node:path";
import { connect } from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";

const toolDirectory = dirname(fileURLToPath(import.meta.url));
const webDirectory = resolve(toolDirectory, "..");
const applicationDirectory = resolve(webDirectory, "..");
const outputDirectory = join(applicationDirectory, "site/dist");
const requestTimeoutMilliseconds = 15_000;

class VerificationError extends Error {}

function fail(message) {
  throw new VerificationError(message);
}

function requestPath(input) {
  try {
    return new URL(String(input)).pathname || "/";
  } catch {
    return "request";
  }
}

export function formatFailure(error) {
  return error instanceof VerificationError
    ? error.message
    : "live verification could not complete";
}

function requireValue(condition, message) {
  if (!condition) fail(message);
}

function usage() {
  return [
    "Usage: node tools/site-live-verify.mjs [--origin URL] [--package-only]",
    "",
    "The default performs the complete read-only production verification at",
    "https://acmemux.com. --package-only is restricted to a loopback origin",
    "and verifies exact package bytes, statuses, and content types.",
  ].join("\n");
}

export function options(arguments_) {
  let origin = "https://acmemux.com";
  let packageOnly = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--help") {
      console.log(usage());
      process.exit(0);
    }
    if (argument === "--package-only") {
      packageOnly = true;
      continue;
    }
    if (argument === "--origin") {
      origin = arguments_[index + 1] ?? "";
      index += 1;
      continue;
    }
    fail("unknown argument");
  }

  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    fail("--origin must be an absolute URL");
  }
  requireValue(
    !parsed.username && !parsed.password,
    "--origin must not contain credentials",
  );
  requireValue(
    parsed.pathname === "/" && !parsed.search && !parsed.hash,
    "--origin must not contain a path, query, or fragment",
  );
  if (packageOnly) {
    requireValue(
      ["127.0.0.1", "[::1]", "::1", "localhost"].includes(parsed.hostname),
      "--package-only is restricted to a loopback origin",
    );
    requireValue(
      parsed.protocol === "http:" || parsed.protocol === "https:",
      "--package-only requires HTTP or HTTPS",
    );
  } else {
    requireValue(
      parsed.href === "https://acmemux.com/",
      "complete verification is restricted to https://acmemux.com",
    );
  }
  return { origin: parsed.origin, packageOnly };
}

async function fetchBounded(input, init, consume, timeoutMilliseconds) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMilliseconds);
  try {
    const response = await fetch(input, {
      ...init,
      headers: {
        Accept: "*/*",
        "User-Agent": "AcmeMux-live-verifier/1",
        ...init.headers,
      },
      redirect: "manual",
      signal: controller.signal,
    });
    return await consume(response);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    fail(`${requestPath(input)}: request failed`);
  } finally {
    clearTimeout(timeout);
  }
}

export async function readLimited(response, maximumBytes) {
  const declaredLength = Number.parseInt(
    response.headers.get("content-length") ?? "",
    10,
  );
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    fail(
      `${requestPath(response.url)}: response exceeds ${maximumBytes} bytes`,
    );
  }
  const chunks = [];
  let size = 0;
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maximumBytes) {
      await reader.cancel();
      fail(
        `${requestPath(response.url)}: response exceeds ${maximumBytes} bytes`,
      );
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, size);
}

export async function requestBytes(
  input,
  init = {},
  maximumBytes = 65_536,
  timeoutMilliseconds = requestTimeoutMilliseconds,
) {
  return fetchBounded(
    input,
    init,
    async (response) => ({
      body: await readLimited(response, maximumBytes),
      response,
    }),
    timeoutMilliseconds,
  );
}

async function requestHeaders(
  input,
  init = {},
  timeoutMilliseconds = requestTimeoutMilliseconds,
) {
  return fetchBounded(
    input,
    init,
    async (response) => {
      await response.body?.cancel();
      return response;
    },
    timeoutMilliseconds,
  );
}

function remotePath(path) {
  if (path === "index.html") return "/";
  if (path === "404.html") return "/404.html";
  if (path.endsWith("/index.html")) {
    return `/${path.slice(0, -"index.html".length)}`;
  }
  return `/${path}`;
}

const contentTypes = new Map([
  [".css", /^text\/css(?:;|$)/i],
  [".html", /^text\/html(?:;|$)/i],
  [".js", /^(?:application|text)\/javascript(?:;|$)/i],
  [".json", /^application\/json(?:;|$)/i],
  [".png", /^image\/png(?:;|$)/i],
  [".svg", /^image\/svg\+xml(?:;|$)/i],
  [".txt", /^text\/plain(?:;|$)/i],
  [".webmanifest", /^application\/manifest\+json(?:;|$)/i],
  [".xml", /^application\/xml(?:;|$)/i],
]);

function verifyContentType(response, path) {
  const expected = contentTypes.get(extname(path));
  requireValue(expected, `${path}: no expected content type is defined`);
  const actual = response.headers.get("content-type") ?? "";
  requireValue(expected.test(actual), `${path}: unexpected content type`);
}

function parseUniqueDirectives(value, separator, label, path) {
  const directives = new Map();
  for (const part of value.split(separator)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens.shift().toLowerCase();
    requireValue(!directives.has(name), `${path}: duplicate ${label}`);
    directives.set(
      name,
      tokens.map((token) => token.toLowerCase()),
    );
  }
  return directives;
}

function requireExactDirective(directives, name, allowed, path) {
  const actual = directives.get(name);
  requireValue(actual, `${path}: CSP lacks ${name}`);
  requireValue(
    allowed.some(
      (candidate) =>
        candidate.length === actual.length &&
        candidate.every((token, index) => token === actual[index]),
    ),
    `${path}: CSP ${name} has an unsafe source set`,
  );
}

function parsePermissions(value, path) {
  const features = new Map();
  for (const part of value.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^([a-z-]+)\s*=\s*(\([^)]*\))$/i);
    requireValue(match, `${path}: malformed Permissions-Policy feature`);
    const name = match[1].toLowerCase();
    requireValue(
      !features.has(name),
      `${path}: duplicate Permissions-Policy feature`,
    );
    features.set(name, match[2].replace(/\s+/g, ""));
  }
  return features;
}

export function verifyCommonSecurity(response, path) {
  const hsts = response.headers.get("strict-transport-security") ?? "";
  const hstsParts = hsts
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean);
  const maximumAgeParts = hstsParts.filter((part) => /^max-age=/i.test(part));
  requireValue(
    maximumAgeParts.length === 1 && /^max-age=\d+$/i.test(maximumAgeParts[0]),
    `${path}: HSTS must contain one valid max-age`,
  );
  const maximumAge = Number.parseInt(maximumAgeParts[0].split("=", 2)[1], 10);
  requireValue(
    maximumAge >= 31_536_000 &&
      hstsParts.some((part) => part.toLowerCase() === "includesubdomains"),
    `${path}: HSTS must cover subdomains for at least one year`,
  );
  const contentTypeOptions = (
    response.headers.get("x-content-type-options") ?? ""
  )
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  requireValue(
    contentTypeOptions.length > 0 &&
      contentTypeOptions.every((value) => value === "nosniff"),
    `${path}: X-Content-Type-Options must be nosniff`,
  );
}

export function verifyCachePolicy(response, path) {
  const policy = response.headers.get("cache-control") ?? "";
  requireValue(policy.trim(), `${path}: Cache-Control is missing`);
  const directives = new Map();
  const allowedDirectives = new Set([
    "max-age",
    "must-revalidate",
    "no-cache",
    "no-store",
    "no-transform",
    "private",
    "proxy-revalidate",
    "public",
    "s-maxage",
  ]);
  for (const part of policy.split(",")) {
    const match = part
      .trim()
      .match(
        /^([a-z][a-z0-9!#$%&'*+.^_`|~-]*)(?:\s*=\s*(?:"([^"]*)"|([^\s,]+)))?$/i,
      );
    requireValue(
      match,
      `${path}: Cache-Control contains a malformed directive`,
    );
    const name = match[1].toLowerCase();
    requireValue(
      allowedDirectives.has(name),
      `${path}: Cache-Control contains an unsupported directive`,
    );
    requireValue(
      !directives.has(name),
      `${path}: Cache-Control repeats a directive`,
    );
    directives.set(name, match[2] ?? match[3] ?? null);
  }
  for (const name of [
    "must-revalidate",
    "no-cache",
    "no-store",
    "no-transform",
    "private",
    "proxy-revalidate",
    "public",
  ]) {
    if (directives.has(name)) {
      requireValue(
        directives.get(name) === null,
        `${path}: Cache-Control ${name} must not have a value`,
      );
    }
  }
  requireValue(
    !(directives.has("public") && directives.has("private")),
    `${path}: Cache-Control must not combine public and private`,
  );
  const ages = new Map();
  for (const name of ["max-age", "s-maxage"]) {
    if (!directives.has(name)) continue;
    const value = directives.get(name);
    requireValue(
      typeof value === "string" && /^\d+$/.test(value),
      `${path}: Cache-Control ${name} must be an integer`,
    );
    const age = Number.parseInt(value, 10);
    requireValue(
      Number.isSafeInteger(age),
      `${path}: Cache-Control ${name} is out of range`,
    );
    ages.set(name, age);
  }
  const extension = extname(path);
  const limit = [".png", ".svg"].includes(extension) ? 86_400 : 300;
  for (const [name, age] of ages) {
    requireValue(
      age <= limit,
      `${path}: Cache-Control ${name} exceeds ${limit} seconds`,
    );
  }
  requireValue(
    directives.has("no-cache") ||
      directives.has("no-store") ||
      ages.has("max-age"),
    `${path}: Cache-Control lacks a bounded browser cache policy`,
  );
}

export function verifyHtmlSecurity(response, path) {
  verifyCommonSecurity(response, path);
  const csp = response.headers.get("content-security-policy") ?? "";
  const directives = parseUniqueDirectives(csp, ";", "CSP directive", path);
  const allowedDirectives = new Set([
    "default-src",
    "img-src",
    "style-src",
    "script-src",
    "font-src",
    "connect-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "object-src",
    "manifest-src",
    "upgrade-insecure-requests",
  ]);
  for (const [name, tokens] of directives) {
    requireValue(
      allowedDirectives.has(name),
      `${path}: CSP contains an unsupported directive`,
    );
    if (name === "upgrade-insecure-requests") {
      requireValue(tokens.length === 0, `${path}: malformed CSP ${name}`);
    }
  }
  for (const name of [
    "default-src",
    "base-uri",
    "frame-ancestors",
    "object-src",
  ]) {
    requireExactDirective(directives, name, [["'none'"]], path);
  }
  for (const name of [
    "script-src",
    "style-src",
    "connect-src",
    "form-action",
    "font-src",
    "manifest-src",
  ]) {
    requireExactDirective(directives, name, [["'self'"]], path);
  }
  requireExactDirective(
    directives,
    "img-src",
    [
      ["'self'", "data:"],
      ["data:", "'self'"],
    ],
    path,
  );
  requireValue(
    response.headers.get("x-frame-options")?.toUpperCase() === "DENY",
    `${path}: X-Frame-Options must be DENY`,
  );
  requireValue(
    [
      "no-referrer",
      "same-origin",
      "strict-origin",
      "strict-origin-when-cross-origin",
    ].includes(response.headers.get("referrer-policy")?.toLowerCase() ?? ""),
    `${path}: Referrer-Policy is missing or too broad`,
  );
  const permissions = parsePermissions(
    response.headers.get("permissions-policy") ?? "",
    path,
  );
  for (const value of permissions.values()) {
    requireValue(
      value === "()",
      `${path}: Permissions-Policy broadens a feature`,
    );
  }
  for (const feature of [
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "browsing-topics",
  ]) {
    requireValue(
      permissions.get(feature) === "()",
      `${path}: Permissions-Policy must deny ${feature}`,
    );
  }
  requireValue(
    response.headers.get("cross-origin-opener-policy")?.toLowerCase() ===
      "same-origin",
    `${path}: Cross-Origin-Opener-Policy must be same-origin`,
  );
}

async function verifyExactFile(origin, path, expected, packageOnly) {
  const pathname = remotePath(path);
  const { body, response } = await requestBytes(
    new URL(pathname, `${origin}/`),
    {},
    Math.max(expected.length + 1, 65_536),
  );
  const expectedStatus = path === "404.html" ? 404 : 200;
  requireValue(
    response.status === expectedStatus,
    `${pathname}: expected ${expectedStatus}, received ${response.status}`,
  );
  verifyContentType(response, path);
  if (!packageOnly) {
    if (extname(path) === ".html") verifyHtmlSecurity(response, pathname);
    else verifyCommonSecurity(response, pathname);
    verifyCachePolicy(response, pathname);
  }
  requireValue(
    body.equals(expected),
    `${pathname}: content differs from site/dist`,
  );
}

function parseUtcSecond(value, name) {
  requireValue(
    typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value),
    `certificate status ${name} is not an exact UTC second`,
  );
  const milliseconds = Date.parse(value);
  requireValue(
    Number.isFinite(milliseconds),
    `certificate status ${name} is invalid`,
  );
  requireValue(
    new Date(milliseconds).toISOString().replace(".000Z", "Z") === value,
    `certificate status ${name} is not canonical`,
  );
  return milliseconds;
}

export function parseStatus(value) {
  requireValue(
    value && typeof value === "object",
    "certificate status is not an object",
  );
  const issuedAt = parseUtcSecond(value.issuedAt, "issuedAt");
  const expiresAt = parseUtcSecond(value.expiresAt, "expiresAt");
  const nextRenewalAt = parseUtcSecond(value.nextRenewalAt, "nextRenewalAt");
  const lastDeployedAt = parseUtcSecond(value.lastDeployedAt, "lastDeployedAt");
  requireValue(issuedAt < expiresAt, "certificate status lifetime is invalid");
  requireValue(
    lastDeployedAt >= issuedAt && lastDeployedAt < expiresAt,
    "certificate deployment evidence is outside the leaf lifetime",
  );
  requireValue(
    nextRenewalAt >= issuedAt && nextRenewalAt < expiresAt,
    "expected replacement evidence is outside the leaf lifetime",
  );
  requireValue(
    typeof value.fingerprintSha256 === "string" &&
      /^[0-9a-f]{64}$/i.test(value.fingerprintSha256),
    "certificate status fingerprint is invalid",
  );
  requireValue(
    value.managedBy === "AcmeMux",
    "certificate status managedBy must be AcmeMux",
  );
  for (const field of ["profile", "estimateBasis"]) {
    requireValue(
      typeof value[field] === "string" && value[field].trim(),
      `certificate status ${field} is missing`,
    );
  }
  return {
    expiresAt,
    fingerprintSha256: value.fingerprintSha256.toLowerCase(),
    issuedAt,
  };
}

function tlsEvidence(hostname) {
  return new Promise((resolvePromise, rejectPromise) => {
    const socket = connect({
      host: hostname,
      minVersion: "TLSv1.2",
      port: 443,
      rejectUnauthorized: true,
      servername: hostname,
    });
    const failConnection = () => {
      socket.destroy();
      rejectPromise(
        new VerificationError(`${hostname}: TLS inspection failed`),
      );
    };
    socket.setTimeout(requestTimeoutMilliseconds, () => failConnection());
    socket.once("error", failConnection);
    socket.once("secureConnect", () => {
      socket.removeListener("error", failConnection);
      try {
        const certificate = socket.getPeerCertificate(true);
        socket.destroy();
        requireValue(
          socket.authorized,
          `${hostname}: TLS peer is not authorized`,
        );
        requireValue(
          certificate.raw,
          `${hostname}: TLS peer certificate is unavailable`,
        );
        const parsed = new X509Certificate(certificate.raw);
        requireValue(
          parsed.checkHost(hostname),
          `${hostname}: TLS peer certificate does not cover the host`,
        );
        const issuedAt = Date.parse(parsed.validFrom);
        const expiresAt = Date.parse(parsed.validTo);
        requireValue(
          Number.isFinite(issuedAt) && Number.isFinite(expiresAt),
          `${hostname}: TLS peer lifetime cannot be parsed`,
        );
        resolvePromise({
          expiresAt,
          fingerprintSha256: createHash("sha256")
            .update(certificate.raw)
            .digest("hex"),
          issuedAt,
        });
      } catch (error) {
        socket.destroy();
        rejectPromise(
          error instanceof VerificationError
            ? error
            : new VerificationError(`${hostname}: TLS inspection failed`),
        );
      }
    });
  });
}

export function verifyTlsMatch(status, apex, www) {
  requireValue(
    apex.fingerprintSha256 === www.fingerprintSha256,
    "apex and www serve different TLS leaves",
  );
  requireValue(
    apex.fingerprintSha256 === status.fingerprintSha256,
    "public status fingerprint does not match the served TLS leaf",
  );
  requireValue(
    apex.issuedAt === status.issuedAt && apex.expiresAt === status.expiresAt,
    "public status lifetime does not match the served TLS leaf",
  );
}

export async function verifyRedirect(input, expected) {
  const response = await requestHeaders(input);
  const path = requestPath(input);
  requireValue(
    response.status === 301 || response.status === 308,
    `${path}: expected a permanent redirect, received ${response.status}`,
  );
  const location = response.headers.get("location") ?? "";
  requireValue(
    new URL(location, input).href === expected,
    `${path}: permanent redirect target is incorrect`,
  );
  if (input.startsWith("https://")) {
    verifyCommonSecurity(response, new URL(input).pathname);
  }
}

async function verifyPublicContracts(origin, publicPaths) {
  const { body: statusBody, response: statusResponse } = await requestBytes(
    new URL("/certificate-status.json", `${origin}/`),
    { cache: "no-store", headers: { Accept: "application/json" } },
    65_536,
  );
  requireValue(
    statusResponse.status === 200,
    `/certificate-status.json: expected 200, received ${statusResponse.status}`,
  );
  verifyContentType(statusResponse, "certificate-status.json");
  verifyCommonSecurity(statusResponse, "/certificate-status.json");
  requireValue(
    /(?:^|,)\s*no-store(?:,|$)/i.test(
      statusResponse.headers.get("cache-control") ?? "",
    ),
    "/certificate-status.json: Cache-Control must include no-store",
  );
  let statusValue;
  try {
    statusValue = JSON.parse(statusBody.toString("utf8"));
  } catch {
    fail("/certificate-status.json: invalid JSON");
  }
  const status = parseStatus(statusValue);
  const [apex, www] = await Promise.all([
    tlsEvidence("acmemux.com"),
    tlsEvidence("www.acmemux.com"),
  ]);
  verifyTlsMatch(status, apex, www);

  const { response: reminderResponse } = await requestBytes(
    new URL("/api/renewal-alerts/subscriptions", `${origin}/`),
    { headers: { Accept: "application/json" } },
    8192,
  );
  requireValue(
    reminderResponse.status === 405,
    `/api/renewal-alerts/subscriptions: read-only probe returned ${reminderResponse.status}`,
  );
  verifyContentType(reminderResponse, "reminder.json");
  verifyCommonSecurity(reminderResponse, "/api/renewal-alerts/subscriptions");
  requireValue(
    /(?:^|,)\s*no-store(?:,|$)/i.test(
      reminderResponse.headers.get("cache-control") ?? "",
    ),
    "/api/renewal-alerts/subscriptions: Cache-Control must include no-store",
  );
  requireValue(
    (reminderResponse.headers.get("allow") ?? "")
      .split(",")
      .map((value) => value.trim().toUpperCase())
      .includes("POST"),
    "/api/renewal-alerts/subscriptions: 405 response must allow POST",
  );
  await verifyReminderSameOrigin(origin);

  for (const path of publicPaths) {
    const expected = new URL(path, "https://acmemux.com").href;
    await Promise.all([
      verifyRedirect(new URL(path, "http://acmemux.com").href, expected),
      verifyRedirect(new URL(path, "http://www.acmemux.com").href, expected),
      verifyRedirect(new URL(path, "https://www.acmemux.com").href, expected),
    ]);
  }

  const expectedNotFound = await readFile(join(outputDirectory, "404.html"));
  const { body: actualNotFound, response: missingResponse } =
    await requestBytes(
      new URL("/__acmemux-live-probe-missing__", `${origin}/`),
      {},
      expectedNotFound.length + 1,
    );
  requireValue(
    missingResponse.status === 404,
    `missing-route probe returned ${missingResponse.status}`,
  );
  verifyContentType(missingResponse, "404.html");
  verifyHtmlSecurity(missingResponse, "/__acmemux-live-probe-missing__");
  verifyCachePolicy(missingResponse, "404.html");
  requireValue(
    actualNotFound.equals(expectedNotFound),
    "missing-route response differs from site/dist/404.html",
  );
}

export async function verifyReminderSameOrigin(origin) {
  const path = "/api/renewal-alerts/subscriptions";
  const response = await requestHeaders(new URL(path, `${origin}/`), {
    headers: {
      "Access-Control-Request-Headers": "content-type",
      "Access-Control-Request-Method": "POST",
      Origin: "https://cross-origin.invalid",
    },
    method: "OPTIONS",
  });
  requireValue(
    response.status >= 200 &&
      response.status < 500 &&
      (response.status < 300 || response.status >= 400),
    `${path}: cross-origin preflight did not fail safely`,
  );
  requireValue(
    !response.headers.has("access-control-allow-origin"),
    `${path}: cross-origin preflight authorizes an origin`,
  );
  requireValue(
    response.headers.get("access-control-allow-credentials")?.toLowerCase() !==
      "true",
    `${path}: cross-origin preflight authorizes credentials`,
  );
}

export function prepareProductionPackage(runCommand = execFileSync) {
  const runGit = (arguments_, failure) => {
    try {
      return runCommand("git", arguments_, {
        cwd: applicationDirectory,
        encoding: "utf8",
        stdio: "pipe",
      });
    } catch {
      fail(failure);
    }
  };
  const sourceState = () =>
    runGit(
      ["status", "--porcelain", "--untracked-files=normal"],
      "application source state is unavailable",
    ).trim();
  const sourceRevision = () =>
    runGit(
      ["rev-parse", "HEAD"],
      "application source revision is unavailable",
    ).trim();

  requireValue(
    sourceState() === "",
    "application worktree must be clean before production verification",
  );
  const beforeRevision = sourceRevision();
  requireValue(
    /^[0-9a-f]{40}$/.test(beforeRevision),
    "application source revision is unavailable",
  );
  try {
    runCommand("make", ["--no-print-directory", "site-build"], {
      cwd: applicationDirectory,
      encoding: "utf8",
      stdio: "pipe",
    });
  } catch {
    fail("public site package build failed");
  }
  requireValue(
    sourceState() === "",
    "application worktree changed while building the production package",
  );
  const afterRevision = sourceRevision();
  requireValue(
    afterRevision === beforeRevision,
    "application revision changed while building the production package",
  );
  return beforeRevision;
}

async function main() {
  const { origin, packageOnly } = options(process.argv.slice(2));
  let sourceRevision = "local-preview";
  if (!packageOnly) {
    requireValue(
      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
      "NODE_TLS_REJECT_UNAUTHORIZED must not disable certificate validation",
    );
    sourceRevision = prepareProductionPackage();
  }
  let localBuild;
  try {
    localBuild = await readFile(join(outputDirectory, "BUILD.json"));
  } catch {
    fail("site package manifest is unavailable");
  }
  let manifest;
  try {
    manifest = JSON.parse(localBuild.toString("utf8"));
  } catch {
    fail("site/dist/BUILD.json is invalid");
  }
  requireValue(
    manifest.format === 1 &&
      manifest.canonicalOrigin === "https://acmemux.com" &&
      Array.isArray(manifest.files),
    "site/dist/BUILD.json has an unsupported shape",
  );

  await verifyExactFile(origin, "BUILD.json", localBuild, packageOnly);
  const seenPaths = new Set();
  const publicPaths = ["/BUILD.json"];
  for (const entry of manifest.files) {
    requireValue(
      entry &&
        typeof entry.path === "string" &&
        entry.path === posix.normalize(entry.path) &&
        !entry.path.startsWith("/") &&
        !entry.path.startsWith("../") &&
        !entry.path.includes("\\") &&
        Number.isSafeInteger(entry.size) &&
        entry.size >= 0 &&
        typeof entry.sha256 === "string" &&
        /^[0-9a-f]{64}$/.test(entry.sha256),
      "site/dist/BUILD.json contains an invalid file entry",
    );
    requireValue(
      !seenPaths.has(entry.path),
      `site/dist/BUILD.json contains duplicate ${entry.path}`,
    );
    seenPaths.add(entry.path);
    publicPaths.push(remotePath(entry.path));
    const expected = await readFile(join(outputDirectory, entry.path));
    requireValue(
      expected.length === entry.size &&
        createHash("sha256").update(expected).digest("hex") === entry.sha256,
      `${entry.path}: local file does not match BUILD.json`,
    );
    await verifyExactFile(origin, entry.path, expected, packageOnly);
  }

  if (packageOnly) {
    const digest = createHash("sha256").update(localBuild).digest("hex");
    console.log(
      `Verified deployed site package (${manifest.files.length + 1} files, BUILD.json sha256 ${digest}) at ${origin}`,
    );
    return;
  }
  await verifyPublicContracts(origin, [...new Set(publicPaths)].sort());
  const digest = createHash("sha256").update(localBuild).digest("hex");
  console.log(
    `Verified source ${sourceRevision} and deployed site package (BUILD.json sha256 ${digest}), security headers, redirects, public contracts, and TLS evidence at ${origin}`,
  );
}

const invokedPath = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : "";
if (import.meta.url === invokedPath) {
  try {
    await main();
  } catch (error) {
    console.error(`FAIL: ${formatFailure(error)}`);
    process.exitCode = 1;
  }
}
