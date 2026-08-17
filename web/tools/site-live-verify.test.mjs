import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  options,
  parseStatus,
  readLimited,
  requestBytes,
  verifyCachePolicy,
  verifyCommonSecurity,
  verifyHtmlSecurity,
  verifyRedirect,
  verifyTlsMatch,
} from "./site-live-verify.mjs";

const safeHeaders = {
  "cache-control": "no-cache",
  "content-security-policy": [
    "default-src 'none'",
    "img-src 'self' data:",
    "style-src 'self'",
    "script-src 'self'",
    "font-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  "referrer-policy": "strict-origin-when-cross-origin",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

const validStatus = {
  estimateBasis: "Expected public replacement window.",
  expiresAt: "2026-11-15T01:05:34Z",
  fingerprintSha256:
    "3564029b1580f99ed3b91d8a9c2160ba33260cda00955812ed95eefc74e8cbe7",
  issuedAt: "2026-08-17T01:05:35Z",
  lastDeployedAt: "2026-08-17T03:20:35Z",
  managedBy: "AcmeMux",
  nextRenewalAt: "2026-08-20T09:35:00Z",
  profile: "Classic Let's Encrypt profile",
};

function response(headers = safeHeaders) {
  return new Response("", { headers, status: 200 });
}

test("origin options are fixed to production or loopback package checks", () => {
  assert.deepEqual(options([]), {
    origin: "https://acmemux.com",
    packageOnly: false,
  });
  assert.deepEqual(
    options(["--origin", "http://127.0.0.1:4174", "--package-only"]),
    { origin: "http://127.0.0.1:4174", packageOnly: true },
  );
  assert.throws(
    () => options(["--origin", "https://example.com", "--package-only"]),
    /loopback/,
  );
  assert.throws(
    () => options(["--origin", "https://www.acmemux.com"]),
    /restricted/,
  );
});

test("security validators accept the exact restrictive policy", () => {
  verifyCommonSecurity(response(), "/");
  verifyHtmlSecurity(response(), "/");
  verifyCachePolicy(response(), "index.html");
});

test("security validators reject broadened and malformed policies", () => {
  assert.throws(
    () =>
      verifyHtmlSecurity(
        response({
          ...safeHeaders,
          "content-security-policy": `${safeHeaders["content-security-policy"]}; script-src-elem https://example.com`,
        }),
        "/",
      ),
    /broadens script-src-elem/,
  );
  assert.throws(
    () =>
      verifyHtmlSecurity(
        response({
          ...safeHeaders,
          "content-security-policy": safeHeaders[
            "content-security-policy"
          ].replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"),
        }),
        "/",
      ),
    /unsafe source set/,
  );
  assert.throws(
    () =>
      verifyCommonSecurity(
        response({
          ...safeHeaders,
          "strict-transport-security":
            "max-age=31536000; includeSubDomainsExpanded",
        }),
        "/",
      ),
    /cover subdomains/,
  );
  assert.throws(
    () =>
      verifyHtmlSecurity(
        response({
          ...safeHeaders,
          "permissions-policy":
            "camera=(), microphone=(), geolocation=(), payment=(self), usb=(), browsing-topics=()",
        }),
        "/",
      ),
    /payment/,
  );
});

test("cache policy rejects missing, immutable, and long unversioned caching", () => {
  assert.throws(() => verifyCachePolicy(response({}), "index.html"), /missing/);
  assert.throws(
    () =>
      verifyCachePolicy(
        response({ "cache-control": "public, max-age=60, immutable" }),
        "assets/site.js",
      ),
    /unsupported immutable/,
  );
  assert.throws(
    () =>
      verifyCachePolicy(
        response({ "cache-control": "public, max-age=301" }),
        "assets/site.js",
      ),
    /exceeds 300 seconds/,
  );
  assert.throws(
    () =>
      verifyCachePolicy(
        response({
          "cache-control": "public, no-cachex, max-age=31536000",
        }),
        "assets/site.js",
      ),
    /unsupported no-cachex/,
  );
  assert.throws(
    () =>
      verifyCachePolicy(
        response({
          "cache-control": "public, max-age=300, s-maxage=31536000",
        }),
        "assets/site.js",
      ),
    /s-maxage exceeds 300 seconds/,
  );
  assert.throws(
    () =>
      verifyCachePolicy(
        response({ "cache-control": "max-age=60, max-age=300" }),
        "assets/site.js",
      ),
    /repeats max-age/,
  );
  for (const extension of ["stale-if-error", "stale-while-revalidate"]) {
    assert.throws(
      () =>
        verifyCachePolicy(
          response({
            "cache-control": `public, max-age=300, ${extension}=31536000`,
          }),
          "assets/site.js",
        ),
      new RegExp(`unsupported ${extension}`),
    );
  }
});

test("status validation matches strict browser chronology and ownership", () => {
  const parsed = parseStatus(validStatus);
  assert.equal(parsed.issuedAt, Date.parse(validStatus.issuedAt));
  assert.throws(
    () => parseStatus({ ...validStatus, nextRenewalAt: validStatus.expiresAt }),
    /replacement evidence/,
  );
  assert.throws(
    () =>
      parseStatus({ ...validStatus, lastDeployedAt: validStatus.expiresAt }),
    /deployment evidence/,
  );
  assert.throws(
    () => parseStatus({ ...validStatus, managedBy: "another-system" }),
    /managedBy/,
  );
});

test("TLS reconciliation rejects leaf and feed mismatches", () => {
  const status = parseStatus(validStatus);
  const apex = {
    expiresAt: status.expiresAt,
    fingerprintSha256: status.fingerprintSha256,
    issuedAt: status.issuedAt,
  };
  verifyTlsMatch(status, apex, { ...apex });
  assert.throws(
    () =>
      verifyTlsMatch(status, apex, {
        ...apex,
        fingerprintSha256: "0".repeat(64),
      }),
    /different TLS leaves/,
  );
  assert.throws(
    () =>
      verifyTlsMatch(
        { ...status, expiresAt: status.expiresAt - 1000 },
        apex,
        apex,
      ),
    /lifetime/,
  );
});

test("bounded reader rejects declared and streamed oversized bodies", async () => {
  await assert.rejects(
    readLimited(
      new Response("too large", { headers: { "content-length": "9" } }),
      2,
    ),
    /exceeds 2 bytes/,
  );
  await assert.rejects(readLimited(new Response("abc"), 2), /exceeds 2 bytes/);
});

test("request timeout remains active while the response body stalls", async () => {
  const sockets = new Set();
  const server = createServer((_request, serverResponse) => {
    serverResponse.writeHead(200, {
      "Content-Length": "10",
      "Content-Type": "text/plain",
    });
    serverResponse.write("a");
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolvePromise) =>
    server.listen(0, "127.0.0.1", resolvePromise),
  );
  const address = server.address();
  assert.equal(typeof address, "object");
  try {
    await assert.rejects(
      requestBytes(`http://127.0.0.1:${address.port}/`, {}, 100, 50),
      /request failed/,
    );
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});

test("redirect verification requires one exact path-preserving hop", async () => {
  const server = createServer((request, serverResponse) => {
    serverResponse.writeHead(301, {
      Location: request.url === "/loop" ? "/loop" : "/target",
    });
    serverResponse.end();
  });
  await new Promise((resolvePromise) =>
    server.listen(0, "127.0.0.1", resolvePromise),
  );
  const address = server.address();
  assert.equal(typeof address, "object");
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    await verifyRedirect(`${origin}/start`, `${origin}/target`);
    await assert.rejects(
      verifyRedirect(`${origin}/start`, `${origin}/different`),
      /expected one redirect/,
    );
    await assert.rejects(
      verifyRedirect(`${origin}/loop`, `${origin}/target`),
      /expected one redirect/,
    );
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});
