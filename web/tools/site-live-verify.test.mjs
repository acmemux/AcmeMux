import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  formatFailure,
  options,
  parseStatus,
  prepareProductionPackage,
  readLimited,
  requestBytes,
  verifyCachePolicy,
  verifyCommonSecurity,
  verifyHtmlSecurity,
  verifyRedirect,
  verifyReminderSameOrigin,
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

test("production package preparation binds one clean unchanged revision", () => {
  const revision = "a".repeat(40);
  function runner({
    states = ["", ""],
    revisions = [revision, revision],
    buildFails = false,
  } = {}) {
    let stateIndex = 0;
    let revisionIndex = 0;
    let builds = 0;
    const run = (command, arguments_) => {
      if (command === "git" && arguments_[0] === "status") {
        return states[stateIndex++] ?? "";
      }
      if (command === "git" && arguments_[0] === "rev-parse") {
        return `${revisions[revisionIndex++] ?? revision}\n`;
      }
      if (command === "make") {
        builds += 1;
        if (buildFails) throw new Error("private build detail");
        return "";
      }
      throw new Error("unexpected command");
    };
    return { builds: () => builds, run };
  }

  const clean = runner();
  assert.equal(prepareProductionPackage(clean.run), revision);
  assert.equal(clean.builds(), 1);

  const dirtyBefore = runner({ states: [" M private-file"] });
  assert.throws(
    () => prepareProductionPackage(dirtyBefore.run),
    /worktree must be clean/,
  );
  assert.equal(dirtyBefore.builds(), 0);

  assert.throws(
    () =>
      prepareProductionPackage(
        runner({ states: ["", " M changed-during-build"] }).run,
      ),
    /worktree changed/,
  );
  assert.throws(
    () =>
      prepareProductionPackage(
        runner({ revisions: [revision, "b".repeat(40)] }).run,
      ),
    /revision changed/,
  );
  assert.throws(
    () => prepareProductionPackage(runner({ buildFails: true }).run),
    /package build failed/,
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
    /unsupported directive/,
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
    /broadens a feature/,
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
    /unsupported directive/,
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
    /unsupported directive/,
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
    /repeats a directive/,
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
      /unsupported directive/,
    );
  }
});

test("failure messages do not echo response or internal error detail", () => {
  const secret = "secret-internal-detail";
  assert.equal(
    formatFailure(new Error(`${secret} at /private/path 10.0.0.8`)),
    "live verification could not complete",
  );
  assert.throws(
    () =>
      verifyCachePolicy(
        response({ "cache-control": `public, ${secret}=1` }),
        "assets/site.js",
      ),
    (error) =>
      error instanceof Error &&
      error.message.includes("unsupported directive") &&
      !error.message.includes(secret),
  );
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
      (error) =>
        error instanceof Error &&
        error.message.includes("request failed") &&
        !error.message.includes("127.0.0.1") &&
        !error.message.includes(String(address.port)),
    );
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});

test("reminder preflight proves a non-mutating same-origin boundary", async () => {
  let mode = "safe";
  const observations = [];
  const server = createServer((request, serverResponse) => {
    let bodyBytes = 0;
    request.on("data", (chunk) => {
      bodyBytes += chunk.length;
    });
    request.on("end", () => {
      observations.push({
        bodyBytes,
        headers: request.headers,
        method: request.method,
        url: request.url,
      });
      if (mode === "wildcard") {
        serverResponse.writeHead(204, {
          "Access-Control-Allow-Origin": "*",
        });
      } else if (mode === "credentials") {
        serverResponse.writeHead(204, {
          "Access-Control-Allow-Credentials": "true",
        });
      } else if (mode === "redirect") {
        serverResponse.writeHead(302, { Location: "/elsewhere" });
      } else if (mode === "server-error") {
        serverResponse.writeHead(503);
      } else {
        serverResponse.writeHead(405, { Allow: "POST" });
      }
      serverResponse.end();
    });
  });
  await new Promise((resolvePromise) =>
    server.listen(0, "127.0.0.1", resolvePromise),
  );
  const address = server.address();
  assert.equal(typeof address, "object");
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    await verifyReminderSameOrigin(origin);
    assert.deepEqual(
      {
        bodyBytes: observations[0].bodyBytes,
        method: observations[0].method,
        origin: observations[0].headers.origin,
        requestHeaders:
          observations[0].headers["access-control-request-headers"],
        requestMethod: observations[0].headers["access-control-request-method"],
        url: observations[0].url,
      },
      {
        bodyBytes: 0,
        method: "OPTIONS",
        origin: "https://cross-origin.invalid",
        requestHeaders: "content-type",
        requestMethod: "POST",
        url: "/api/renewal-alerts/subscriptions",
      },
    );
    for (const rejectedMode of [
      "wildcard",
      "credentials",
      "redirect",
      "server-error",
    ]) {
      mode = rejectedMode;
      await assert.rejects(verifyReminderSameOrigin(origin), /cross-origin/);
    }
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});

test("redirect verification requires one exact path-preserving hop", async () => {
  const server = createServer((request, serverResponse) => {
    serverResponse.writeHead(301, {
      Location:
        request.url === "/loop"
          ? "/loop"
          : request.url === "/leak"
            ? "https://user:secret@private.invalid/?token=hidden"
            : "/target",
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
      /target is incorrect/,
    );
    await assert.rejects(
      verifyRedirect(`${origin}/loop`, `${origin}/target`),
      /target is incorrect/,
    );
    await assert.rejects(
      verifyRedirect(`${origin}/leak`, `${origin}/target`),
      (error) =>
        error instanceof Error &&
        error.message.includes("target is incorrect") &&
        !error.message.includes("secret") &&
        !error.message.includes("private.invalid") &&
        !error.message.includes("hidden"),
    );
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
});
