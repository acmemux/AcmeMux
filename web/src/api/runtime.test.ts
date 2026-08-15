import { vi } from "vitest";

import {
  RuntimeRequestError,
  createRuntimeClient,
  type RuntimeEvidence,
} from "./runtime";
import { CSRF_HEADER_NAME } from "./session";

type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const evidence: RuntimeEvidence = {
  canonicalPath: "/usr/local/bin/lego",
  version: "v5.3.1",
  commit: null,
  versionOutput: "lego version v5.3.1 linux/amd64",
  platform: { os: "linux", architecture: "amd64" },
  metadata: {
    sizeBytes: 24_001_024,
    modifiedAt: "2030-01-01T00:00:00Z",
    changedAt: "2030-01-01T00:00:01Z",
    mode: "0755",
    capabilities: "none",
    uid: 1000,
    gid: 1000,
    device: "259",
    inode: "123456",
  },
  build: {
    available: true,
    provenanceComplete: true,
    goVersion: "go1.26.6",
    commandPath: "github.com/go-acme/lego/v5",
    mainPath: "github.com/go-acme/lego/v5",
    mainVersion: "v5.3.1",
    dependencyGraphSha256: "d".repeat(64),
    goos: "linux",
    goarch: "amd64",
    vcsRevision: "589c84af4f26629fbdaa7fbca712f806632ccb7e",
    vcsModifiedKnown: true,
    vcsModifiedValid: true,
    vcsModified: false,
  },
  sha256: "a".repeat(64),
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

describe("runtime client", () => {
  it("decodes an exact supported runtime snapshot", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({
        state: "supported",
        runtime: evidence,
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      }),
    );
    const client = createRuntimeClient({ fetch: request });

    await expect(client.getRuntime()).resolves.toMatchObject({
      state: "supported",
      runtime: { canonicalPath: "/usr/local/bin/lego" },
    });
    expect(request).toHaveBeenCalledWith(
      "/api/v1/runtime",
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
        method: "GET",
        redirect: "error",
      }),
    );
  });

  it("inspects only an explicit absolute host path with current CSRF", async () => {
    let cookies = "__Host-acmemux_csrf=first-token";
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({
        state: "review_required",
        candidate: evidence,
        compatibility: {
          state: "unverified",
          code: "unknown_identity",
          summary: "No exact compatibility evidence exists.",
        },
      }),
    );
    const client = createRuntimeClient({
      fetch: request,
      readCookies: () => cookies,
    });
    cookies = "__Host-acmemux_csrf=rotated-token";

    await expect(
      client.inspectCandidate("/usr/local/bin/lego"),
    ).resolves.toMatchObject({
      state: "review_required",
      compatibility: { state: "unverified" },
    });

    const init = request.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ path: "/usr/local/bin/lego" }));
    const headers = new Headers(init?.headers);
    expect(headers.get(CSRF_HEADER_NAME)).toBe("rotated-token");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("treats a missing mutation CSRF cookie as an expired session", async () => {
    const request = vi.fn<FetchImplementation>();
    const client = createRuntimeClient({
      fetch: request,
      readCookies: () => "",
    });

    await expect(
      client.inspectCandidate("/usr/local/bin/lego"),
    ).rejects.toMatchObject({
      code: "authentication_required",
      status: 401,
    });
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects a mutation response for a different executable path", async () => {
    const otherEvidence = {
      ...evidence,
      canonicalPath: "/opt/lego/bin/lego",
    };
    const candidateClient = createRuntimeClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "review_required",
          candidate: otherEvidence,
          compatibility: {
            state: "supported",
            code: "compatible",
            manifestId: "lego-v5.3.1",
            summary: "Exact release and platform match.",
          },
          reviewedEvidenceSha256: "b".repeat(64),
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    await expect(
      candidateClient.inspectCandidate(evidence.canonicalPath),
    ).rejects.toMatchObject({ code: "invalid_response" });

    const adoptionClient = createRuntimeClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "supported",
          runtime: otherEvidence,
          compatibility: {
            state: "supported",
            code: "compatible",
            manifestId: "lego-v5.3.1",
            summary: "Exact release and platform match.",
          },
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    await expect(
      adoptionClient.adoptCandidate(evidence, "lego-v5.3.1", "b".repeat(64)),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("binds adoption to the reviewed canonical path, digest, and manifest", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({
        state: "supported",
        runtime: evidence,
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      }),
    );
    const client = createRuntimeClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await client.adoptCandidate(evidence, "lego-v5.3.1", "b".repeat(64));

    const init = request.mock.calls[0]?.[1];
    expect(init?.method).toBe("PUT");
    expect(JSON.parse(String(init?.body))).toEqual({
      path: evidence.canonicalPath,
      reviewedSha256: evidence.sha256,
      reviewedManifestId: "lego-v5.3.1",
      reviewedEvidenceSha256: "b".repeat(64),
    });
  });

  it("rejects relative, empty, control-character, and oversized paths locally", async () => {
    const request = vi.fn<FetchImplementation>();
    const client = createRuntimeClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    for (const path of [
      "",
      "bin/lego",
      "/tmp/lego\nnext",
      `/${"a".repeat(4095)}`,
      `/${"é".repeat(2048)}`,
    ]) {
      await expect(client.inspectCandidate(path)).rejects.toMatchObject({
        code: "invalid_request",
      });
    }
    expect(request).not.toHaveBeenCalled();
  });

  it("strictly rejects unknown fields, missing evidence, and mismatched states", async () => {
    const values = [
      { state: "unselected", extra: true },
      {
        state: "supported",
        runtime: { ...evidence, sha256: undefined },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "manifest",
          summary: "Supported",
        },
      },
      {
        state: "supported",
        runtime: evidence,
        compatibility: {
          state: "incompatible",
          code: "build_modified",
          summary: "Mismatch",
        },
      },
      {
        state: "supported",
        runtime: evidence,
        compatibility: {
          state: "supported",
          code: "compatible",
          summary: "Missing manifest",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          commit: "2a58c3522708e4c7393a67be691bd0c3a16d8441",
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Two identities are not reviewable.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          versionOutput: "lego version v5.3.2 linux/amd64",
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Output mismatch.",
        },
      },
      {
        state: "supported",
        runtime: evidence,
        compatibility: {
          state: "supported",
          code: "unknown_identity",
          manifestId: "lego-v5.3.1",
          summary: "State and code disagree.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          build: { ...evidence.build, goVersion: "go1.26.é" },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Non-ASCII embedded build evidence.",
        },
      },
      {
        state: "unsafe",
        path: "/usr/local/bin/lego",
        diagnostic: {
          code: "path_unavailable",
          message: "State and diagnostic disagree.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: {
            ...evidence.metadata,
            modifiedAt: "2024-02-31T00:00:00Z",
          },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Impossible timestamp.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: {
            ...evidence.metadata,
            changedAt: "2030-01-01T00:00:00+00:00",
          },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Noncanonical timestamp.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, changedAt: "0000-01-01T00:00:00Z" },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Year zero.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: {
            ...evidence.metadata,
            changedAt: "2030-01-01T00:00:00.100Z",
          },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Noncanonical fractional timestamp.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, mode: "755" },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Malformed mode.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, sizeBytes: 0 },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Empty executable.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, sizeBytes: 512 * 1024 * 1024 + 1 },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Oversized executable.",
        },
      },
      ...["0775", "4755", "2755", "1755", "0644"].map((mode) => ({
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, mode },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Unsafe executable mode.",
        },
      })),
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, uid: 0x1_0000_0000 },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "UID outside uint32.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, gid: 0x1_0000_0000 },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "GID outside uint32.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: {
            ...evidence.metadata,
            device: "18446744073709551616",
          },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Device outside uint64.",
        },
      },
      {
        state: "supported",
        runtime: {
          ...evidence,
          metadata: { ...evidence.metadata, inode: "0123456" },
        },
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Noncanonical inode.",
        },
      },
    ];

    for (const value of values) {
      const client = createRuntimeClient({
        fetch: vi.fn(async () => jsonResponse(value)),
      });
      await expect(client.getRuntime()).rejects.toMatchObject({
        code: "invalid_response",
      });
    }
  });

  it("accepts exact runtime metadata wire boundaries", async () => {
    const boundaryEvidence: RuntimeEvidence = {
      ...evidence,
      metadata: {
        ...evidence.metadata,
        modifiedAt: "2024-02-29T23:59:59.123456789Z",
        changedAt: "2030-01-01T00:00:00Z",
        sizeBytes: 512 * 1024 * 1024,
        mode: "0755",
        uid: 0xffff_ffff,
        gid: 0xffff_ffff,
        device: "18446744073709551615",
        inode: "18446744073709551615",
      },
    };
    const client = createRuntimeClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "supported",
          runtime: boundaryEvidence,
          compatibility: {
            state: "supported",
            code: "compatible",
            manifestId: "lego-v5.3.1",
            summary: "Exact boundary metadata.",
          },
        }),
      ),
    });

    await expect(client.getRuntime()).resolves.toMatchObject({
      state: "supported",
      runtime: boundaryEvidence,
    });
  });

  it("rejects non-JSON responses and maps replacement races without reflecting bodies", async () => {
    const htmlClient = createRuntimeClient({
      fetch: vi.fn(
        async () =>
          new Response("<html>not an API response</html>", {
            headers: { "Content-Type": "text/html" },
          }),
      ),
    });
    await expect(htmlClient.getRuntime()).rejects.toMatchObject({
      code: "invalid_response",
    });

    const changedClient = createRuntimeClient({
      fetch: vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: "runtime_changed",
              message: "secret-bearing subprocess output",
            },
          },
          { status: 409 },
        ),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    const error = await changedClient
      .adoptCandidate(evidence, "manifest", "b".repeat(64))
      .catch((value) => value);
    expect(error).toBeInstanceOf(RuntimeRequestError);
    expect(error).toMatchObject({ code: "runtime_changed", status: 409 });
    expect(String(error)).not.toContain("secret-bearing");
  });

  it.each([
    {
      status: 401,
      bodyCode: "service_unavailable",
      expected: "authentication_required",
    },
    {
      status: 403,
      bodyCode: "authentication_required",
      expected: "request_not_allowed",
    },
    {
      status: 421,
      bodyCode: "runtime_changed",
      expected: "request_not_allowed",
    },
    {
      status: 503,
      bodyCode: "authentication_required",
      expected: "service_unavailable",
    },
    {
      status: 400,
      bodyCode: "request_not_allowed",
      expected: "invalid_request",
    },
  ])(
    "keeps HTTP $status authoritative over protected body code $bodyCode",
    async ({ status, bodyCode, expected }) => {
      const client = createRuntimeClient({
        fetch: vi.fn(async () =>
          jsonResponse(
            { error: { code: bodyCode, message: "Mismatched error." } },
            { status },
          ),
        ),
      });

      await expect(client.getRuntime()).rejects.toMatchObject({
        code: expected,
        status,
      });
    },
  );
});
