import { vi } from "vitest";

import { CSRF_HEADER_NAME } from "./session";
import {
  OperationRequestError,
  createOperationClient,
  type ActiveOperation,
  type ManualOperationPreview,
  type TerminalOperationResult,
} from "./operations";

type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const policy = {
  browserDisconnect: "continues",
  cancellation: "not_supported",
  retry: "manual_only",
  timeoutSeconds: 1800,
} as const;

const activeOperation: ActiveOperation = {
  id: "a".repeat(32),
  kind: "manual",
  state: "running",
  phase: "executing",
  requestedAt: "2030-01-01T00:00:00Z",
  startedAt: "2030-01-01T00:00:01Z",
};

const preview: ManualOperationPreview = {
  state: "review_required",
  reviewedPreviewToken: "P".repeat(43),
  intent: {
    kind: "manual_workspace_run",
    workingDirectory: "/srv/lego",
    configurationPath: "/srv/lego/.lego.yml",
    storagePath: "/srv/lego/data",
    runtime: { identity: "v5.3.1", manifestId: "lego-v5.3.1" },
    certificates: [
      {
        name: "gateway@example",
        domains: ["gateway.home.example"],
        account: "admin@example.com",
        ca: "letsencrypt",
        challenge: {
          name: "http-home",
          kind: "http-01",
          mode: "listener",
        },
      },
      {
        name: "media",
        domains: ["media.home.example"],
        account: "primary",
        ca: "https://acme-v02.api.letsencrypt.org/directory",
        challenge: {
          name: "http-webroot",
          kind: "http-01",
          mode: "webroot",
        },
      },
    ],
    cloudAccess: [],
    nativeEffects: [
      "acme_accounts_may_change",
      "certificate_artifacts_may_change",
      "native_configuration_backup_may_change",
      "external_acme_state_may_change",
    ],
  },
  policy,
};

const terminalResult: TerminalOperationResult = {
  id: activeOperation.id,
  kind: "manual",
  state: "partial",
  reasonCode: "certificate_failed",
  requestedAt: activeOperation.requestedAt,
  startedAt: activeOperation.startedAt,
  finishedAt: "2030-01-01T00:02:00Z",
  mayHaveChanged: true,
  output: {
    text: "[stdout]\ncertificate gateway completed\n[stderr]\nmedia failed\n",
    truncated: false,
  },
  certificates: [
    {
      name: "gateway@example",
      state: "completed",
      reasonCode: "completed",
    },
    { name: "media", state: "failed", reasonCode: "upstream_failed" },
    {
      name: "router",
      state: "not_attempted",
      reasonCode: "upstream_stopped",
    },
  ],
  inventory: {
    state: "refreshed",
    certificateCount: 2,
    summary: "Native inventory was refreshed after the operation.",
  },
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

function clientWith(value: unknown, status = 200) {
  return createOperationClient({
    fetch: vi.fn(async () => jsonResponse(value, { status })),
    readCookies: () => "__Host-acmemux_csrf=test-csrf-token",
  });
}

describe("operation client", () => {
  it("loads strict idle, active, latest, and fixed-policy wrappers", async () => {
    await expect(clientWith({ state: "idle" }).getStatus()).resolves.toEqual({
      state: "idle",
    });
    await expect(
      clientWith({ state: "active", operation: activeOperation }).getStatus(),
    ).resolves.toEqual({ state: "active", operation: activeOperation });
    await expect(clientWith({ state: "empty" }).getLatest()).resolves.toEqual({
      state: "empty",
    });
    await expect(
      clientWith({ state: "available", result: terminalResult }).getLatest(),
    ).resolves.toEqual({ state: "available", result: terminalResult });
    await expect(clientWith({ policy }).getCancelPolicy()).resolves.toEqual(
      policy,
    );
  });

  it("accepts the bounded native inventory count independently of result detail limits", async () => {
    const result = {
      ...terminalResult,
      inventory: { ...terminalResult.inventory, certificateCount: 10_000 },
    };

    await expect(
      clientWith({ state: "available", result }).getLatest(),
    ).resolves.toEqual({ state: "available", result });
  });

  it("previews a bounded semantic intent without a command or secret surface", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse(preview),
    );
    const client = createOperationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=rotated-token",
    });

    await expect(client.previewManual()).resolves.toEqual(preview);

    expect(request).toHaveBeenCalledWith(
      "/api/v1/operations/manual/previews",
      expect.objectContaining({
        body: "{}",
        cache: "no-store",
        credentials: "same-origin",
        method: "POST",
        redirect: "error",
      }),
    );
    const headers = new Headers(request.mock.calls[0]?.[1]?.headers);
    expect(headers.get(CSRF_HEADER_NAME)).toBe("rotated-token");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(JSON.stringify(preview)).not.toMatch(/argv|environment|secret/i);
  });

  it("enqueues only an opaque reviewed preview and requires 202", async () => {
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({ operation: activeOperation }, { status: 202 }),
    );
    const client = createOperationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.enqueueManual(preview.reviewedPreviewToken),
    ).resolves.toEqual(activeOperation);
    expect(request.mock.calls[0]?.[0]).toBe("/api/v1/operations/manual");
    expect(request.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ reviewedPreviewToken: preview.reviewedPreviewToken }),
    );

    await expect(
      clientWith({ operation: activeOperation }).enqueueManual(
        preview.reviewedPreviewToken,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("requires a current CSRF cookie before preview or enqueue", async () => {
    const request = vi.fn<FetchImplementation>();
    const client = createOperationClient({
      fetch: request,
      readCookies: () => "",
    });

    await expect(client.previewManual()).rejects.toMatchObject({
      code: "authentication_required",
      status: 401,
    });
    await expect(
      client.enqueueManual(preview.reviewedPreviewToken),
    ).rejects.toMatchObject({ code: "authentication_required", status: 401 });
    expect(request).not.toHaveBeenCalled();
  });

  it.each([
    {
      name: "an injected command field",
      value: { ...preview, command: ["lego"] },
    },
    {
      name: "a secret-shaped certificate field",
      value: {
        ...preview,
        intent: {
          ...preview.intent,
          certificates: [
            { ...preview.intent.certificates[0], credential: "do-not-return" },
          ],
        },
      },
    },
    {
      name: "missing native-effect consequences",
      value: {
        ...preview,
        intent: {
          ...preview.intent,
          nativeEffects: preview.intent.nativeEffects.slice(0, 3),
        },
      },
    },
    {
      name: "unsorted certificate bindings",
      value: {
        ...preview,
        intent: {
          ...preview.intent,
          certificates: [...preview.intent.certificates].reverse(),
        },
      },
    },
    {
      name: "an unsupported CA",
      value: {
        ...preview,
        intent: {
          ...preview.intent,
          certificates: [
            { ...preview.intent.certificates[0], ca: "https://evil.invalid" },
          ],
        },
      },
    },
  ])("rejects $name in a preview", async ({ value }) => {
    await expect(clientWith(value).previewManual()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it.each([
    {
      name: "queued work with a start time",
      operation: {
        ...activeOperation,
        state: "queued",
        phase: "queued",
      },
    },
    {
      name: "running work with a queued phase",
      operation: { ...activeOperation, phase: "queued" },
    },
    {
      name: "running work without a start time",
      operation: { ...activeOperation, startedAt: null },
    },
    {
      name: "work started before it was requested",
      operation: {
        ...activeOperation,
        startedAt: "2029-12-31T23:59:59Z",
      },
    },
  ])("rejects $name", async ({ operation }) => {
    await expect(
      clientWith({ state: "active", operation }).getStatus(),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it.each([
    {
      name: "an active-only phase",
      result: { ...terminalResult, phase: "executing" },
    },
    {
      name: "a missing terminal reason",
      result: { ...terminalResult, reasonCode: "" },
    },
    {
      name: "a finish before start",
      result: {
        ...terminalResult,
        finishedAt: "2030-01-01T00:00:00Z",
      },
    },
    {
      name: "duplicate certificate results",
      result: {
        ...terminalResult,
        certificates: [
          terminalResult.certificates[0],
          terminalResult.certificates[0],
        ],
      },
    },
    {
      name: "an unsafe output control",
      result: {
        ...terminalResult,
        output: { text: "safe\u0000unsafe", truncated: false },
      },
    },
    {
      name: "an unbounded transcript",
      result: {
        ...terminalResult,
        output: { text: "x".repeat(256 * 1024 + 1), truncated: true },
      },
    },
    {
      name: "a count for failed inventory refresh",
      result: {
        ...terminalResult,
        inventory: {
          ...terminalResult.inventory,
          state: "refresh_failed",
          certificateCount: 2,
        },
      },
    },
  ])("rejects $name in a latest result", async ({ result }) => {
    await expect(
      clientWith({ state: "available", result }).getLatest(),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("never reflects an API error message and keeps trusted auth semantics", async () => {
    const client = createOperationClient({
      fetch: vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: "configuration_invalid",
              message: "credential=do-not-reflect",
            },
          },
          { status: 409 },
        ),
      ),
    });

    await expect(client.getStatus()).rejects.toEqual(
      new OperationRequestError("configuration_invalid", 409),
    );
    await expect(client.getStatus()).rejects.not.toThrow(/do-not-reflect/);

    const forgedAuth = createOperationClient({
      fetch: vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: "authentication_required",
              message: "forged body",
            },
          },
          { status: 409 },
        ),
      ),
    });
    await expect(forgedAuth.getStatus()).rejects.toMatchObject({
      code: "operation_changed",
      status: 409,
    });
  });

  it("maps a lost response to network failure without retrying", async () => {
    const request = vi.fn<FetchImplementation>(async () => {
      throw new TypeError("connection closed");
    });
    const client = createOperationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.enqueueManual(preview.reviewedPreviewToken),
    ).rejects.toMatchObject({ code: "network_failure", status: 0 });
    expect(request).toHaveBeenCalledTimes(1);
  });
});
