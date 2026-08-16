import {
  ConfigurationRequestError,
  createConfigurationClient,
  type ConfigurationChange,
} from "./configuration";

const baseRevisionToken = "A".repeat(43);
const nextRevisionToken = "B".repeat(43);
const reviewedPreviewToken = "C".repeat(43);

const source = {
  baseRevisionToken,
  configurationPath: "/srv/lego/.lego.yml",
  dotenvPaths: ["/srv/lego/provider.env"],
  runtimeManifestId: "lego-v5.3.1",
};

const readySnapshot = {
  state: "ready",
  source,
  projection: [
    {
      fieldId: "account.eab.hmac_key",
      bindings: [{ id: "account", value: "home" }],
      label: "External account binding secret",
      kind: "secret",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
    },
    {
      fieldId: "workspace.storage",
      bindings: [],
      label: "Native storage directory",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: "./data",
    },
  ],
  diagnostics: [],
  capabilities: { editing: true, execution: true },
} as const;

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
    status: 200,
    ...init,
  });
}

function diagnostic(
  code: "unsupported_provider" | "recovery_required" = "unsupported_provider",
) {
  return {
    code,
    severity: "blocking",
    role: code === "recovery_required" ? "recovery" : "semantic",
    message:
      code === "recovery_required"
        ? "A prior replacement needs reconciliation."
        : "The configured provider is not supported.",
    fieldId: null,
    bindings: [],
    path: "/srv/lego/.lego.yml",
    line: 12,
    column: 5,
  } as const;
}

describe("configuration client", () => {
  it("strictly decodes a ready projection without returning secret values", async () => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(readySnapshot)),
    });

    const snapshot = await client.getConfiguration();

    expect(snapshot).toEqual(readySnapshot);
    expect(JSON.stringify(snapshot)).not.toContain("secret-value");
    if (snapshot.state === "ready") {
      expect(snapshot.projection[0]).toEqual({
        fieldId: "account.eab.hmac_key",
        bindings: [{ id: "account", value: "home" }],
        label: "External account binding secret",
        kind: "secret",
        present: true,
        configured: true,
        defaulted: false,
        presenceKnown: true,
      });
    }
  });

  it("decodes preserved unsupported content and blocks execution", async () => {
    const unsupported = {
      ...readySnapshot,
      state: "unsupported",
      diagnostics: [diagnostic()],
      capabilities: { editing: true, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(unsupported)),
    });

    await expect(client.getConfiguration()).resolves.toEqual(unsupported);
  });

  it("decodes a curated-invalid projection as repairable when editing is enabled", async () => {
    const repairable = {
      ...readySnapshot,
      state: "invalid",
      diagnostics: [
        {
          ...diagnostic(),
          code: "semantic_validation_failed",
          fieldId: "certificate.domains",
          bindings: [{ id: "certificate", value: "home" }],
        },
      ],
      capabilities: { editing: true, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(repairable)),
    });

    await expect(client.getConfiguration()).resolves.toEqual(repairable);
  });

  it("keeps an invalid projection read-only when editing is disabled", async () => {
    const readOnly = {
      ...readySnapshot,
      state: "invalid",
      diagnostics: [
        {
          ...diagnostic(),
          code: "schema_validation_failed",
          fieldId: null,
          bindings: [],
        },
      ],
      capabilities: { editing: false, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(readOnly)),
    });

    await expect(client.getConfiguration()).resolves.toEqual(readOnly);
  });

  it("decodes secret-free recovery evidence", async () => {
    const recovery = {
      state: "recovery_required",
      source,
      recovery: {
        operation: "edit",
        phase: "replacing",
        state: "ambiguous",
        targets: [
          {
            role: "configuration",
            path: "/srv/lego/.lego.yml",
            state: "ambiguous",
          },
          {
            role: "dotenv",
            path: "/srv/lego/provider.env",
            state: "unapplied",
          },
        ],
      },
      diagnostics: [diagnostic("recovery_required")],
      capabilities: { editing: false, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(recovery)),
    });

    await expect(client.getConfiguration()).resolves.toEqual(recovery);
  });

  it("decodes the exact creation-required bootstrap boundary", async () => {
    const creationRequired = {
      state: "creation_required",
      source: {
        baseRevisionToken,
        configurationPath: "",
        dotenvPaths: [],
        runtimeManifestId: "lego-v5.3.1",
      },
      diagnostics: [],
      capabilities: { editing: false, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(creationRequired)),
    });

    await expect(client.getConfiguration()).resolves.toEqual(creationRequired);
  });

  it("sends the runtime-bound creation preview and save contracts", async () => {
    const changes: ConfigurationChange[] = [
      {
        fieldId: "workspace.storage",
        bindings: [],
        operation: "set",
        value: ".lego",
      },
    ];
    const preview = {
      state: "review_required",
      baseRevisionToken,
      reviewedPreviewToken,
      resultingState: "ready",
      summary: [
        {
          fieldId: "workspace.storage",
          bindings: [],
          label: "Native storage directory",
          file: "configuration",
          action: "added",
          sensitive: false,
          before: { state: "absent" },
          after: { state: "value", value: ".lego" },
        },
      ],
      diagnostics: [],
      executionAllowed: true,
    };
    const created = {
      ...readySnapshot,
      source: { ...source, baseRevisionToken: nextRevisionToken },
    };
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse(created));
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await client.previewCreation(baseRevisionToken, "/srv/lego", null, changes);
    await client.createConfiguration(
      "/srv/lego",
      null,
      baseRevisionToken,
      source.runtimeManifestId,
      changes,
      reviewedPreviewToken,
    );

    expect(request).toHaveBeenNthCalledWith(
      1,
      "/api/v1/configuration/creation-previews",
      expect.objectContaining({
        body: JSON.stringify({
          baseRevisionToken,
          workingDirectory: "/srv/lego",
          configurationPath: null,
          changes,
        }),
        method: "POST",
      }),
    );
    expect(request).toHaveBeenNthCalledWith(
      2,
      "/api/v1/configuration/creation",
      expect.objectContaining({
        body: JSON.stringify({
          workingDirectory: "/srv/lego",
          configurationPath: null,
          baseRevisionToken,
          changes,
          reviewedPreviewToken,
        }),
        method: "PUT",
      }),
    );
  });

  it.each([
    {
      name: "the stale creation base revision",
      response: readySnapshot,
    },
    {
      name: "a different native target",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          configurationPath: "/srv/other/.lego.yml",
        },
      },
    },
    {
      name: "a different runtime manifest",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          runtimeManifestId: "lego-v5.4.0",
        },
      },
    },
    {
      name: "a non-ready creation state",
      response: {
        ...readySnapshot,
        source: { ...source, baseRevisionToken: nextRevisionToken },
        state: "unsupported",
        diagnostics: [diagnostic()],
        capabilities: { editing: true, execution: false },
      },
    },
  ])("rejects creation success reporting $name", async ({ response }) => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(response));
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.createConfiguration(
        "/srv/lego",
        null,
        baseRevisionToken,
        source.runtimeManifestId,
        [
          {
            fieldId: "workspace.storage",
            bindings: [],
            operation: "set",
            value: ".lego",
          },
        ],
        reviewedPreviewToken,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("submits an explicit adopt-current recovery without replay fields", async () => {
    const resolved = {
      ...readySnapshot,
      source: { ...source, baseRevisionToken: nextRevisionToken },
    };
    const request = vi.fn<typeof fetch>(async () => jsonResponse(resolved));
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.resolveRecovery(
        baseRevisionToken,
        "adopt_current",
        "edit",
        source.configurationPath,
        source.runtimeManifestId,
      ),
    ).resolves.toEqual(resolved);
    expect(request).toHaveBeenCalledWith(
      "/api/v1/configuration/recovery",
      expect.objectContaining({
        body: JSON.stringify({
          baseRevisionToken,
          resolution: "adopt_current",
        }),
        method: "PUT",
      }),
    );
    const headers = new Headers(request.mock.calls[0]![1]?.headers);
    expect(headers.get("X-AcmeMux-CSRF")).toBe("csrf-token");
  });

  it.each([
    {
      name: "the stale recovery revision",
      response: readySnapshot,
    },
    {
      name: "a different native target",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          configurationPath: "/srv/other/.lego.yml",
        },
      },
    },
    {
      name: "a different runtime manifest",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          runtimeManifestId: "lego-v5.4.0",
        },
      },
    },
    {
      name: "another recovery-required state",
      response: {
        state: "recovery_required",
        source: { ...source, baseRevisionToken: nextRevisionToken },
        recovery: {
          operation: "edit",
          phase: "replacing",
          state: "ambiguous",
          targets: [
            {
              role: "configuration",
              path: source.configurationPath,
              state: "ambiguous",
            },
          ],
        },
        diagnostics: [diagnostic("recovery_required")],
        capabilities: { editing: false, execution: false },
      },
    },
    {
      name: "an invalid adopted configuration",
      response: {
        ...readySnapshot,
        source: { ...source, baseRevisionToken: nextRevisionToken },
        state: "invalid",
        diagnostics: [
          {
            ...diagnostic(),
            code: "semantic_validation_failed",
          },
        ],
        capabilities: { editing: true, execution: false },
      },
    },
    {
      name: "creation-required after adoption",
      response: {
        state: "creation_required",
        source: {
          baseRevisionToken: nextRevisionToken,
          configurationPath: "",
          dotenvPaths: [],
          runtimeManifestId: source.runtimeManifestId,
        },
        diagnostics: [],
        capabilities: { editing: false, execution: false },
      },
    },
  ])("rejects recovery success reporting $name", async ({ response }) => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(response)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.resolveRecovery(
        baseRevisionToken,
        "adopt_current",
        "edit",
        source.configurationPath,
        source.runtimeManifestId,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("accepts creation-required only after discarding unapplied creation", async () => {
    const creationRequired = {
      state: "creation_required",
      source: {
        baseRevisionToken: nextRevisionToken,
        configurationPath: "",
        dotenvPaths: [],
        runtimeManifestId: source.runtimeManifestId,
      },
      diagnostics: [],
      capabilities: { editing: false, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(creationRequired)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.resolveRecovery(
        baseRevisionToken,
        "discard_unapplied",
        "creation",
        source.configurationPath,
        source.runtimeManifestId,
      ),
    ).resolves.toEqual(creationRequired);
  });

  it("rejects an adopted state after discarding unapplied creation", async () => {
    const adopted = {
      ...readySnapshot,
      source: { ...source, baseRevisionToken: nextRevisionToken },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(adopted)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.resolveRecovery(
        baseRevisionToken,
        "discard_unapplied",
        "creation",
        source.configurationPath,
        source.runtimeManifestId,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("accepts a repairable invalid base after discarding an unapplied edit", async () => {
    const originalInvalid = {
      ...readySnapshot,
      source: { ...source, baseRevisionToken: nextRevisionToken },
      state: "invalid",
      diagnostics: [
        {
          ...diagnostic(),
          code: "semantic_validation_failed",
        },
      ],
      capabilities: { editing: true, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(originalInvalid)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.resolveRecovery(
        baseRevisionToken,
        "discard_unapplied",
        "edit",
        source.configurationPath,
        source.runtimeManifestId,
      ),
    ).resolves.toEqual(originalInvalid);
  });

  it.each([
    {
      name: "an extra top-level property",
      value: { ...readySnapshot, rawYaml: "secret-value" },
    },
    {
      name: "a secret projection value",
      value: {
        ...readySnapshot,
        projection: [
          {
            fieldId: "account.eab.hmac_key",
            bindings: [{ id: "account", value: "home" }],
            label: "External account binding secret",
            kind: "secret",
            present: true,
            configured: true,
            defaulted: false,
            presenceKnown: true,
            value: "secret-value",
          },
        ],
      },
    },
    {
      name: "an invalid logical binding identifier",
      value: {
        ...readySnapshot,
        projection: [
          {
            ...readySnapshot.projection[0],
            bindings: [{ id: "AccountName", value: "home" }],
          },
          readySnapshot.projection[1],
        ],
      },
    },
    {
      name: "a public configured field without its effective value",
      value: {
        ...readySnapshot,
        projection: [
          readySnapshot.projection[0],
          {
            fieldId: "workspace.storage",
            bindings: [],
            label: "Native storage directory",
            kind: "string",
            present: true,
            configured: true,
            defaulted: false,
            presenceKnown: true,
          },
        ],
      },
    },
    {
      name: "an incorrectly sized opaque revision token",
      value: {
        ...readySnapshot,
        source: { ...source, baseRevisionToken: "a".repeat(64) },
      },
    },
    {
      name: "execution enabled for unsupported content",
      value: {
        ...readySnapshot,
        state: "unsupported",
        diagnostics: [diagnostic()],
        capabilities: { editing: true, execution: true },
      },
    },
    {
      name: "a noncanonical dotenv list",
      value: {
        ...readySnapshot,
        source: {
          ...source,
          dotenvPaths: ["/srv/lego/z.env", "/srv/lego/a.env"],
        },
      },
    },
  ])("rejects $name", async ({ value }) => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(value)),
    });

    await expect(client.getConfiguration()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("sends exact preview and save bodies with CSRF while never echoing a secret", async () => {
    const secret = "test-only-super-secret";
    const changes: ConfigurationChange[] = [
      {
        fieldId: "account.eab.hmac_key",
        bindings: [{ id: "account", value: "home" }],
        operation: "set",
        value: secret,
      },
    ];
    const preview = {
      state: "review_required",
      baseRevisionToken,
      reviewedPreviewToken,
      resultingState: "ready",
      summary: [
        {
          fieldId: "account.eab.hmac_key",
          bindings: [{ id: "account", value: "home" }],
          label: "External account binding secret",
          file: "configuration",
          action: "secret_replaced",
          sensitive: true,
          before: { state: "present_secret" },
          after: { state: "present_secret" },
        },
      ],
      diagnostics: [],
      executionAllowed: true,
    };
    const saved = {
      ...readySnapshot,
      source: { ...source, baseRevisionToken: nextRevisionToken },
    };
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(preview))
      .mockResolvedValueOnce(jsonResponse(saved));
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    const reviewed = await client.previewChanges(baseRevisionToken, changes);
    const result = await client.saveChanges(
      baseRevisionToken,
      source.configurationPath,
      source.runtimeManifestId,
      changes,
      reviewedPreviewToken,
    );

    expect(JSON.stringify(reviewed)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(request).toHaveBeenNthCalledWith(
      1,
      "/api/v1/configuration/previews",
      expect.objectContaining({
        body: JSON.stringify({ baseRevisionToken, changes }),
        method: "POST",
      }),
    );
    expect(request).toHaveBeenNthCalledWith(
      2,
      "/api/v1/configuration",
      expect.objectContaining({
        body: JSON.stringify({
          baseRevisionToken,
          changes,
          reviewedPreviewToken,
        }),
        method: "PUT",
      }),
    );
    for (const call of request.mock.calls) {
      const headers = new Headers(call[1]?.headers);
      expect(headers.get("X-AcmeMux-CSRF")).toBe("csrf-token");
      expect(headers.get("Content-Type")).toBe("application/json");
    }
  });

  it("rejects an edit save response that remains invalid", async () => {
    const invalid = {
      ...readySnapshot,
      state: "invalid",
      diagnostics: [
        {
          ...diagnostic(),
          code: "semantic_validation_failed",
          fieldId: "certificate.domains",
          bindings: [{ id: "certificate", value: "home" }],
        },
      ],
      capabilities: { editing: true, execution: false },
    };
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(invalid)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.saveChanges(
        baseRevisionToken,
        source.configurationPath,
        source.runtimeManifestId,
        [
          {
            fieldId: "certificate.domains",
            bindings: [{ id: "certificate", value: "home" }],
            operation: "set",
            value: ["home.example.com"],
          },
        ],
        reviewedPreviewToken,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it.each([
    {
      name: "the stale base revision",
      response: readySnapshot,
    },
    {
      name: "a different native target",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          configurationPath: "/srv/other/.lego.yml",
        },
      },
    },
    {
      name: "a different runtime manifest",
      response: {
        ...readySnapshot,
        source: {
          ...source,
          baseRevisionToken: nextRevisionToken,
          runtimeManifestId: "lego-v5.4.0",
        },
      },
    },
  ])("rejects edit save success reporting $name", async ({ response }) => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () => jsonResponse(response)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.saveChanges(
        baseRevisionToken,
        source.configurationPath,
        source.runtimeManifestId,
        [
          {
            fieldId: "workspace.storage",
            bindings: [],
            operation: "set",
            value: "./other-data",
          },
        ],
        reviewedPreviewToken,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("rejects a preview summary that represents a secret as a value", async () => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "review_required",
          baseRevisionToken,
          reviewedPreviewToken,
          resultingState: "ready",
          summary: [
            {
              fieldId: "account.eab.hmac_key",
              bindings: [{ id: "account", value: "home" }],
              label: "External account binding secret",
              file: "configuration",
              action: "secret_replaced",
              sensitive: true,
              before: { state: "present_secret" },
              after: { state: "value", value: "secret-value" },
            },
          ],
          diagnostics: [],
          executionAllowed: true,
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.previewChanges(baseRevisionToken, [
        {
          fieldId: "account.eab.hmac_key",
          bindings: [{ id: "account", value: "home" }],
          operation: "remove",
        },
      ]),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("treats a missing mutation CSRF cookie as an ended session", async () => {
    const request = vi.fn<typeof fetch>();
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "",
    });

    await expect(
      client.previewChanges(baseRevisionToken, [
        {
          fieldId: "workspace.storage",
          bindings: [],
          operation: "set",
          value: "./data",
        },
      ]),
    ).rejects.toMatchObject({
      code: "authentication_required",
      status: 401,
    });
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects malformed changes before a request", async () => {
    const request = vi.fn<typeof fetch>();
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.previewChanges(baseRevisionToken, [
        {
          fieldId: "workspace.storage",
          bindings: [],
          operation: "set",
          value: "./data",
        },
        {
          fieldId: "workspace.storage",
          bindings: [],
          operation: "remove",
        },
      ]),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects malformed bindings before a request", async () => {
    const request = vi.fn<typeof fetch>();
    const client = createConfigurationClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.previewChanges(baseRevisionToken, [
        {
          fieldId: "account.eab.hmac_key",
          bindings: [{ id: "account", value: "home\nlab" }],
          operation: "set",
          value: "replacement-secret",
        },
      ]),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(request).not.toHaveBeenCalled();
  });

  it.each([
    {
      status: 401,
      bodyCode: "service_busy",
      expected: "authentication_required",
    },
    { status: 403, bodyCode: "service_busy", expected: "request_not_allowed" },
    { status: 421, bodyCode: "service_busy", expected: "request_not_allowed" },
    {
      status: 409,
      bodyCode: "configuration_changed",
      expected: "configuration_changed",
    },
    { status: 429, bodyCode: "service_busy", expected: "service_busy" },
    {
      status: 503,
      bodyCode: "service_unavailable",
      expected: "service_unavailable",
    },
  ])(
    "maps protected and continuity status $status to $expected",
    async ({ status, bodyCode, expected }) => {
      const client = createConfigurationClient({
        fetch: vi.fn(async () =>
          jsonResponse(
            { error: { code: bodyCode, message: "Do not reflect this body." } },
            { status },
          ),
        ),
      });

      const error = await client.getConfiguration().catch((reason) => reason);
      expect(error).toBeInstanceOf(ConfigurationRequestError);
      expect(error).toMatchObject({ code: expected, status });
      expect(String(error)).not.toContain("Do not reflect");
    },
  );

  it("rejects a preview bound to another base revision", async () => {
    const client = createConfigurationClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "unchanged",
          baseRevisionToken: nextRevisionToken,
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.previewChanges(baseRevisionToken, [
        {
          fieldId: "workspace.storage",
          bindings: [],
          operation: "set",
          value: "./data",
        },
      ]),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });
});
