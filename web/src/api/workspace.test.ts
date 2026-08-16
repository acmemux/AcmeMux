import { vi } from "vitest";

import { CSRF_HEADER_NAME } from "./session";
import {
  WorkspaceRequestError,
  createWorkspaceClient,
  workspacePathError,
  type CertificateInventoryItem,
  type WorkspaceEvidence,
} from "./workspace";

type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const metadata = {
  uid: 991,
  gid: 991,
  mode: "0750",
  nlink: 2,
  device: "259",
  inode: "81234",
  sizeBytes: 4096,
  modifiedAt: "2030-01-01T00:00:00Z",
  changedAt: "2030-01-01T00:00:01Z",
} as const;

function pathEvidence(
  configuredPath: string,
  canonicalPath: string,
  type: "directory" | "regular_file",
) {
  const componentPaths = [
    "/",
    ...canonicalPath
      .slice(1)
      .split("/")
      .map((_, index, parts) => `/${parts.slice(0, index + 1).join("/")}`),
  ];
  const finalMode = type === "regular_file" ? "0600" : "0750";
  const finalInode = String(81000 + componentPaths.length - 1);
  return {
    configuredPath,
    canonicalPath,
    status: "available" as const,
    access: {
      readable: true,
      writable: true,
      searchable: type === "directory",
    },
    type,
    metadata: {
      ...metadata,
      mode: finalMode,
      nlink: type === "regular_file" ? 1 : metadata.nlink,
      inode: finalInode,
    },
    components: componentPaths.map((path, index) => ({
      path,
      type: index === componentPaths.length - 1 ? type : ("directory" as const),
      device: "259",
      inode: String(81000 + index),
      mode:
        index === 0
          ? "0755"
          : index === componentPaths.length - 1
            ? finalMode
            : "0750",
      uid: index === 0 ? 0 : 991,
      gid: index === 0 ? 0 : 991,
      access: {
        readable: true,
        writable: index !== 0,
        searchable: index !== componentPaths.length - 1 || type === "directory",
      },
    })),
    safe: true,
  };
}

function unresolvedPathEvidence() {
  return {
    configuredPath: null,
    canonicalPath: null,
    status: "unresolved" as const,
    access: { readable: false, writable: false, searchable: false },
    type: "unresolved" as const,
    metadata: null,
    components: [],
    safe: false,
  };
}

function missingPathEvidence(configuredPath: string, canonicalPath: string) {
  const componentPaths = [
    "/",
    ...canonicalPath
      .slice(1)
      .split("/")
      .map((_, index, parts) => `/${parts.slice(0, index + 1).join("/")}`),
  ].slice(0, -1);
  return {
    configuredPath,
    canonicalPath,
    status: "missing" as const,
    access: { readable: false, writable: false, searchable: false },
    type: "missing" as const,
    metadata: null,
    components: componentPaths.map((path, index) => ({
      path,
      type: "directory" as const,
      device: "259",
      inode: String(81000 + index),
      mode: index === 0 ? "0755" : "0750",
      uid: index === 0 ? 0 : 991,
      gid: index === 0 ? 0 : 991,
      access: {
        readable: true,
        writable: index !== 0,
        searchable: true,
      },
    })),
    safe: false,
  };
}

const workspaceEvidence: WorkspaceEvidence = {
  workingDirectory: pathEvidence("/srv/lego", "/srv/lego", "directory"),
  configuration: {
    source: "conventional_lego_yml",
    path: pathEvidence(
      "/srv/lego/.lego.yml",
      "/srv/lego/.lego.yml",
      "regular_file",
    ),
  },
  storage: pathEvidence("./data", "/srv/lego/data", "directory"),
  dotenv: [
    pathEvidence(
      "./cloudflare.env",
      "/srv/lego/cloudflare.env",
      "regular_file",
    ),
  ],
  webroots: [pathEvidence("./public", "/srv/lego/public", "directory")],
};

const certificate: CertificateInventoryItem = {
  name: "gateway.home.example",
  dnsNames: ["gateway.home.example", "home.example"],
  issuer: "Let's Encrypt Authority X3",
  expiresAt: "2030-03-31T12:30:00Z",
  health: "healthy",
  artifact: {
    nativePath: "/srv/lego/data/certificates/gateway.home.example.crt",
    ...metadata,
    mode: "0640",
    nlink: 1,
    sizeBytes: 2834,
  },
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

describe("workspace client", () => {
  it("decodes complete ready workspace and inventory evidence", async () => {
    const diagnostics = [
      {
        code: "configuration_precedence" as const,
        severity: "notice" as const,
        role: "configuration" as const,
        message: "The yml file wins.",
        path: "/srv/lego/.lego.yml",
        component: "/srv/lego/.lego.yaml",
      },
    ];
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse({
        state: "ready",
        workspace: workspaceEvidence,
        inventory: [certificate],
        diagnostics,
      }),
    );
    const client = createWorkspaceClient({ fetch: request });

    await expect(client.getWorkspace()).resolves.toEqual({
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [certificate],
      diagnostics,
    });
    expect(request).toHaveBeenCalledWith(
      "/api/v1/workspace",
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
        method: "GET",
        redirect: "error",
      }),
    );
  });

  it("accepts a reconciled certificate in a nested native storage directory", async () => {
    const nested = {
      ...certificate,
      artifact: {
        ...certificate.artifact,
        nativePath:
          "/srv/lego/data/certificates/archive/gateway.home.example.crt",
      },
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "ready",
          workspace: workspaceEvidence,
          inventory: [nested],
          diagnostics: [],
        }),
      ),
    });

    await expect(client.getWorkspace()).resolves.toMatchObject({
      state: "ready",
      inventory: [nested],
    });
  });

  it("accepts inventory text at the backend UTF-8 byte limits", async () => {
    const boundedCertificate = {
      ...certificate,
      dnsNames: ["é".repeat(126)],
      issuer: "é".repeat(2048),
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "ready",
          workspace: workspaceEvidence,
          inventory: [boundedCertificate],
          diagnostics: [],
        }),
      ),
    });

    await expect(client.getWorkspace()).resolves.toMatchObject({
      state: "ready",
      inventory: [boundedCertificate],
    });
  });

  it.each([
    {
      name: "overlong multibyte certificate name",
      certificate: {
        ...certificate,
        name: "é".repeat(128),
        artifact: {
          ...certificate.artifact,
          nativePath: `/srv/lego/data/certificates/${"é".repeat(128)}.crt`,
        },
      },
    },
    {
      name: "too many DNS names",
      certificate: {
        ...certificate,
        dnsNames: Array.from(
          { length: 101 },
          (_, index) => `name-${index}.example`,
        ),
      },
    },
    {
      name: "overlong multibyte DNS name",
      certificate: { ...certificate, dnsNames: ["é".repeat(127)] },
    },
    {
      name: "control-bearing issuer",
      certificate: { ...certificate, issuer: "Trusted\tCA" },
    },
    {
      name: "overlong multibyte issuer",
      certificate: { ...certificate, issuer: "é".repeat(2049) },
    },
  ])("rejects $name inventory text", async ({ certificate: invalid }) => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "ready",
          workspace: workspaceEvidence,
          inventory: [invalid],
          diagnostics: [],
        }),
      ),
    });

    await expect(client.getWorkspace()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it.each([
    {
      name: "five-digit final path mode",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          metadata: {
            ...workspaceEvidence.storage.metadata!,
            mode: "00750",
          },
          components: workspaceEvidence.storage.components.map(
            (component, index, components) =>
              index === components.length - 1
                ? { ...component, mode: "00750" }
                : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "five-digit traversal component mode",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map(
            (component, index) =>
              index === 0 ? { ...component, mode: "00750" } : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "five-digit inventory artifact mode",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: { ...certificate.artifact, mode: "00640" },
        },
      ],
    },
    {
      name: "path owner above uint32",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          metadata: {
            ...workspaceEvidence.storage.metadata!,
            uid: 0x1_0000_0000,
          },
          components: workspaceEvidence.storage.components.map(
            (component, index, components) =>
              index === components.length - 1
                ? { ...component, uid: 0x1_0000_0000 }
                : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "component group above uint32",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map(
            (component, index) =>
              index === 0 ? { ...component, gid: 0x1_0000_0000 } : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "artifact owner above uint32",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: { ...certificate.artifact, uid: 0x1_0000_0000 },
        },
      ],
    },
    {
      name: "path device above uint64",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          metadata: {
            ...workspaceEvidence.storage.metadata!,
            device: "18446744073709551616",
          },
          components: workspaceEvidence.storage.components.map(
            (component, index, components) =>
              index === components.length - 1
                ? { ...component, device: "18446744073709551616" }
                : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "component inode above uint64",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map(
            (component, index) =>
              index === 0
                ? { ...component, inode: "18446744073709551616" }
                : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "artifact inode above uint64",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: {
            ...certificate.artifact,
            inode: "18446744073709551616",
          },
        },
      ],
    },
    {
      name: "shared confidential configuration",
      workspace: {
        ...workspaceEvidence,
        configuration: {
          ...workspaceEvidence.configuration,
          path: {
            ...workspaceEvidence.configuration.path,
            metadata: {
              ...workspaceEvidence.configuration.path.metadata!,
              mode: "0640",
              nlink: 2,
            },
            components: workspaceEvidence.configuration.path.components.map(
              (component, index, components) =>
                index === components.length - 1
                  ? { ...component, mode: "0640" }
                  : component,
            ),
          },
        },
      },
      inventory: [],
    },
    {
      name: "unsafe writable traversal ancestor",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map((component) =>
            component.path === "/srv"
              ? { ...component, mode: "0770" }
              : component,
          ),
        },
      },
      inventory: [],
    },
    {
      name: "empty configuration evidence",
      workspace: {
        ...workspaceEvidence,
        configuration: {
          ...workspaceEvidence.configuration,
          path: {
            ...workspaceEvidence.configuration.path,
            metadata: {
              ...workspaceEvidence.configuration.path.metadata!,
              sizeBytes: 0,
            },
          },
        },
      },
      inventory: [],
    },
    {
      name: "multi-linked certificate artifact",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: { ...certificate.artifact, nlink: 2 },
        },
      ],
    },
    {
      name: "oversized certificate artifact",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: {
            ...certificate.artifact,
            sizeBytes: 4 * 1024 * 1024 + 1,
          },
        },
      ],
    },
    {
      name: "writable certificate artifact",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: { ...certificate.artifact, mode: "0664" },
        },
      ],
    },
  ])("rejects $name", async ({ workspace, inventory }) => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "ready",
          workspace,
          inventory,
          diagnostics: [],
        }),
      ),
    });

    await expect(client.getWorkspace()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("accepts a root-owned sticky writable traversal ancestor", async () => {
    const withRootStickyAncestor = (
      path: WorkspaceEvidence["storage"],
    ): WorkspaceEvidence["storage"] => ({
      ...path,
      components: path.components.map((component) =>
        component.path === "/srv"
          ? {
              ...component,
              mode: "1777",
              uid: 0,
              gid: 0,
              access: { readable: true, writable: true, searchable: true },
            }
          : component,
      ),
    });
    const evidence: WorkspaceEvidence = {
      workingDirectory: withRootStickyAncestor(
        workspaceEvidence.workingDirectory,
      ),
      configuration: {
        ...workspaceEvidence.configuration,
        path: withRootStickyAncestor(workspaceEvidence.configuration.path),
      },
      storage: withRootStickyAncestor(workspaceEvidence.storage),
      dotenv: workspaceEvidence.dotenv.map(withRootStickyAncestor),
      webroots: workspaceEvidence.webroots.map(withRootStickyAncestor),
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "ready",
          workspace: evidence,
          inventory: [],
          diagnostics: [],
        }),
      ),
    });

    await expect(client.getWorkspace()).resolves.toMatchObject({
      state: "ready",
      workspace: evidence,
    });
  });

  it("sends exact selection and review bodies with CSRF protection", async () => {
    const responses = [
      {
        state: "review_required",
        candidate: workspaceEvidence,
        reviewedEvidenceSha256: "a".repeat(64),
        adoptable: true,
        diagnostics: [
          {
            code: "configuration_precedence",
            severity: "notice",
            role: "configuration",
            message: "The yml file wins.",
            path: "/srv/lego/.lego.yml",
            component: "/srv/lego/.lego.yaml",
          },
        ],
      },
      {
        state: "ready",
        workspace: workspaceEvidence,
        inventory: [],
        diagnostics: [],
      },
    ];
    const request = vi.fn<FetchImplementation>(async () =>
      jsonResponse(responses.shift()),
    );
    const client = createWorkspaceClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.inspectCandidate("/srv/lego", null),
    ).resolves.toMatchObject({ state: "review_required", adoptable: true });
    await expect(
      client.adoptCandidate("/srv/lego", null, "a".repeat(64)),
    ).resolves.toMatchObject({ state: "ready" });

    const inspection = request.mock.calls[0];
    expect(inspection?.[0]).toBe("/api/v1/workspace/candidates");
    expect(JSON.parse(String(inspection?.[1]?.body))).toEqual({
      workingDirectory: "/srv/lego",
      configurationPath: null,
    });
    expect(new Headers(inspection?.[1]?.headers).get(CSRF_HEADER_NAME)).toBe(
      "csrf-token",
    );

    const adoption = request.mock.calls[1];
    expect(adoption?.[0]).toBe("/api/v1/workspace");
    expect(JSON.parse(String(adoption?.[1]?.body))).toEqual({
      workingDirectory: "/srv/lego",
      configurationPath: null,
      reviewedEvidenceSha256: "a".repeat(64),
    });
  });

  it("treats a missing mutation CSRF cookie as an expired session", async () => {
    const request = vi.fn<FetchImplementation>();
    const client = createWorkspaceClient({
      fetch: request,
      readCookies: () => "",
    });

    await expect(
      client.inspectCandidate("/srv/lego", null),
    ).rejects.toMatchObject({
      code: "authentication_required",
      status: 401,
    });
    expect(request).not.toHaveBeenCalled();
  });

  it("decodes a precise inventory-blocked candidate returned by adoption", async () => {
    const blocked = {
      state: "review_required",
      candidate: workspaceEvidence,
      reviewedEvidenceSha256: "a".repeat(64),
      adoptable: false,
      diagnostics: [
        {
          code: "inventory_busy",
          severity: "blocking",
          role: "inventory",
          message: "Inventory is busy.",
          path: null,
          component: null,
        },
      ],
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () => jsonResponse(blocked)),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.adoptCandidate("/srv/lego", null, "a".repeat(64)),
    ).resolves.toEqual(blocked);
  });

  it("accepts last-reviewed evidence only where the state contract permits it", async () => {
    const changed = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "changed",
          workspace: workspaceEvidence,
          inventory: [],
          diagnostics: [
            {
              code: "review_evidence_changed",
              severity: "blocking",
              role: "workspace",
              message: "A path changed.",
              path: null,
              component: null,
            },
          ],
        }),
      ),
    });
    await expect(changed.getWorkspace()).resolves.toMatchObject({
      state: "changed",
      workspace: workspaceEvidence,
    });

    const missingEvidence: WorkspaceEvidence = {
      ...workspaceEvidence,
      storage: missingPathEvidence("./data", "/srv/lego/data"),
    };
    const missing = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "missing",
          workspace: missingEvidence,
          inventory: [],
          diagnostics: [
            {
              code: "path_missing",
              severity: "blocking",
              role: "storage",
              message: "Path missing.",
              path: "/srv/lego/data",
              component: "/srv/lego/data",
            },
            {
              code: "review_evidence_changed",
              severity: "blocking",
              role: "workspace",
              message: "Evidence changed.",
              path: null,
              component: null,
            },
          ],
        }),
      ),
    });
    await expect(missing.getWorkspace()).resolves.toEqual({
      state: "missing",
      workspace: missingEvidence,
      inventory: [],
      diagnostics: [
        {
          code: "path_missing",
          severity: "blocking",
          role: "storage",
          message: "Path missing.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
        {
          code: "review_evidence_changed",
          severity: "blocking",
          role: "workspace",
          message: "Evidence changed.",
          path: null,
          component: null,
        },
      ],
    });
  });

  it.each([
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [
        {
          code: "service_busy",
          severity: "blocking",
          role: "workspace",
          message: "Unexpected.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "unsafe",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [],
    },
    {
      state: "changed",
      inventory: [],
      diagnostics: [
        {
          code: "review_evidence_changed",
          severity: "blocking",
          role: "workspace",
          message: "Evidence changed.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "missing",
      inventory: [],
      diagnostics: [
        {
          code: "path_missing",
          severity: "blocking",
          role: "storage",
          message: "Path missing.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
        {
          code: "review_evidence_changed",
          severity: "blocking",
          role: "workspace",
          message: "Evidence changed.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "incompatible",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [
        {
          code: "path_missing",
          severity: "blocking",
          role: "storage",
          message: "Path missing.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      state: "inventory_unavailable",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [
        {
          code: "runtime_unavailable",
          severity: "blocking",
          role: "runtime",
          message: "Runtime unavailable.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "incompatible",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "unsafe",
          safe: false,
        },
      },
      inventory: [],
      diagnostics: [
        {
          code: "runtime_unavailable",
          severity: "blocking",
          role: "runtime",
          message: "Runtime unavailable.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "inventory_unavailable",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "unsafe",
          safe: false,
        },
      },
      inventory: [],
      diagnostics: [
        {
          code: "inventory_timeout",
          severity: "blocking",
          role: "inventory",
          message: "Inventory timed out.",
          path: null,
          component: null,
        },
      ],
    },
    {
      state: "missing",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [
        {
          code: "path_missing",
          severity: "blocking",
          role: "storage",
          message: "Path missing.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics: [],
      unexpected: "field",
    },
    {
      state: "ready",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "missing",
          access: { readable: false, writable: false, searchable: false },
        },
      },
      inventory: [],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [{ ...certificate, expiresAt: "tomorrow" }],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [{ ...certificate, expiresAt: "2030-02-31T12:30:00Z" }],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [{ ...certificate, expiresAt: "0000-01-01T00:00:00Z" }],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [{ ...certificate, expiresAt: "2030-01-01T00:00:00.100Z" }],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: {
        ...workspaceEvidence,
        workingDirectory: {
          ...workspaceEvidence.workingDirectory,
          configuredPath: "/opt/lego",
        },
      },
      inventory: [],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: {
        ...workspaceEvidence,
        configuration: {
          source: "conventional_lego_yml",
          path: pathEvidence(
            "/srv/lego/custom.yml",
            "/srv/lego/custom.yml",
            "regular_file",
          ),
        },
      },
      inventory: [],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: {
        ...workspaceEvidence,
        storage: { ...workspaceEvidence.storage, configuredPath: "./other" },
      },
      inventory: [],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [
        {
          ...certificate,
          artifact: {
            ...certificate.artifact,
            nativePath: "/tmp/gateway.home.example.crt",
          },
        },
      ],
      diagnostics: [],
    },
    {
      state: "ready",
      workspace: workspaceEvidence,
      inventory: [{ ...certificate, name: "other.home.example" }],
      diagnostics: [],
    },
    {
      state: "unsafe",
      workspace: workspaceEvidence,
      inventory: [certificate],
      diagnostics: [
        {
          code: "path_permissions_unsafe",
          severity: "blocking",
          role: "storage",
          message: "Unsafe permissions.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
  ])("rejects contradictory or expanded response %#", async (value) => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () => jsonResponse(value)),
    });
    await expect(client.getWorkspace()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it.each([
    {
      state: "missing",
      diagnostic: {
        code: "path_missing",
        severity: "blocking",
        role: "storage",
        message: "Storage missing.",
        path: "/srv/lego/data",
        component: "/srv/lego/data",
      },
    },
    {
      state: "read_only",
      diagnostic: {
        code: "path_read_only",
        severity: "blocking",
        role: "storage",
        message: "Storage is read only.",
        path: "/srv/lego/data",
        component: "/srv/lego/data",
      },
    },
    {
      state: "unsafe",
      diagnostic: {
        code: "path_permissions_unsafe",
        severity: "blocking",
        role: "storage",
        message: "Storage permissions are unsafe.",
        path: "/srv/lego/data",
        component: "/srv/lego/data",
      },
    },
  ])("rejects all-safe evidence for $state", async ({ state, diagnostic }) => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state,
          workspace: workspaceEvidence,
          inventory: [],
          diagnostics: [
            diagnostic,
            {
              code: "review_evidence_changed",
              severity: "blocking",
              role: "workspace",
              message: "Workspace evidence changed.",
              path: null,
              component: null,
            },
          ],
        }),
      ),
    });

    await expect(client.getWorkspace()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("rejects workspace-state diagnostics assigned to the runtime role", async () => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "missing",
          workspace: {
            ...workspaceEvidence,
            storage: missingPathEvidence("./data", "/srv/lego/data"),
          },
          inventory: [],
          diagnostics: [
            {
              code: "path_missing",
              severity: "blocking",
              role: "runtime",
              message: "Wrong diagnostic role.",
              path: "/srv/lego/data",
              component: "/srv/lego/data",
            },
            {
              code: "review_evidence_changed",
              severity: "blocking",
              role: "workspace",
              message: "Workspace evidence changed.",
              path: null,
              component: null,
            },
          ],
        }),
      ),
    });

    await expect(client.getWorkspace()).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it.each([
    {
      state: "missing",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "unsafe",
          safe: false,
        },
      },
      diagnostic: {
        code: "path_missing",
        severity: "blocking",
        role: "storage",
        message: "Fabricated missing classification.",
        path: "/srv/lego/data",
        component: "/srv/lego/data",
      },
    },
    {
      state: "read_only",
      workspace: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "unsafe",
          safe: false,
        },
      },
      diagnostic: {
        code: "path_read_only",
        severity: "blocking",
        role: "storage",
        message: "Fabricated read-only classification.",
        path: "/srv/lego/data",
        component: "/srv/lego/data",
      },
    },
  ])(
    "rejects $state when diagnostics contradict path evidence",
    async ({ state, workspace, diagnostic }) => {
      const client = createWorkspaceClient({
        fetch: vi.fn(async () =>
          jsonResponse({
            state,
            workspace,
            inventory: [],
            diagnostics: [
              diagnostic,
              {
                code: "review_evidence_changed",
                severity: "blocking",
                role: "workspace",
                message: "Workspace evidence changed.",
                path: null,
                component: null,
              },
            ],
          }),
        ),
      });

      await expect(client.getWorkspace()).rejects.toMatchObject({
        code: "invalid_response",
      });
    },
  );

  it("rejects adoptable review evidence containing a blocking diagnostic", async () => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "review_required",
          candidate: workspaceEvidence,
          reviewedEvidenceSha256: "a".repeat(64),
          adoptable: true,
          diagnostics: [
            {
              code: "path_permissions_unsafe",
              severity: "blocking",
              role: "working_directory",
              message: "Unsafe permissions.",
              path: "/srv/lego",
              component: "/srv/lego",
            },
          ],
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    await expect(
      client.inspectCandidate("/srv/lego", null),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("decodes blocked evidence with unresolved storage without fabricating a path", async () => {
    const candidate = {
      ...workspaceEvidence,
      configuration: {
        source: "conventional_lego_yml" as const,
        path: missingPathEvidence("/srv/lego/.lego.yml", "/srv/lego/.lego.yml"),
      },
      storage: unresolvedPathEvidence(),
      dotenv: [],
      webroots: [],
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "review_required",
          candidate,
          reviewedEvidenceSha256: "a".repeat(64),
          adoptable: false,
          diagnostics: [
            {
              code: "configuration_missing",
              severity: "blocking",
              role: "configuration",
              message: "Configuration missing.",
              path: "/srv/lego/.lego.yml",
              component: "/srv/lego",
            },
          ],
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.inspectCandidate("/srv/lego", null),
    ).resolves.toMatchObject({
      state: "review_required",
      adoptable: false,
      candidate: { storage: { status: "unresolved", configuredPath: null } },
    });
  });

  it("preserves unsafe wrong-type and partial traversal evidence", async () => {
    const storage = workspaceEvidence.storage;
    const unsafeStorage = {
      ...storage,
      status: "unsafe" as const,
      type: "regular_file" as const,
      safe: false,
      components: storage.components.map((component, index, components) =>
        index === components.length - 1
          ? { ...component, type: "regular_file" as const }
          : component,
      ),
    };
    const candidate = {
      ...workspaceEvidence,
      storage: unsafeStorage,
    };
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse({
          state: "review_required",
          candidate,
          reviewedEvidenceSha256: "a".repeat(64),
          adoptable: false,
          diagnostics: [
            {
              code: "path_type_unsafe",
              severity: "blocking",
              role: "storage",
              message: "Unexpected path type.",
              path: "/srv/lego/data",
              component: "/srv/lego/data",
            },
          ],
        }),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    await expect(
      client.inspectCandidate("/srv/lego", null),
    ).resolves.toMatchObject({
      adoptable: false,
      candidate: { storage: unsafeStorage },
    });
  });

  it.each([
    {
      name: "inaccessible component",
      path: {
        ...workspaceEvidence.storage,
        status: "inaccessible",
        type: "unknown",
        metadata: null,
        components: workspaceEvidence.storage.components.slice(0, 3),
        access: { readable: false, writable: false, searchable: false },
        safe: false,
      },
      code: "path_unavailable",
      component: "/srv/lego/data",
    },
    {
      name: "intermediate non-directory",
      path: {
        ...workspaceEvidence.storage,
        status: "unsafe",
        type: "unknown",
        metadata: null,
        components: workspaceEvidence.storage.components
          .slice(0, 3)
          .map((component, index, components) =>
            index === components.length - 1
              ? { ...component, type: "regular_file" }
              : component,
          ),
        access: { readable: false, writable: false, searchable: false },
        safe: false,
      },
      code: "component_not_directory",
      component: "/srv/lego",
    },
    {
      name: "intermediate symlink",
      path: {
        ...workspaceEvidence.storage,
        status: "unsafe",
        type: "symlink",
        metadata: null,
        components: workspaceEvidence.storage.components
          .slice(0, 3)
          .map((component, index, components) =>
            index === components.length - 1
              ? { ...component, type: "symlink" }
              : component,
          ),
        access: { readable: false, writable: false, searchable: false },
        safe: false,
      },
      code: "symlink_not_allowed",
      component: "/srv/lego",
    },
  ] as const)(
    "decodes $name partial evidence",
    async ({ path, code, component }) => {
      const client = createWorkspaceClient({
        fetch: vi.fn(async () =>
          jsonResponse({
            state: "review_required",
            candidate: { ...workspaceEvidence, storage: path },
            reviewedEvidenceSha256: "a".repeat(64),
            adoptable: false,
            diagnostics: [
              {
                code,
                severity: "blocking",
                role: "storage",
                message: "Path inspection failed.",
                path: "/srv/lego/data",
                component,
              },
            ],
          }),
        ),
        readCookies: () => "__Host-acmemux_csrf=csrf-token",
      });

      await expect(
        client.inspectCandidate("/srv/lego", null),
      ).resolves.toMatchObject({
        adoptable: false,
        candidate: {
          storage: { status: path.status, components: path.components },
        },
      });
    },
  );

  it.each([
    {
      name: "unrelated traversal component",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map(
            (component, index) =>
              index === 1 ? { ...component, path: "/unrelated" } : component,
          ),
        },
      },
      adoptable: true,
      diagnostics: [],
    },
    {
      name: "unsafe evidence marked adoptable",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          safe: false,
          status: "unsafe",
        },
      },
      adoptable: true,
      diagnostics: [
        {
          code: "path_permissions_unsafe",
          severity: "blocking",
          role: "storage",
          message: "Unsafe permissions.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      name: "unsafe evidence without a blocking diagnostic",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          safe: false,
          status: "unsafe",
        },
      },
      adoptable: false,
      diagnostics: [],
    },
    {
      name: "available evidence marked unsafe",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          safe: false,
        },
      },
      adoptable: false,
      diagnostics: [
        {
          code: "path_permissions_unsafe",
          severity: "blocking",
          role: "storage",
          message: "Unsafe permissions.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      name: "unsafe evidence with only a notice",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          safe: false,
          status: "unsafe",
        },
      },
      adoptable: false,
      diagnostics: [
        {
          code: "configuration_precedence",
          severity: "notice",
          role: "configuration",
          message: "The yml file wins.",
          path: "/srv/lego/.lego.yml",
          component: "/srv/lego/.lego.yaml",
        },
      ],
    },
    {
      name: "blocking code downgraded to notice",
      candidate: workspaceEvidence,
      adoptable: true,
      diagnostics: [
        {
          code: "path_permissions_unsafe",
          severity: "notice",
          role: "storage",
          message: "Unsafe permissions.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      name: "inventory-role diagnostic during path inspection",
      candidate: workspaceEvidence,
      adoptable: false,
      diagnostics: [
        {
          code: "invalid_policy",
          severity: "blocking",
          role: "inventory",
          message: "Inventory policy invalid.",
          path: null,
          component: null,
        },
      ],
    },
    {
      name: "runtime-role diagnostic during path inspection",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          status: "unsafe",
          safe: false,
        },
      },
      adoptable: false,
      diagnostics: [
        {
          code: "path_permissions_unsafe",
          severity: "blocking",
          role: "runtime",
          message: "Wrong diagnostic role.",
          path: "/srv/lego/data",
          component: "/srv/lego/data",
        },
      ],
    },
    {
      name: "precedence notice on an explicit configuration",
      candidate: {
        ...workspaceEvidence,
        configuration: {
          ...workspaceEvidence.configuration,
          source: "explicit",
        },
      },
      adoptable: true,
      diagnostics: [
        {
          code: "configuration_precedence",
          severity: "notice",
          role: "configuration",
          message: "The yml file wins.",
          path: "/srv/lego/.lego.yml",
          component: "/srv/lego/.lego.yaml",
        },
      ],
    },
    {
      name: "precedence notice with the wrong selected path",
      candidate: workspaceEvidence,
      adoptable: true,
      diagnostics: [
        {
          code: "configuration_precedence",
          severity: "notice",
          role: "configuration",
          message: "The yml file wins.",
          path: "/srv/lego/.lego.yaml",
          component: "/srv/lego/.lego.yaml",
        },
      ],
    },
    {
      name: "duplicate precedence notices",
      candidate: workspaceEvidence,
      adoptable: true,
      diagnostics: Array.from({ length: 2 }, () => ({
        code: "configuration_precedence",
        severity: "notice",
        role: "configuration",
        message: "The yml file wins.",
        path: "/srv/lego/.lego.yml",
        component: "/srv/lego/.lego.yaml",
      })),
    },
    {
      name: "safe storage without required write access",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          access: { readable: true, writable: false, searchable: true },
          components: workspaceEvidence.storage.components.map(
            (component, index, components) =>
              index === components.length - 1
                ? {
                    ...component,
                    access: {
                      readable: true,
                      writable: false,
                      searchable: true,
                    },
                  }
                : component,
          ),
        },
      },
      adoptable: true,
      diagnostics: [],
    },
    {
      name: "over-depth traversal evidence",
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: Array.from({ length: 65 }, (_, index) => ({
            ...workspaceEvidence.storage.components[0]!,
            path:
              index === 0
                ? "/"
                : `/${Array.from({ length: index }, () => "d").join("/")}`,
          })),
        },
      },
      adoptable: true,
      diagnostics: [],
    },
  ])(
    "rejects contradictory $name responses",
    async ({ candidate, adoptable, diagnostics }) => {
      const client = createWorkspaceClient({
        fetch: vi.fn(async () =>
          jsonResponse({
            state: "review_required",
            candidate,
            reviewedEvidenceSha256: "a".repeat(64),
            adoptable,
            diagnostics,
          }),
        ),
        readCookies: () => "__Host-acmemux_csrf=csrf-token",
      });
      await expect(
        client.inspectCandidate("/srv/lego", null),
      ).rejects.toMatchObject({ code: "invalid_response" });
    },
  );

  it("maps protected and replacement errors without reflecting response text", async () => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: "workspace_changed",
              message: "secret-bearing YAML fragment",
            },
          },
          { status: 409 },
        ),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    const error = await client
      .adoptCandidate("/srv/lego", null, "a".repeat(64))
      .catch((value) => value);
    expect(error).toBeInstanceOf(WorkspaceRequestError);
    expect(error).toMatchObject({ code: "workspace_changed", status: 409 });
    expect(String(error)).not.toContain("secret-bearing");
  });

  it("preserves a native configuration recovery conflict", async () => {
    const client = createWorkspaceClient({
      fetch: vi.fn(async () =>
        jsonResponse(
          {
            error: {
              code: "recovery_required",
              message: "Do not reflect recovery journal details.",
            },
          },
          { status: 409 },
        ),
      ),
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });

    const error = await client
      .inspectCandidate("/srv/lego", null)
      .catch((value) => value);
    expect(error).toBeInstanceOf(WorkspaceRequestError);
    expect(error).toMatchObject({ code: "recovery_required", status: 409 });
    expect(String(error)).not.toContain("recovery journal details");
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
    { status: 421, bodyCode: "service_busy", expected: "request_not_allowed" },
  ])(
    "keeps protected status $status authoritative over a $bodyCode body",
    async ({ status, bodyCode, expected }) => {
      const client = createWorkspaceClient({
        fetch: vi.fn(async () =>
          jsonResponse(
            { error: { code: bodyCode, message: "Mismatched error." } },
            { status },
          ),
        ),
      });

      await expect(client.getWorkspace()).rejects.toMatchObject({
        code: expected,
        status,
      });
    },
  );

  it("validates explicit absolute paths before making a request", async () => {
    expect(workspacePathError("srv/lego", "working directory")).toMatch(
      /absolute Linux working directory/,
    );
    expect(workspacePathError("", "configuration path", true)).toBeUndefined();

    const request = vi.fn<FetchImplementation>();
    const client = createWorkspaceClient({
      fetch: request,
      readCookies: () => "__Host-acmemux_csrf=csrf-token",
    });
    await expect(
      client.inspectCandidate("srv/lego", null),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(request).not.toHaveBeenCalled();
  });
});
