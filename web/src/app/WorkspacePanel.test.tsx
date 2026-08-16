import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { vi } from "vitest";
import type { ComponentProps } from "react";

import { App as ProductApp } from "../App";
import type { ConfigurationClient } from "../api/configuration";
import type {
  RuntimeCandidate,
  RuntimeClient,
  RuntimeEvidence,
  RuntimeSnapshot,
} from "../api/runtime";
import type { SessionClient } from "../api/session";
import {
  WorkspaceRequestError,
  type CertificateInventoryItem,
  type WorkspaceCandidate,
  type WorkspaceClient,
  type WorkspaceDiagnostic,
  type WorkspaceEvidence,
  type WorkspaceSnapshot,
} from "../api/workspace";
import { WorkspacePanel, type WorkspaceController } from "./WorkspacePanel";
import { idleOperationClient } from "../../tests/support/operations";

const runtimeEvidence: RuntimeEvidence = {
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
    uid: 0,
    gid: 0,
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

const supportedRuntimeClient: RuntimeClient = {
  getRuntime: vi.fn(async () => ({
    state: "supported" as const,
    runtime: runtimeEvidence,
    compatibility: {
      state: "supported" as const,
      code: "compatible" as const,
      manifestId: "lego-v5.3.1",
      summary: "Exact release and platform match.",
    },
  })),
  inspectCandidate: vi.fn(),
  adoptCandidate: vi.fn(),
};

const authenticatedSession: SessionClient = {
  getSession: vi.fn(async () => ({ state: "authenticated" as const })),
  signIn: vi.fn(async () => ({ state: "authenticated" as const })),
  signOut: vi.fn(async () => undefined),
};

const readyConfigurationClient: ConfigurationClient = {
  getConfiguration: vi.fn(async () => ({
    state: "ready" as const,
    source: {
      baseRevisionToken: "A".repeat(43),
      configurationPath: "/srv/lego/.lego.yml",
      dotenvPaths: ["/srv/lego/cloudflare.env"],
      runtimeManifestId: "lego-v5.3.1",
    },
    projection: [],
    diagnostics: [],
    capabilities: { editing: true, execution: true },
  })),
  previewChanges: vi.fn(),
  saveChanges: vi.fn(),
  previewCreation: vi.fn(),
  createConfiguration: vi.fn(),
  resolveRecovery: vi.fn(),
};

function App(props: ComponentProps<typeof ProductApp>) {
  return (
    <ProductApp
      configurationClient={readyConfigurationClient}
      operationClient={idleOperationClient}
      {...props}
    />
  );
}

const pathMetadata = {
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
      ...pathMetadata,
      mode: finalMode,
      nlink: type === "regular_file" ? 1 : pathMetadata.nlink,
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
  artifact: {
    nativePath: "/srv/lego/data/certificates/gateway.home.example.crt",
    ...pathMetadata,
    mode: "0640",
    nlink: 1,
    sizeBytes: 2834,
  },
};

const reviewCandidate: WorkspaceCandidate = {
  state: "review_required",
  candidate: workspaceEvidence,
  reviewedEvidenceSha256: "b".repeat(64),
  adoptable: true,
  diagnostics: [],
};

const readySnapshot: WorkspaceSnapshot = {
  state: "ready",
  workspace: workspaceEvidence,
  inventory: [certificate],
  diagnostics: [],
};

function workspaceClientWith(
  snapshot: WorkspaceSnapshot = { state: "unadopted" },
  candidate: WorkspaceCandidate = reviewCandidate,
  overrides: Partial<WorkspaceClient> = {},
): WorkspaceClient {
  return {
    getWorkspace: vi.fn(async () => snapshot),
    inspectCandidate: vi.fn(async () => candidate),
    adoptCandidate: vi.fn(async () => readySnapshot),
    ...overrides,
  };
}

async function inspectWorkspace(
  workingDirectory = "/srv/lego",
  configurationPath = "",
) {
  const workingDirectoryField = await screen.findByLabelText(
    "Effective working directory",
  );
  await waitFor(() => expect(workingDirectoryField).toBeEnabled());
  fireEvent.change(workingDirectoryField, {
    target: { value: workingDirectory },
  });
  if (configurationPath) {
    fireEvent.change(
      screen.getByLabelText("Explicit configuration path (optional)"),
      { target: { value: configurationPath } },
    );
  }
  await act(async () =>
    fireEvent.click(screen.getByRole("button", { name: "Inspect workspace" })),
  );
}

describe("workspace adoption", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("loads workspace status only after runtime trust settles", async () => {
    let resolveRuntime: (snapshot: RuntimeSnapshot) => void = () => undefined;
    const pendingRuntime = new Promise<RuntimeSnapshot>((resolve) => {
      resolveRuntime = resolve;
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(() => pendingRuntime),
    };
    const workspaceClient = workspaceClientWith();

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await waitFor(() =>
      expect(runtimeClient.getRuntime).toHaveBeenCalledTimes(1),
    );
    expect(workspaceClient.getWorkspace).not.toHaveBeenCalled();

    await act(async () =>
      resolveRuntime({
        state: "supported",
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      }),
    );

    await waitFor(() =>
      expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1),
    );
  });

  it("announces the sequenced workspace check after a diagnostic runtime settles", async () => {
    let resolveWorkspace: (snapshot: WorkspaceSnapshot) => void = () =>
      undefined;
    const pendingWorkspace = new Promise<WorkspaceSnapshot>((resolve) => {
      resolveWorkspace = resolve;
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "missing" as const,
        path: "/usr/local/bin/lego",
        diagnostic: {
          code: "path_unavailable" as const,
          message: "The selected executable is missing.",
        },
      })),
    };
    const workspaceClient = workspaceClientWith(
      { state: "unadopted" },
      reviewCandidate,
      { getWorkspace: vi.fn(() => pendingWorkspace) },
    );

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    expect(
      await screen.findByText("Checking adopted workspace status"),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1),
    );

    await act(async () => resolveWorkspace({ state: "unadopted" }));
    await waitFor(() =>
      expect(
        screen.queryByText("Checking adopted workspace status"),
      ).toBeNull(),
    );
  });

  it("blocks runtime interaction while workspace status is in flight", async () => {
    let resolveWorkspace: (snapshot: WorkspaceSnapshot) => void = () =>
      undefined;
    const pendingWorkspace = new Promise<WorkspaceSnapshot>((resolve) => {
      resolveWorkspace = resolve;
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
      inspectCandidate: vi.fn(),
    };
    const workspaceClient = workspaceClientWith(
      { state: "unadopted" },
      reviewCandidate,
      { getWorkspace: vi.fn(() => pendingWorkspace) },
    );

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await waitFor(() =>
      expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1),
    );
    expect(
      screen.getByText("Checking adopted workspace status"),
    ).toBeInTheDocument();
    const inspect = screen.getByRole("button", {
      name: "Inspect executable",
    });
    expect(inspect).toBeDisabled();
    fireEvent.click(inspect);
    expect(runtimeClient.inspectCandidate).not.toHaveBeenCalled();

    await act(async () => resolveWorkspace({ state: "unadopted" }));
    await waitFor(() => expect(inspect).toBeEnabled());
  });

  it("blocks workspace retry while runtime inspection is in flight without reloading on review", async () => {
    let resolveInspection: (candidate: RuntimeCandidate) => void = () =>
      undefined;
    const pendingInspection = new Promise<RuntimeCandidate>((resolve) => {
      resolveInspection = resolve;
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
      inspectCandidate: vi.fn(() => pendingInspection),
    };
    const degraded: WorkspaceSnapshot = {
      state: "inventory_unavailable",
      workspace: workspaceEvidence,
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
    };
    const workspaceClient = workspaceClientWith(degraded);

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await screen.findByText("Certificate inventory unavailable");
    const inspectRuntime = screen.getByRole("button", {
      name: "Inspect executable",
    });
    await waitFor(() => expect(inspectRuntime).toBeEnabled());
    fireEvent.click(inspectRuntime);
    await waitFor(() =>
      expect(runtimeClient.inspectCandidate).toHaveBeenCalledTimes(1),
    );

    const retry = screen.getByRole("button", {
      name: "Check workspace again",
    });
    expect(retry).toBeDisabled();
    fireEvent.click(retry);
    expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1);

    await act(async () =>
      resolveInspection({
        state: "review_required",
        candidate: runtimeEvidence,
        compatibility: {
          state: "supported",
          code: "compatible",
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
        reviewedEvidenceSha256: "b".repeat(64),
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Review executable evidence",
      }),
    ).toBeInTheDocument();
    expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1);
    expect(retry).toBeEnabled();
    expect(
      screen.getByRole("checkbox", { name: /I reviewed the canonical path/i }),
    ).toBeEnabled();
  });

  it("does not re-inventory or self-lock a settled runtime candidate review", async () => {
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
      inspectCandidate: vi.fn(async () => ({
        state: "review_required" as const,
        candidate: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
        reviewedEvidenceSha256: "b".repeat(64),
      })),
    };
    const workspaceClient = workspaceClientWith(readySnapshot);
    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await screen.findByRole("heading", { name: "Native workspace ready" });
    await screen.findByText("Configuration engine ready");
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Inspect executable" }),
      ),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Review executable evidence",
      }),
    ).toBeInTheDocument();
    expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("checkbox", {
        name: /I reviewed the canonical path/i,
      }),
    ).toBeEnabled();
  });

  it("withdraws cached workspace readiness for divergent evidence at the adopted runtime path", async () => {
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
      inspectCandidate: vi.fn(async () => ({
        state: "review_required" as const,
        candidate: { ...runtimeEvidence, sha256: "c".repeat(64) },
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
        reviewedEvidenceSha256: "d".repeat(64),
      })),
    };
    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith(readySnapshot)}
      />,
    );

    await screen.findByRole("heading", { name: "Native workspace ready" });
    await screen.findByText("Configuration engine ready");
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Inspect executable" }),
      ),
    );

    await screen.findByRole("heading", { name: "Review executable evidence" });
    expect(screen.getByText("Workspace recheck required")).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Native workspace ready" }),
    ).toBeNull();
    expect(
      screen.queryByRole("heading", { name: certificate.name }),
    ).toBeNull();
    expect(screen.queryByText("Native workspace connected")).toBeNull();
    expect(screen.queryByText("Workspace trusted")).toBeNull();
  });

  it("requires explicit review of every resolved native path before adoption", async () => {
    const client = workspaceClientWith();
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace();

    expect(
      await screen.findByRole("heading", {
        name: "Review native workspace evidence",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Conventional \.lego\.yml/)).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Effective working directory" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Selected native configuration"),
    ).toBeInTheDocument();
    expect(screen.getByText("Resolved native storage")).toBeInTheDocument();
    expect(screen.getByText("Referenced dotenv 01")).toBeInTheDocument();
    expect(screen.getByText("Referenced webroot 01")).toBeInTheDocument();
    expect(screen.getAllByText("uid 991 / gid 991")).not.toHaveLength(0);
    expect(screen.getAllByText("0750 / 2")).not.toHaveLength(0);
    expect(screen.getByText("./cloudflare.env")).toBeInTheDocument();
    expect(screen.getAllByText("/srv/lego/cloudflare.env")).not.toHaveLength(0);
    expect(screen.queryByText("259 / 81000")).toBeNull();
    fireEvent.click(
      screen.getAllByText(/Show .* traversed path components/)[0]!,
    );
    expect(await screen.findAllByText("259 / 81000")).not.toHaveLength(0);

    const adopt = screen.getByRole("button", {
      name: "Adopt reviewed workspace",
    });
    expect(adopt).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    );
    expect(adopt).toBeEnabled();
    await act(async () => fireEvent.click(adopt));

    await waitFor(() =>
      expect(client.adoptCandidate).toHaveBeenCalledWith(
        "/srv/lego",
        null,
        "b".repeat(64),
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "Native workspace ready" }),
    ).toHaveFocus();
  });

  it("explains that pending native configuration recovery blocks workspace changes", async () => {
    const client = workspaceClientWith(
      { state: "unadopted" },
      reviewCandidate,
      {
        inspectCandidate: vi.fn(async () => {
          throw new WorkspaceRequestError("recovery_required", 409);
        }),
      },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace();

    expect(
      await screen.findByText("Workspace unavailable"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Native configuration recovery is required. Reconcile the interrupted edit before inspecting or adopting workspace paths.",
      ),
    ).toBeInTheDocument();
  });

  it("returns precise inventory evidence and resets confirmation when adoption is blocked", async () => {
    const blockedCandidate: WorkspaceCandidate = {
      ...reviewCandidate,
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
    const client = workspaceClientWith(
      { state: "unadopted" },
      reviewCandidate,
      { adoptCandidate: vi.fn(async () => blockedCandidate) },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    );
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Adopt reviewed workspace" }),
      ),
    );

    expect(await screen.findByText("inventory_busy")).toBeInTheDocument();
    expect(
      screen.getByText(
        /Another bounded native inventory inspection is running/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adoption blocked" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    ).toBeNull();
  });

  it("keeps explicit configuration selection separate from effective working directory", async () => {
    const explicitEvidence: WorkspaceEvidence = {
      ...workspaceEvidence,
      configuration: {
        source: "explicit",
        path: pathEvidence(
          "/etc/lego/home.yaml",
          "/etc/lego/home.yaml",
          "regular_file",
        ),
      },
    };
    const client = workspaceClientWith(
      { state: "unadopted" },
      { ...reviewCandidate, candidate: explicitEvidence },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace("/srv/lego", "/etc/lego/home.yaml");

    expect(
      await screen.findByText(/Explicit configuration path$/),
    ).toBeInTheDocument();
    expect(client.inspectCandidate).toHaveBeenCalledWith(
      "/srv/lego",
      "/etc/lego/home.yaml",
    );
  });

  it("keeps real unsafe path evidence visible while blocking adoption", async () => {
    const unsafeEvidence: WorkspaceEvidence = {
      ...workspaceEvidence,
      dotenv: [
        {
          ...workspaceEvidence.dotenv[0]!,
          status: "unsafe",
          access: { readable: true, writable: false, searchable: false },
          safe: false,
        },
      ],
    };
    const client = workspaceClientWith(
      { state: "unadopted" },
      {
        ...reviewCandidate,
        candidate: unsafeEvidence,
        adoptable: false,
        diagnostics: [
          {
            code: "symlink_not_allowed",
            severity: "blocking",
            role: "dotenv",
            message: "A symlink was observed.",
            path: "/srv/lego/cloudflare.env",
            component: "/srv/lego/cloudflare.env",
          },
        ],
      },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace();

    expect(await screen.findByText("symlink_not_allowed")).toBeInTheDocument();
    expect(screen.getAllByText("/srv/lego/cloudflare.env")).not.toHaveLength(0);
    expect(screen.getByText("Unsafe")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adoption blocked" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    ).toBeNull();
  });

  it("shows unresolved storage as absent evidence for a missing configuration", async () => {
    const missingConfiguration = {
      ...workspaceEvidence.configuration.path,
      status: "missing" as const,
      access: { readable: false, writable: false, searchable: false },
      type: "missing" as const,
      metadata: null,
      components: workspaceEvidence.configuration.path.components.slice(0, -1),
      safe: false,
    };
    const unresolvedStorage = {
      configuredPath: null,
      canonicalPath: null,
      status: "unresolved" as const,
      access: { readable: false, writable: false, searchable: false },
      type: "unresolved" as const,
      metadata: null,
      components: [],
      safe: false,
    };
    const client = workspaceClientWith(
      { state: "unadopted" },
      {
        ...reviewCandidate,
        candidate: {
          ...workspaceEvidence,
          configuration: {
            source: "conventional_lego_yml",
            path: missingConfiguration,
          },
          storage: unresolvedStorage,
          dotenv: [],
          webroots: [],
        },
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
      },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace();

    expect(
      await screen.findByText("configuration_missing"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Not resolved")).toHaveLength(3);
    expect(
      screen.getByText(
        "No path component evidence exists because this reference could not be resolved.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adoption blocked" }),
    ).toBeDisabled();
  });

  it("distinguishes unavailable traversal evidence from an unresolved reference", async () => {
    const unavailableStorage = {
      ...workspaceEvidence.storage,
      status: "inaccessible" as const,
      access: { readable: false, writable: false, searchable: false },
      type: "unknown" as const,
      metadata: null,
      components: [],
      safe: false,
    };
    const client = workspaceClientWith(
      { state: "unadopted" },
      {
        ...reviewCandidate,
        candidate: { ...workspaceEvidence, storage: unavailableStorage },
        adoptable: false,
        diagnostics: [
          {
            code: "path_unavailable",
            severity: "blocking",
            role: "storage",
            message: "Storage unavailable.",
            path: "/srv/lego/data",
            component: "/srv/lego",
          },
        ],
      },
    );

    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );
    await inspectWorkspace();

    expect(
      await screen.findByText(
        "No traversal component evidence was available for this resolved path audit.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(
        "No path component evidence exists because this reference could not be resolved.",
      ),
    ).toBeNull();
  });

  it("requires a new acknowledgement when the full evidence fingerprint changes", () => {
    const first = reviewCandidate;
    const second: WorkspaceCandidate = {
      ...reviewCandidate,
      candidate: {
        ...workspaceEvidence,
        storage: {
          ...workspaceEvidence.storage,
          components: workspaceEvidence.storage.components.map(
            (component, index, components) =>
              index === components.length - 2
                ? { ...component, inode: "99999" }
                : component,
          ),
        },
      },
      reviewedEvidenceSha256: "c".repeat(64),
    };
    const controller = (
      candidate: WorkspaceCandidate,
    ): WorkspaceController => ({
      adopt: vi.fn(async () => undefined),
      candidate,
      configurationPath: "",
      configurationPathError: null,
      consumeReadyFocus: vi.fn(),
      error: null,
      inspect: vi.fn(async () => undefined),
      phase: "idle",
      readyFocusRequested: false,
      refresh: vi.fn(async () => undefined),
      requestRevision: 1,
      runtimeRecheckRequired: false,
      setConfigurationPath: vi.fn(),
      setWorkingDirectory: vi.fn(),
      snapshot: null,
      workingDirectory: "/srv/lego",
      workingDirectoryError: null,
    });
    const { rerender } = render(
      <WorkspacePanel controller={controller(first)} runtimeReady />,
    );

    const checkbox = screen.getByRole("checkbox", {
      name: /I reviewed the effective working directory/i,
    });
    fireEvent.click(checkbox);
    expect(checkbox).toBeChecked();

    rerender(
      <WorkspacePanel
        key={second.reviewedEvidenceSha256}
        controller={controller(second)}
        runtimeReady
      />,
    );
    expect(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Adopt reviewed workspace" }),
    ).toBeDisabled();
  });

  it("disables a reviewed candidate when runtime trust is no longer ready", () => {
    const controller: WorkspaceController = {
      adopt: vi.fn(async () => undefined),
      candidate: reviewCandidate,
      configurationPath: "",
      configurationPathError: null,
      consumeReadyFocus: vi.fn(),
      error: null,
      inspect: vi.fn(async () => undefined),
      phase: "idle",
      readyFocusRequested: false,
      refresh: vi.fn(async () => undefined),
      requestRevision: 1,
      runtimeRecheckRequired: false,
      setConfigurationPath: vi.fn(),
      setWorkingDirectory: vi.fn(),
      snapshot: readySnapshot,
      workingDirectory: "/srv/lego",
      workingDirectoryError: null,
    };
    const { rerender } = render(
      <WorkspacePanel controller={controller} runtimeReady />,
    );
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    );

    rerender(<WorkspacePanel controller={controller} runtimeReady={false} />);

    expect(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Adopt reviewed workspace" }),
    ).toBeDisabled();
    expect(screen.getAllByText("Compatible runtime required")).not.toHaveLength(
      0,
    );

    rerender(<WorkspacePanel controller={controller} runtimeReady />);
    expect(
      screen.getByRole("checkbox", {
        name: /I reviewed the effective working directory/i,
      }),
    ).not.toBeChecked();
    expect(screen.queryByText("Compatible runtime required")).toBeNull();
  });

  it("loads incompatible workspace evidence after a diagnostic runtime settles", async () => {
    const diagnosticRuntimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "missing" as const,
        path: "/usr/local/bin/lego",
        diagnostic: {
          code: "path_unavailable" as const,
          message: "The selected executable is missing.",
        },
      })),
    };
    const incompatibleWorkspace: WorkspaceSnapshot = {
      state: "incompatible",
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
    };
    const workspaceClient = workspaceClientWith(incompatibleWorkspace);
    render(
      <App
        runtimeClient={diagnosticRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    expect(
      await screen.findByText("Managed operations remain blocked"),
    ).toBeInTheDocument();
    expect(screen.getByText("Setup incomplete")).toBeInTheDocument();
    expect(screen.queryByText("Workspace trusted")).toBeNull();
    expect(
      await screen.findByText("Workspace runtime incompatible"),
    ).toBeInTheDocument();
    expect(
      await screen.findAllByText("Compatible runtime required"),
    ).not.toHaveLength(0);
    expect(screen.queryByRole("heading", { name: "1 certificate" })).toBeNull();
    expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(1);
  });

  it("withdraws effective runtime trust when workspace verification reports incompatibility", async () => {
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
    };
    const incompatible: WorkspaceSnapshot = {
      state: "incompatible",
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
    };
    const getWorkspace = vi
      .fn<WorkspaceClient["getWorkspace"]>()
      .mockResolvedValueOnce(incompatible)
      .mockResolvedValueOnce(readySnapshot);
    const workspaceClient = workspaceClientWith(incompatible, reviewCandidate, {
      getWorkspace,
    });

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await screen.findByText("Workspace runtime incompatible");
    expect(screen.getAllByText("Recheck required")).not.toHaveLength(0);
    expect(screen.getByText("Runtime recheck required")).toBeInTheDocument();
    expect(screen.queryByText("Exact manifest supported")).toBeNull();
    expect(
      screen.getByText("Managed operations remain blocked"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Native workspace connected")).toBeNull();
    expect(screen.queryByText("Workspace trusted")).toBeNull();

    const inspectWorkspaceButton = screen.getByRole("button", {
      name: "Inspect workspace",
    });
    expect(inspectWorkspaceButton).toBeDisabled();
    fireEvent.click(inspectWorkspaceButton);
    expect(workspaceClient.inspectCandidate).not.toHaveBeenCalled();

    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Check workspace again" }),
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "Native workspace ready" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Runtime recheck required")).toBeNull();
    expect(screen.queryByText("Recheck required")).toBeNull();
    expect(screen.getByText("Native workspace connected")).toBeInTheDocument();
    expect(getWorkspace).toHaveBeenCalledTimes(2);
  });

  it("keeps an incompatible workspace refresh failure visible and retryable", async () => {
    const incompatible: WorkspaceSnapshot = {
      state: "incompatible",
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
    };
    let failRefresh = false;
    const getWorkspace = vi.fn<WorkspaceClient["getWorkspace"]>(async () => {
      if (failRefresh) {
        throw new WorkspaceRequestError("network_failure", 0);
      }
      return incompatible;
    });
    const workspaceClient = workspaceClientWith(incompatible, reviewCandidate, {
      getWorkspace,
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
    };

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClient}
      />,
    );

    await screen.findByText("Workspace runtime incompatible");
    failRefresh = true;
    await act(async () =>
      fireEvent.click(
        screen.getByRole("button", { name: "Check workspace again" }),
      ),
    );

    expect(
      await screen.findByText("Workspace unavailable"),
    ).toBeInTheDocument();
    expect(screen.getByText("Runtime recheck required")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Check workspace again" }),
    ).toBeEnabled();
    expect(screen.queryByText("Workspace runtime incompatible")).toBeNull();
  });

  it("shows native certificate inventory without rendering artifact contents", async () => {
    const client = workspaceClientWith(readySnapshot);
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    const readyHeading = await screen.findByRole("heading", {
      name: "Native workspace ready",
    });
    expect(readyHeading).not.toHaveFocus();
    expect(screen.getByText("gateway.home.example")).toBeInTheDocument();
    expect(
      screen.getByText("gateway.home.example, home.example"),
    ).toBeInTheDocument();
    expect(screen.getByText("Let's Encrypt Authority X3")).toBeInTheDocument();
    expect(
      screen.getByText("/srv/lego/data/certificates/gateway.home.example.crt"),
    ).toBeInTheDocument();
    expect(screen.getByText("uid 991 / gid 991 / 0640")).toBeInTheDocument();
    expect(screen.getByText(/Mar 31, 2030.*UTC/)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).toBeNull();
    expect(screen.queryByText(/PRIVATE KEY/)).toBeNull();
  });

  it("pages large native inventory without creating an unbounded tab surface", async () => {
    const inventory = Array.from({ length: 101 }, (_, index) => {
      const name = `certificate-${String(index).padStart(3, "0")}.home.example`;
      return {
        ...certificate,
        name,
        dnsNames: [name],
        artifact: {
          ...certificate.artifact,
          nativePath: `/srv/lego/data/certificates/${name}.crt`,
          inode: String(90_000 + index),
        },
      };
    });
    const client = workspaceClientWith({
      ...readySnapshot,
      inventory,
    });

    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    expect(
      await screen.findByText("Showing 1-50 of 101 certificates"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: inventory[0]!.name }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: inventory[50]!.name }),
    ).toBeNull();
    expect(
      screen.getAllByText("Show complete native artifact evidence"),
    ).toHaveLength(50);

    const next = screen.getByRole("button", { name: "Next certificates" });
    next.focus();
    await act(async () => {
      fireEvent.keyDown(next, { key: "Enter", code: "Enter" });
      fireEvent.keyUp(next, { key: "Enter", code: "Enter" });
    });

    expect(
      await screen.findByText("Showing 51-100 of 101 certificates"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: inventory[0]!.name }),
    ).toBeNull();
    expect(
      screen.getByRole("heading", { name: inventory[50]!.name }),
    ).toBeInTheDocument();
    expect(next).toHaveFocus();
  });

  it("rechecks a degraded adopted workspace without re-adoption", async () => {
    const degraded: WorkspaceSnapshot = {
      state: "inventory_unavailable",
      workspace: workspaceEvidence,
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
    };
    const getWorkspace = vi
      .fn<WorkspaceClient["getWorkspace"]>()
      .mockResolvedValueOnce(degraded)
      .mockResolvedValueOnce(readySnapshot);
    const client = workspaceClientWith(degraded, reviewCandidate, {
      getWorkspace,
    });
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    expect(
      await screen.findByText("Certificate inventory unavailable"),
    ).toBeInTheDocument();
    const retry = screen.getByRole("button", {
      name: "Check workspace again",
    });
    await waitFor(() => expect(retry).toBeEnabled());
    await act(async () => fireEvent.click(retry));

    await waitFor(() => expect(getWorkspace).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByRole("heading", { name: "Native workspace ready" }),
    ).toBeInTheDocument();
    expect(client.adoptCandidate).not.toHaveBeenCalled();
  });

  it("hides prior ready inventory when a bounded refresh fails", async () => {
    let rejectRefresh: (error: unknown) => void = () => undefined;
    const pendingRefresh = new Promise<WorkspaceSnapshot>((_, reject) => {
      rejectRefresh = reject;
    });
    let refreshing = false;
    const getWorkspace = vi.fn<WorkspaceClient["getWorkspace"]>(() =>
      refreshing ? pendingRefresh : Promise.resolve(readySnapshot),
    );
    const client = workspaceClientWith(readySnapshot, reviewCandidate, {
      getWorkspace,
    });
    const runtimeClient: RuntimeClient = {
      ...supportedRuntimeClient,
      getRuntime: vi.fn(async () => ({
        state: "supported" as const,
        runtime: runtimeEvidence,
        compatibility: {
          state: "supported" as const,
          code: "compatible" as const,
          manifestId: "lego-v5.3.1",
          summary: "Exact release and platform match.",
        },
      })),
    };

    render(
      <App
        runtimeClient={runtimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await waitFor(() => expect(getWorkspace).toHaveBeenCalled());
    await screen.findByRole("heading", { name: "Native workspace ready" });
    const initialCalls = getWorkspace.mock.calls.length;
    refreshing = true;
    const refresh = screen.getByRole("button", {
      name: "Check workspace again",
    });
    await waitFor(() => expect(refresh).toBeEnabled());
    fireEvent.click(refresh);
    fireEvent.click(refresh);

    expect(
      await screen.findByText("Checking adopted workspace status"),
    ).toBeInTheDocument();
    expect(screen.queryByText("gateway.home.example")).toBeNull();
    expect(getWorkspace).toHaveBeenCalledTimes(initialCalls + 1);

    await act(async () =>
      rejectRefresh(new WorkspaceRequestError("network_failure", 0)),
    );

    expect(
      await screen.findByText("Workspace unavailable"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Native workspace ready")).toBeNull();
    expect(screen.queryByText("gateway.home.example")).toBeNull();
    expect(screen.queryByText("1 certificate")).toBeNull();

    fireEvent.change(screen.getByLabelText("Effective working directory"), {
      target: { value: "/srv/lego-next" },
    });
    expect(screen.queryByText("Native workspace ready")).toBeNull();
    expect(screen.queryByText("gateway.home.example")).toBeNull();
    expect(screen.queryByText("Native workspace connected")).toBeNull();
  });

  it.each([
    ["changed", "Workspace changed", "review_evidence_changed"],
    ["missing", "Workspace path missing", "path_missing"],
    ["read_only", "Workspace is read only", "path_read_only"],
    ["unsafe", "Workspace safety check failed", "symlink_not_allowed"],
    ["incompatible", "Workspace runtime incompatible", "runtime_unavailable"],
    [
      "inventory_unavailable",
      "Certificate inventory unavailable",
      "inventory_timeout",
    ],
  ] as const)("renders precise %s state", async (state, title, code) => {
    const primary: WorkspaceDiagnostic = {
      code,
      severity: "blocking",
      role: code.startsWith("inventory_")
        ? "inventory"
        : code === "runtime_unavailable"
          ? "runtime"
          : code === "path_missing"
            ? "working_directory"
            : "workspace",
      message: "Safe diagnostic",
      path:
        code === "runtime_unavailable" || code === "review_evidence_changed"
          ? null
          : "/srv/lego",
      component:
        code === "runtime_unavailable" || code === "review_evidence_changed"
          ? null
          : "/srv/lego",
    };
    const reviewChanged: WorkspaceDiagnostic = {
      code: "review_evidence_changed",
      severity: "blocking",
      role: "workspace",
      message: "Evidence changed.",
      path: null,
      component: null,
    };
    const diagnostics =
      state === "changed"
        ? [primary]
        : state === "missing" || state === "read_only" || state === "unsafe"
          ? [primary, reviewChanged]
          : [primary];
    const snapshot: WorkspaceSnapshot = {
      state,
      workspace: workspaceEvidence,
      inventory: [],
      diagnostics,
    };
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith(snapshot)}
      />,
    );

    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.getByText(code)).toBeInTheDocument();
    expect(screen.getByText("Setup incomplete")).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Check workspace again" }),
      ).toBeEnabled(),
    );
  });

  it("validates host paths before inspection", async () => {
    const client = workspaceClientWith();
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    await inspectWorkspace("srv/lego");

    expect(
      await screen.findByText(
        "Enter an absolute Linux working directory beginning with /.",
      ),
    ).toBeInTheDocument();
    expect(client.inspectCandidate).not.toHaveBeenCalled();
  });

  it("returns to authentication when a protected workspace request expires", async () => {
    const client = workspaceClientWith(
      { state: "unadopted" },
      reviewCandidate,
      {
        getWorkspace: vi.fn(async () => {
          throw new WorkspaceRequestError("authentication_required", 401);
        }),
      },
    );
    render(
      <App
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={client}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();
  });
});
