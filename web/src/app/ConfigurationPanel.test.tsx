import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { vi } from "vitest";

import { App } from "../App";
import {
  ConfigurationRequestError,
  type ConfigurationClient,
  type ConfigurationSnapshot,
} from "../api/configuration";
import type { RuntimeClient, RuntimeSnapshot } from "../api/runtime";
import type { SessionClient } from "../api/session";
import type { WorkspaceClient, WorkspaceSnapshot } from "../api/workspace";
import { supportedRuntime } from "../../tests/support/runtime";
import { readyWorkspace } from "../../tests/support/workspace";
import {
  ConfigurationPanel,
  type ConfigurationController,
} from "./ConfigurationPanel";

const baseRevisionToken = "A".repeat(43);
const source = {
  baseRevisionToken,
  configurationPath: "/srv/lego/.lego.yml",
  dotenvPaths: ["/srv/lego/provider.env"],
  runtimeManifestId: "lego-v5.3.1",
};

const readyConfiguration: ConfigurationSnapshot = {
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
};

const creationRequired: ConfigurationSnapshot = {
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

const repairableConfiguration: ConfigurationSnapshot = {
  state: "invalid",
  source,
  projection: [
    {
      fieldId: "workspace.storage",
      bindings: [],
      label: "Native storage directory",
      kind: "string",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: ".lego",
    },
    ...[
      ["account.server", "Certificate authority", "letsencrypt"],
      ["account.email", "Account email", "admin@example.com"],
      ["account.key_type", "Account key type", "EC256"],
    ].map(([fieldId, label, value]) => ({
      fieldId: fieldId!,
      bindings: [{ id: "account", value: "primary" }],
      label: label!,
      kind: "string" as const,
      present: true,
      configured: true as const,
      defaulted: false,
      presenceKnown: true,
      value: value!,
    })),
    {
      fieldId: "account.accepts_terms_of_service",
      bindings: [{ id: "account", value: "primary" }],
      label: "Terms acknowledgement",
      kind: "boolean",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: true,
    },
    ...[
      ["challenge.http.address", "Listener address", ":8080"],
      ["challenge.http.delay", "Validation delay", "0s"],
    ].map(([fieldId, label, value]) => ({
      fieldId: fieldId!,
      bindings: [{ id: "challenge", value: "http-home" }],
      label: label!,
      kind: "string" as const,
      present: true,
      configured: true as const,
      defaulted: false,
      presenceKnown: true,
      value: value!,
    })),
    {
      fieldId: "certificate.domains",
      bindings: [{ id: "certificate", value: "home" }],
      label: "DNS names",
      kind: "string_list",
      present: true,
      configured: true,
      defaulted: false,
      presenceKnown: true,
      value: ["*.home.example.com"],
    },
    ...[
      ["certificate.account", "Account", "primary"],
      ["certificate.challenge", "Challenge", "http-home"],
      ["certificate.key_type", "Certificate key type", "EC256"],
    ].map(([fieldId, label, value]) => ({
      fieldId: fieldId!,
      bindings: [{ id: "certificate", value: "home" }],
      label: label!,
      kind: "string" as const,
      present: true,
      configured: true as const,
      defaulted: false,
      presenceKnown: true,
      value: value!,
    })),
  ],
  diagnostics: [
    {
      code: "semantic_validation_failed",
      severity: "blocking",
      role: "semantic",
      message: "HTTP-01 cannot validate a wildcard DNS name.",
      fieldId: "certificate.domains",
      bindings: [{ id: "certificate", value: "home" }],
      path: "/srv/lego/.lego.yml",
      line: null,
      column: null,
    },
  ],
  capabilities: { editing: true, execution: false },
};

const authenticatedSession: SessionClient = {
  getSession: vi.fn(async () => ({ state: "authenticated" as const })),
  signIn: vi.fn(async () => ({ state: "authenticated" as const })),
  signOut: vi.fn(async () => undefined),
};

const supportedRuntimeClient: RuntimeClient = {
  getRuntime: vi.fn(async () => supportedRuntime as RuntimeSnapshot),
  inspectCandidate: vi.fn(),
  adoptCandidate: vi.fn(),
};

function workspaceClientWith(
  getWorkspace: WorkspaceClient["getWorkspace"] = vi.fn(
    async () => readyWorkspace as WorkspaceSnapshot,
  ),
): WorkspaceClient {
  return {
    getWorkspace,
    inspectCandidate: vi.fn(),
    adoptCandidate: vi.fn(),
  };
}

function configurationClientWith(
  getConfiguration: ConfigurationClient["getConfiguration"] = vi.fn(
    async () => readyConfiguration,
  ),
  overrides: Partial<ConfigurationClient> = {},
): ConfigurationClient {
  return {
    getConfiguration,
    previewChanges: vi.fn(),
    saveChanges: vi.fn(),
    previewCreation: vi.fn(),
    createConfiguration: vi.fn(),
    resolveRecovery: vi.fn(),
    ...overrides,
  };
}

function recoveryConfiguration(
  revisionToken = baseRevisionToken,
): Extract<ConfigurationSnapshot, { state: "recovery_required" }> {
  return {
    state: "recovery_required",
    source: { ...source, baseRevisionToken: revisionToken },
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
      ],
    },
    diagnostics: [
      {
        code: "recovery_required",
        severity: "blocking",
        role: "recovery",
        message: "A replacement requires reconciliation.",
        fieldId: null,
        bindings: [],
        path: "/srv/lego/.lego.yml",
        line: null,
        column: null,
      },
    ],
    capabilities: { editing: false, execution: false },
  };
}

function controllerWith(
  snapshot: ConfigurationSnapshot,
): ConfigurationController {
  return {
    error: null,
    mutationError: null,
    mutationPhase: "idle",
    phase: "idle",
    recoveryEvidenceStale: false,
    recoveryOutcomeUnknown: false,
    requestRevision: 1,
    snapshot,
    refresh: vi.fn(async () => undefined),
    previewChanges: vi.fn(async () => null),
    savePrepared: vi.fn(async () => false),
    resolveRecovery: vi.fn(async () => undefined),
  };
}

describe("configuration mediation", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("loads configuration only after runtime and workspace trust settle", async () => {
    let resolveWorkspace: (snapshot: WorkspaceSnapshot) => void = () =>
      undefined;
    const pendingWorkspace = new Promise<WorkspaceSnapshot>((resolve) => {
      resolveWorkspace = resolve;
    });
    const getConfiguration = vi.fn(async () => readyConfiguration);

    render(
      <App
        configurationClient={configurationClientWith(getConfiguration)}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith(vi.fn(() => pendingWorkspace))}
      />,
    );

    await screen.findByText("Checking adopted workspace status");
    expect(getConfiguration).not.toHaveBeenCalled();

    await act(async () =>
      resolveWorkspace(readyWorkspace as WorkspaceSnapshot),
    );
    await waitFor(() => expect(getConfiguration).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText("Configuration engine ready"),
    ).toBeInTheDocument();
  });

  it("previews a runtime-bound creation before workspace adoption", async () => {
    const previewCreation = vi.fn<ConfigurationClient["previewCreation"]>(
      async () => ({ state: "unchanged", baseRevisionToken }),
    );
    render(
      <App
        configurationClient={configurationClientWith(
          vi.fn(async () => creationRequired),
          { previewCreation },
        )}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith(
          vi.fn(async () => ({ state: "unadopted" as const })),
        )}
      />,
    );

    await screen.findByText("Prepare the first supported configuration");
    fireEvent.change(screen.getByLabelText("Working directory"), {
      target: { value: "/srv/lego" },
    });
    fireEvent.change(screen.getByLabelText("Account email"), {
      target: { value: "admin@example.com" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /acknowledge this CA's subscriber agreement/i,
      }),
    );
    fireEvent.change(screen.getByLabelText("DNS names"), {
      target: { value: "home.example.com" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Preview native workspace creation",
      }),
    );

    await waitFor(() => expect(previewCreation).toHaveBeenCalledTimes(1));
    const [token, workingDirectory, configurationPath, changes] =
      previewCreation.mock.calls[0]!;
    expect(token).toBe(baseRevisionToken);
    expect(workingDirectory).toBe("/srv/lego");
    expect(configurationPath).toBeNull();
    expect(changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          fieldId: "challenge.http.delay",
          operation: "set",
          value: "0s",
        }),
        expect.objectContaining({
          fieldId: "certificate.renew.days",
          operation: "set",
          value: 0,
        }),
        expect.objectContaining({
          fieldId: "certificate.renew.reuse_key",
          operation: "set",
          value: false,
        }),
        expect.objectContaining({
          fieldId: "certificate.renew.disable_random_sleep",
          operation: "set",
          value: false,
        }),
        expect.objectContaining({
          fieldId: "certificate.renew.ari.disable",
          operation: "set",
          value: false,
        }),
        expect.objectContaining({
          fieldId: "certificate.renew.ari.wait_to_renew_duration",
          operation: "set",
          value: "0s",
        }),
      ]),
    );
  });

  it("blocks runtime and workspace controls while configuration status is in flight", async () => {
    let resolveConfiguration: (snapshot: ConfigurationSnapshot) => void = () =>
      undefined;
    const pending = new Promise<ConfigurationSnapshot>((resolve) => {
      resolveConfiguration = resolve;
    });
    render(
      <App
        configurationClient={configurationClientWith(vi.fn(() => pending))}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText("Checking native configuration support");
    expect(
      screen.getByRole("button", { name: "Inspect executable" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Check workspace again" }),
    ).toBeDisabled();

    await act(async () => resolveConfiguration(readyConfiguration));
    await screen.findByText("Configuration engine ready");
    expect(
      screen.getByRole("button", { name: "Inspect executable" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Check workspace again" }),
    ).toBeEnabled();
  });

  it("keeps runtime and workspace mutations disabled while configuration recovery is pending", async () => {
    render(
      <App
        configurationClient={configurationClientWith(
          vi.fn(async () => recoveryConfiguration()),
        )}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText(/will not replay or roll back/);
    expect(
      screen.getByRole("button", { name: "Inspect executable" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Check workspace again" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Inspect workspace" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", {
        name: /I repaired the active files and removed the interrupted staging entries/,
      }),
    ).toBeEnabled();
  });

  it("returns to authentication when protected configuration access expires", async () => {
    render(
      <App
        configurationClient={configurationClientWith(
          vi.fn(async () => {
            throw new ConfigurationRequestError("authentication_required", 401);
          }),
        )}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Configuration mediation")).toBeNull();
  });

  it("reloads current evidence after an unconfirmed recovery response before re-enabling actions", async () => {
    const recovery = recoveryConfiguration();
    const reloaded = recoveryConfiguration("B".repeat(43));
    const getConfiguration = vi
      .fn<ConfigurationClient["getConfiguration"]>()
      .mockResolvedValueOnce(recovery)
      .mockResolvedValueOnce(reloaded);
    const resolveRecovery = vi.fn<ConfigurationClient["resolveRecovery"]>(
      async () => {
        throw new ConfigurationRequestError("network_failure", 0);
      },
    );

    render(
      <App
        configurationClient={configurationClientWith(getConfiguration, {
          resolveRecovery,
        })}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText(/will not replay or roll back/);
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I repaired the active files and removed the interrupted staging entries/,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Validate and adopt current files",
      }),
    );

    expect(
      await screen.findByText("Recovery outcome unknown"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Current native configuration evidence was reloaded/),
    ).toBeInTheDocument();
    expect(getConfiguration).toHaveBeenCalledTimes(2);
    expect(resolveRecovery).toHaveBeenCalledWith(
      baseRevisionToken,
      "adopt_current",
      "edit",
      "/srv/lego/.lego.yml",
      "lego-v5.3.1",
    );
    expect(document.body).not.toHaveTextContent("No native files were changed");

    const adopt = screen.getByRole("button", {
      name: "Validate and adopt current files",
    });
    expect(adopt).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I repaired the active files and removed the interrupted staging entries/,
      }),
    );
    expect(adopt).toBeEnabled();
  });

  it("retains failed recovery evidence as read-only when the immediate recheck also fails", async () => {
    const recovery = recoveryConfiguration();
    const getConfiguration = vi
      .fn<ConfigurationClient["getConfiguration"]>()
      .mockResolvedValueOnce(recovery)
      .mockRejectedValueOnce(
        new ConfigurationRequestError("service_unavailable", 503),
      );
    const resolveRecovery = vi.fn<ConfigurationClient["resolveRecovery"]>(
      async () => {
        throw new ConfigurationRequestError("network_failure", 0);
      },
    );

    render(
      <App
        configurationClient={configurationClientWith(getConfiguration, {
          resolveRecovery,
        })}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText(/will not replay or roll back/);
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I repaired the active files and removed the interrupted staging entries/,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Validate and adopt current files",
      }),
    );

    expect(
      await screen.findByText("Recovery outcome unknown"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/recovery evidence below predates that request/i),
    ).toBeInTheDocument();
    expect(screen.getByText("Recovery required")).toBeInTheDocument();
    expect(getConfiguration).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("checkbox", {
        name: /I repaired the active files and removed the interrupted staging entries/,
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", {
        name: "Validate and adopt current files",
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Check configuration again" }),
    ).toBeEnabled();
    expect(document.body).not.toHaveTextContent("No native files were changed");
  });

  it("presents projection counts without rendering native or secret field values", () => {
    const { container } = render(
      <ConfigurationPanel controller={controllerWith(readyConfiguration)} />,
    );

    expect(screen.getByText("Configuration engine ready")).toBeInTheDocument();
    expect(screen.getByText("2 known")).toBeInTheDocument();
    expect(screen.getAllByText("1")).toHaveLength(2);
    expect(container).not.toHaveTextContent("./data");
    expect(container).not.toHaveTextContent(baseRevisionToken);
  });

  it("preserves an effective unsupported challenge during an unrelated edit", async () => {
    const unsupported: ConfigurationSnapshot = {
      ...repairableConfiguration,
      state: "unsupported",
      projection: repairableConfiguration.projection
        .filter((field) => !field.fieldId.startsWith("challenge.http."))
        .map((field) => {
          if (
            field.fieldId === "certificate.domains" &&
            field.configured &&
            field.kind === "string_list"
          ) {
            return { ...field, value: ["home.example.com"] };
          }
          if (
            field.fieldId === "certificate.challenge" &&
            field.configured &&
            field.kind === "string"
          ) {
            return {
              ...field,
              present: false,
              defaulted: true,
              value: "tls-alpn-01",
            };
          }
          return field;
        }),
      diagnostics: [
        {
          code: "unsupported_challenge",
          severity: "blocking",
          role: "semantic",
          message: "The effective TLS-ALPN challenge is preserved.",
          fieldId: "certificate.challenge",
          bindings: [{ id: "certificate", value: "home" }],
          path: "/srv/lego/.lego.yml",
          line: null,
          column: null,
        },
      ],
      capabilities: { editing: true, execution: false },
    };
    const previewChanges = vi.fn<ConfigurationClient["previewChanges"]>(
      async () => ({ state: "unchanged", baseRevisionToken }),
    );
    render(
      <App
        configurationClient={configurationClientWith(
          vi.fn(async () => unsupported),
          { previewChanges },
        )}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText("Native content unsupported");
    fireEvent.change(screen.getByLabelText("Storage directory"), {
      target: { value: "./other-data" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Preview native configuration changes",
      }),
    );

    await waitFor(() => expect(previewChanges).toHaveBeenCalledTimes(1));
    expect(previewChanges).toHaveBeenCalledWith(baseRevisionToken, [
      {
        fieldId: "workspace.storage",
        bindings: [],
        operation: "set",
        value: "./other-data",
      },
    ]);
  });

  it("previews and saves a typed repair for curated-invalid native values", async () => {
    const reviewedPreviewToken = "C".repeat(43);
    const previewChanges = vi.fn<ConfigurationClient["previewChanges"]>(
      async () => ({
        state: "review_required",
        baseRevisionToken,
        reviewedPreviewToken,
        resultingState: "ready",
        summary: [
          {
            fieldId: "certificate.domains",
            bindings: [{ id: "certificate", value: "home" }],
            label: "DNS names",
            file: "configuration",
            action: "changed",
            sensitive: false,
            before: { state: "value", value: ["*.home.example.com"] },
            after: { state: "value", value: ["home.example.com"] },
          },
        ],
        diagnostics: [],
        executionAllowed: true,
      }),
    );
    const repaired: ConfigurationSnapshot = {
      ...repairableConfiguration,
      state: "ready",
      projection: repairableConfiguration.projection.map((field) =>
        field.fieldId === "certificate.domains" &&
        field.configured &&
        field.kind === "string_list"
          ? { ...field, value: ["home.example.com"] }
          : field,
      ),
      diagnostics: [],
      capabilities: { editing: true, execution: true },
    };
    const saveChanges = vi.fn<ConfigurationClient["saveChanges"]>(
      async () => repaired,
    );
    render(
      <App
        configurationClient={configurationClientWith(
          vi.fn(async () => repairableConfiguration),
          { previewChanges, saveChanges },
        )}
        runtimeClient={supportedRuntimeClient}
        sessionClient={authenticatedSession}
        workspaceClient={workspaceClientWith()}
      />,
    );

    await screen.findByText("Configuration needs repair");
    fireEvent.change(screen.getByLabelText("DNS names"), {
      target: { value: "home.example.com" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Preview native configuration changes",
      }),
    );
    await waitFor(() => expect(previewChanges).toHaveBeenCalledTimes(1));
    fireEvent.click(
      screen.getByRole("button", { name: "Review 1 native change" }),
    );
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed every affected native file/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Save reviewed changes" }),
    );

    await waitFor(() => expect(saveChanges).toHaveBeenCalledTimes(1));
    expect(saveChanges).toHaveBeenCalledWith(
      baseRevisionToken,
      "/srv/lego/.lego.yml",
      "lego-v5.3.1",
      expect.arrayContaining([
        {
          fieldId: "certificate.domains",
          bindings: [{ id: "certificate", value: "home" }],
          operation: "set",
          value: ["home.example.com"],
        },
      ]),
      reviewedPreviewToken,
    );
    expect(await screen.findByText("Configuration engine ready")).toBeVisible();
  });

  it("keeps source-invalid native content read-only", () => {
    const readOnly: ConfigurationSnapshot = {
      ...repairableConfiguration,
      capabilities: { editing: false, execution: false },
    };
    render(<ConfigurationPanel controller={controllerWith(readOnly)} />);

    expect(screen.getByText("Configuration invalid")).toBeInTheDocument();
    expect(
      screen.queryByText("CA, certificate, and HTTP-01 configuration"),
    ).not.toBeInTheDocument();
  });

  it("presents fixed diagnostic copy for unsupported content", () => {
    const unsupported: ConfigurationSnapshot = {
      ...readyConfiguration,
      state: "unsupported",
      diagnostics: [
        {
          code: "unsupported_provider",
          severity: "blocking",
          role: "semantic",
          message:
            "This native DNS provider is preserved but is not an implemented AcmeMux integration.",
          fieldId: null,
          bindings: [],
          path: "/srv/lego/.lego.yml",
          line: 14,
          column: 7,
        },
      ],
      capabilities: { editing: true, execution: false },
    };
    const { container } = render(
      <ConfigurationPanel controller={controllerWith(unsupported)} />,
    );

    expect(screen.getByText("Native content unsupported")).toBeInTheDocument();
    expect(
      screen.getByText(/native DNS provider is preserved/),
    ).toBeInTheDocument();
    expect(container).toHaveTextContent("implemented AcmeMux integration");
  });

  it.each([
    [
      "ambiguous",
      /I repaired the active files and removed the interrupted staging entries/,
    ],
    [
      "applied",
      /I reviewed the active native files and accept their current path references/,
    ],
  ] as const)(
    "requires explicit confirmation before adopting %s current files",
    (recoveryState, confirmationName) => {
      const recovery: ConfigurationSnapshot = {
        state: "recovery_required",
        source,
        recovery: {
          operation: "edit",
          phase: "replacing",
          state: recoveryState,
          targets: [
            {
              role: "configuration",
              path: "/srv/lego/.lego.yml",
              state: recoveryState,
            },
          ],
        },
        diagnostics: [
          {
            code: "recovery_required",
            severity: "blocking",
            role: "recovery",
            message: "A replacement requires reconciliation.",
            fieldId: null,
            bindings: [],
            path: "/srv/lego/.lego.yml",
            line: null,
            column: null,
          },
        ],
        capabilities: { editing: false, execution: false },
      };
      const controller = controllerWith(recovery);
      render(<ConfigurationPanel controller={controller} />);

      expect(screen.getAllByText("Recovery required")).toHaveLength(2);
      expect(
        screen.getByText(/will not replay or roll back/),
      ).toBeInTheDocument();
      expect(screen.getAllByText(recoveryState)).toHaveLength(2);
      const adopt = screen.getByRole("button", {
        name: "Validate and adopt current files",
      });
      expect(adopt).toBeDisabled();
      fireEvent.click(
        screen.getByRole("checkbox", {
          name: confirmationName,
        }),
      );
      expect(adopt).toBeEnabled();
      fireEvent.click(adopt);
      expect(controller.resolveRecovery).toHaveBeenCalledWith("adopt_current");
    },
  );

  it("requires explicit adoption instead of finalization after interrupted creation", () => {
    const recovery: ConfigurationSnapshot = {
      ...recoveryConfiguration(),
      recovery: {
        operation: "creation",
        phase: "finalizing",
        state: "applied",
        targets: [
          {
            role: "configuration",
            path: "/srv/lego/.lego.yml",
            state: "applied",
          },
        ],
      },
    };
    render(<ConfigurationPanel controller={controllerWith(recovery)} />);

    expect(
      screen.queryByRole("button", {
        name: "Validate and finalize replacement",
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/has no previously adopted workspace to finalize/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "Validate and adopt current files",
      }),
    ).toBeDisabled();
  });
});
