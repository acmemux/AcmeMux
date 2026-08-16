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
      fieldId: "account.eab_hmac",
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
    phase: "idle",
    recoveryEvidenceStale: false,
    recoveryOutcomeUnknown: false,
    requestRevision: 1,
    snapshot,
    refresh: vi.fn(async () => undefined),
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
});
