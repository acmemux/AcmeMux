import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { vi } from "vitest";

import { App } from "../App";
import {
  OperationRequestError,
  type AutomaticSchedule,
  type ActiveOperation,
  type LatestOperation,
  type ManualOperationPreview,
  type OperationClient,
  type OperationPolicy,
  type OperationStatus,
  type TerminalOperationResult,
} from "../api/operations";
import type {
  ConfigurationClient,
  ConfigurationSnapshot,
} from "../api/configuration";
import type { RuntimeClient, RuntimeSnapshot } from "../api/runtime";
import type { SessionClient } from "../api/session";
import type { WorkspaceClient, WorkspaceSnapshot } from "../api/workspace";
import {
  disabledAutomaticSchedule,
  manualOperationPreview,
  operationPolicy,
  partialOperationResult,
  queuedOperation,
  runningOperation,
} from "../../tests/support/operations";
import { readyConfiguration } from "../../tests/support/configuration";
import { supportedRuntime } from "../../tests/support/runtime";
import { readyWorkspace } from "../../tests/support/workspace";

function clone<T>(value: unknown): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

const sessionClient: SessionClient = {
  getSession: vi.fn(async () => ({ state: "authenticated" as const })),
  signIn: vi.fn(async () => ({ state: "authenticated" as const })),
  signOut: vi.fn(async () => undefined),
};

const runtimeClient: RuntimeClient = {
  getRuntime: vi.fn(async () => clone<RuntimeSnapshot>(supportedRuntime)),
  inspectCandidate: vi.fn(),
  adoptCandidate: vi.fn(),
};

const workspaceClient: WorkspaceClient = {
  getWorkspace: vi.fn(async () => clone<WorkspaceSnapshot>(readyWorkspace)),
  inspectCandidate: vi.fn(),
  adoptCandidate: vi.fn(),
};

const configurationClient: ConfigurationClient = {
  getConfiguration: vi.fn(async () =>
    clone<ConfigurationSnapshot>(readyConfiguration),
  ),
  previewChanges: vi.fn(),
  saveChanges: vi.fn(),
  previewCreation: vi.fn(),
  createConfiguration: vi.fn(),
  resolveRecovery: vi.fn(),
};

function operationClientWith({
  status = { state: "idle" },
  latest = { state: "empty" },
  overrides = {},
}: {
  status?: OperationStatus;
  latest?: LatestOperation;
  overrides?: Partial<OperationClient>;
} = {}): OperationClient {
  return {
    getStatus: vi.fn(async () => clone<OperationStatus>(status)),
    getLatest: vi.fn(async () => clone<LatestOperation>(latest)),
    getCancelPolicy: vi.fn(async () => clone<OperationPolicy>(operationPolicy)),
    previewManual: vi.fn(async () =>
      clone<ManualOperationPreview>(manualOperationPreview),
    ),
    enqueueManual: vi.fn(async () => clone<ActiveOperation>(queuedOperation)),
    getAutomaticSchedule: vi.fn(async () =>
      clone<AutomaticSchedule>(disabledAutomaticSchedule),
    ),
    updateAutomaticSchedule: vi.fn(async () =>
      clone<AutomaticSchedule>(disabledAutomaticSchedule),
    ),
    ...overrides,
  };
}

function renderReadyApp(operationClient: OperationClient) {
  return render(
    <App
      configurationClient={configurationClient}
      operationClient={operationClient}
      runtimeClient={runtimeClient}
      sessionClient={sessionClient}
      workspaceClient={workspaceClient}
    />,
  );
}

describe("manual operation experience", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
    vi.clearAllMocks();
  });

  it("configures one typed daily automatic schedule and shows local plus UTC time", async () => {
    const saved: AutomaticSchedule = {
      state: "scheduled",
      enabled: true,
      timeZone: "America/Denver",
      localTime: "03:35",
      nextEvaluationAt: "2030-01-02T10:35:00Z",
      lastTriggeredAt: null,
      reasonCode: "schedule_saved",
    };
    const updateAutomaticSchedule = vi.fn<
      OperationClient["updateAutomaticSchedule"]
    >(async () => clone<AutomaticSchedule>(saved));
    const client = operationClientWith({
      overrides: { updateAutomaticSchedule },
    });
    renderReadyApp(client);

    expect(
      await screen.findByRole("heading", {
        name: "Automatic renewal evaluation",
      }),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("checkbox", { name: /Enable daily evaluation/i }),
    );
    fireEvent.change(screen.getByLabelText(/IANA time zone/i), {
      target: { value: "America/Denver" },
    });
    fireEvent.change(screen.getByLabelText(/Local evaluation time/i), {
      target: { value: "03:35" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save automatic schedule" }),
    );

    await waitFor(() =>
      expect(updateAutomaticSchedule).toHaveBeenCalledWith({
        enabled: true,
        timeZone: "America/Denver",
        localTime: "03:35",
      }),
    );
    expect(await screen.findByText("03:35 America/Denver")).toBeInTheDocument();
    expect(screen.getByText("2030-01-02T10:35:00Z")).toBeInTheDocument();
    expect(screen.getByText(/no cron syntax or backlog/i)).toBeInTheDocument();
    expect(
      screen.getByText(/upstream lego alone applies ARI/i),
    ).toBeInTheDocument();
  });

  it("explains deferred automatic evaluation without presenting a backlog or retry", async () => {
    const deferred: AutomaticSchedule = {
      state: "deferred",
      enabled: true,
      timeZone: "UTC",
      localTime: "03:35",
      nextEvaluationAt: "2030-01-01T03:35:00Z",
      lastTriggeredAt: null,
      reasonCode: "operation_active",
    };
    const client = operationClientWith({
      overrides: {
        getAutomaticSchedule: vi.fn(async () => deferred),
      },
    });
    renderReadyApp(client);

    expect(
      await screen.findByText("Due evaluation is deferred", { exact: true }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/one coalesced evaluation remains due/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/never replayed automatically/i),
    ).toBeInTheDocument();
  });

  it("reviews semantic whole-workspace intent before enqueueing only the opaque token", async () => {
    const client = operationClientWith();
    renderReadyApp(client);

    const previewButton = await screen.findByRole(
      "button",
      { name: "Preview manual workspace operation" },
      { timeout: 3_000 },
    );
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);

    const dialog = await screen.findByRole("dialog");
    expect(
      screen.getByRole("heading", { name: "Review manual lego operation" }),
    ).toBeInTheDocument();
    expect(dialog).toHaveTextContent("/srv/lego/.lego.yml");
    expect(dialog).toHaveTextContent("gateway.home.example");
    expect(dialog).toHaveTextContent("Configured certificates");
    expect(dialog).toHaveTextContent("2 name-sorted");
    expect(dialog).toHaveTextContent(
      "AcmeMux revalidates the complete native sources before execution",
    );
    expect(dialog).toHaveTextContent("Browser cancellation is not supported");
    expect(dialog).not.toHaveTextContent(/every certificate|native order/i);
    expect(dialog).not.toHaveTextContent(
      manualOperationPreview.reviewedPreviewToken,
    );
    expect(dialog).not.toHaveTextContent(
      /argv|environment variable|private key/i,
    );

    const start = screen.getByRole("button", {
      name: "Start reviewed operation",
    });
    expect(start).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed the runtime, native paths, configured certificate targets/i,
      }),
    );
    expect(start).toBeEnabled();
    fireEvent.click(start);

    await waitFor(() =>
      expect(client.enqueueManual).toHaveBeenCalledWith(
        manualOperationPreview.reviewedPreviewToken,
      ),
    );
    expect(client.enqueueManual).toHaveBeenCalledTimes(1);
    expect(
      await screen.findByRole("heading", { name: "Operation queued" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /cancel operation/i }),
    ).toBeNull();
  });

  it("shows an active durable operation even when current setup is unavailable", async () => {
    const unselectedRuntime: RuntimeClient = {
      ...runtimeClient,
      getRuntime: vi.fn(async () => ({ state: "unselected" as const })),
    };
    const client = operationClientWith({
      status: {
        state: "active",
        operation: clone<ActiveOperation>(runningOperation),
      },
    });
    render(
      <App
        operationClient={client}
        runtimeClient={unselectedRuntime}
        sessionClient={sessionClient}
        workspaceClient={workspaceClient}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Operation running" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Closing or navigating away/)).toBeInTheDocument();
    expect(
      within(screen.getByLabelText("System signal")).getByText("Running", {
        exact: true,
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Operations" })).toHaveAttribute(
      "href",
      "#manual-operation",
    );
  });

  it("renders partial, not-attempted, ambiguity, inventory, and redacted output evidence", async () => {
    const client = operationClientWith({
      latest: {
        state: "available",
        result: clone<TerminalOperationResult>(partialOperationResult),
      },
    });
    renderReadyApp(client);

    expect(
      await screen.findByRole(
        "heading",
        { name: "Partially completed" },
        { timeout: 3_000 },
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText("not attempted").length).toBeGreaterThan(0);
    expect(
      screen.getByText("External state may have changed"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Do not retry blindly/)).toBeInTheDocument();
    expect(
      screen.getByText("2 native certificates were observed."),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByText("Show redacted upstream transcript", { exact: true }),
    );
    expect(screen.getByText(/gateway completed/)).toBeInTheDocument();
    expect(screen.getByText(/media failed/)).toBeInTheDocument();
  });

  it.each([
    ["succeeded", "Succeeded"],
    ["failed", "Failed"],
    ["not_attempted", "Not attempted"],
    ["timed_out", "Timed out"],
    ["interrupted", "Interrupted"],
    ["incompatible", "Incompatible"],
    ["ambiguous", "Outcome ambiguous"],
  ] as const)(
    "renders the %s latest-result state with a safe next action",
    async (state, label) => {
      const result = clone<TerminalOperationResult>(partialOperationResult);
      result.state = state;
      result.reasonCode = `execution_${state}`;
      renderReadyApp(
        operationClientWith({ latest: { state: "available", result } }),
      );

      expect(
        await screen.findByRole("heading", { name: label }),
      ).toBeInTheDocument();
      expect(screen.getByText(/Safe next action:/)).toBeInTheDocument();
    },
  );

  it("does not retry when the enqueue response is lost and reconciles status once", async () => {
    const getStatus = vi
      .fn<OperationClient["getStatus"]>()
      .mockResolvedValue({ state: "idle" });
    const getLatest = vi
      .fn<OperationClient["getLatest"]>()
      .mockResolvedValue({ state: "empty" });
    const enqueueManual = vi.fn<OperationClient["enqueueManual"]>(async () => {
      throw new OperationRequestError("network_failure", 0);
    });
    const client = operationClientWith({
      overrides: { enqueueManual, getLatest, getStatus },
    });
    renderReadyApp(client);

    const previewButton = await screen.findByRole(
      "button",
      { name: "Preview manual workspace operation" },
      { timeout: 3_000 },
    );
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);
    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: /I reviewed the runtime, native paths, configured certificate targets/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start reviewed operation" }),
    );

    expect(
      await screen.findByText("Enqueue outcome unknown", { exact: true }),
    ).toBeInTheDocument();
    expect(screen.getByText(/did not retry/i)).toBeInTheDocument();
    expect(enqueueManual).toHaveBeenCalledTimes(1);
    expect(getStatus).toHaveBeenCalledTimes(2);
    expect(getLatest).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", {
        name: "Preview manual workspace operation",
      }),
    ).toBeDisabled();
  });

  it("refreshes native evidence when a lost enqueue response is already terminal", async () => {
    const getStatus = vi
      .fn<OperationClient["getStatus"]>()
      .mockResolvedValue({ state: "idle" });
    const getLatest = vi
      .fn<OperationClient["getLatest"]>()
      .mockResolvedValueOnce({ state: "empty" })
      .mockResolvedValue({
        state: "available",
        result: clone<TerminalOperationResult>(partialOperationResult),
      });
    const enqueueManual = vi.fn<OperationClient["enqueueManual"]>(async () => {
      throw new OperationRequestError("network_failure", 0);
    });
    const client = operationClientWith({
      overrides: { enqueueManual, getLatest, getStatus },
    });
    renderReadyApp(client);

    const previewButton = await screen.findByRole(
      "button",
      { name: "Preview manual workspace operation" },
      { timeout: 3_000 },
    );
    await waitFor(() => expect(previewButton).toBeEnabled());
    const workspaceCalls = vi.mocked(workspaceClient.getWorkspace).mock.calls
      .length;
    const configurationCalls = vi.mocked(configurationClient.getConfiguration)
      .mock.calls.length;
    fireEvent.click(previewButton);
    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: /I reviewed the runtime, native paths, configured certificate targets/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start reviewed operation" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Partially completed" }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(workspaceClient.getWorkspace).toHaveBeenCalledTimes(
        workspaceCalls + 1,
      ),
    );
    await waitFor(() =>
      expect(configurationClient.getConfiguration).toHaveBeenCalledTimes(
        configurationCalls + 1,
      ),
    );
    expect(enqueueManual).toHaveBeenCalledTimes(1);
  });

  it("reloads authoritative status when another accepted operation wins the enqueue race", async () => {
    const getStatus = vi
      .fn<OperationClient["getStatus"]>()
      .mockResolvedValueOnce({ state: "idle" })
      .mockResolvedValue({
        state: "active",
        operation: clone<ActiveOperation>(runningOperation),
      });
    const enqueueManual = vi.fn<OperationClient["enqueueManual"]>(async () => {
      throw new OperationRequestError("operation_active", 409);
    });
    const client = operationClientWith({
      overrides: { enqueueManual, getStatus },
    });
    renderReadyApp(client);

    const previewButton = await screen.findByRole(
      "button",
      { name: "Preview manual workspace operation" },
      { timeout: 3_000 },
    );
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);
    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: /I reviewed the runtime, native paths, configured certificate targets/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Start reviewed operation" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Operation running" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/already active/)).toBeInTheDocument();
    expect(enqueueManual).toHaveBeenCalledTimes(1);
    expect(getStatus).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", {
        name: "Preview native configuration changes",
      }),
    ).toBeDisabled();
  });

  it("polls active work to a terminal result without sending a cancel or retry", async () => {
    let status: OperationStatus = {
      state: "active",
      operation: clone<ActiveOperation>(runningOperation),
    };
    let latest: LatestOperation = { state: "empty" };
    const client = operationClientWith({
      overrides: {
        getStatus: vi.fn(async () => clone<OperationStatus>(status)),
        getLatest: vi.fn(async () => clone<LatestOperation>(latest)),
      },
    });
    renderReadyApp(client);

    expect(
      await screen.findByRole("heading", { name: "Operation running" }),
    ).toBeInTheDocument();

    status = { state: "idle" };
    latest = {
      state: "available",
      result: clone<TerminalOperationResult>(partialOperationResult),
    };

    expect(
      await screen.findByRole(
        "heading",
        { name: "Partially completed" },
        { timeout: 3_000 },
      ),
    ).toBeInTheDocument();
    expect(client.enqueueManual).not.toHaveBeenCalled();
  });
});
