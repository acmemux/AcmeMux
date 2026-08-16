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
import {
  RuntimeRequestError,
  type RuntimeCandidate,
  type RuntimeClient,
  type RuntimeEvidence,
  type RuntimeSnapshot,
} from "../api/runtime";
import type { SessionClient } from "../api/session";
import type { WorkspaceClient } from "../api/workspace";
import { RuntimePanel, type RuntimeController } from "./RuntimePanel";
import { idleOperationClient } from "../../tests/support/operations";

function App(props: ComponentProps<typeof ProductApp>) {
  return <ProductApp operationClient={idleOperationClient} {...props} />;
}

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

const authenticatedSession: SessionClient = {
  getSession: vi.fn(async () => ({ state: "authenticated" as const })),
  signIn: vi.fn(async () => ({ state: "authenticated" as const })),
  signOut: vi.fn(async () => undefined),
};

const unadoptedWorkspaceClient: WorkspaceClient = {
  getWorkspace: vi.fn(async () => ({ state: "unadopted" as const })),
  inspectCandidate: vi.fn(),
  adoptCandidate: vi.fn(),
};

function renderApp(runtimeClient: RuntimeClient) {
  return render(
    <App
      runtimeClient={runtimeClient}
      sessionClient={authenticatedSession}
      workspaceClient={unadoptedWorkspaceClient}
    />,
  );
}

function clientWith(
  snapshot: RuntimeSnapshot,
  candidate: RuntimeCandidate = {
    state: "review_required",
    candidate: evidence,
    compatibility: {
      state: "supported",
      code: "compatible",
      manifestId: "lego-v5.3.1",
      summary: "Exact release and platform match.",
    },
    reviewedEvidenceSha256: "b".repeat(64),
  },
): RuntimeClient {
  return {
    getRuntime: vi.fn(async () => snapshot),
    inspectCandidate: vi.fn(async () => candidate),
    adoptCandidate: vi.fn(async () => ({
      state: "supported" as const,
      runtime: evidence,
      compatibility: {
        state: "supported" as const,
        code: "compatible" as const,
        manifestId: "lego-v5.3.1",
        summary: "Exact release and platform match.",
      },
    })),
  };
}

async function inspectPath(value: string): Promise<void> {
  const path = await screen.findByLabelText("Host executable path");
  const inspect = screen.getByRole("button", { name: "Inspect executable" });
  await waitFor(() => {
    expect(path).toBeEnabled();
    expect(inspect).toBeEnabled();
  });
  fireEvent.change(path, { target: { value } });
  fireEvent.click(inspect);
}

describe("runtime selection", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("requires review of exact evidence before adopting a supported candidate", async () => {
    const client = clientWith({ state: "unselected" });
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(
      await screen.findByRole("heading", {
        name: "Review executable evidence",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("/usr/local/bin/lego")).toBeInTheDocument();
    expect(screen.getAllByText("v5.3.1")).not.toHaveLength(0);
    expect(screen.getAllByText("linux / amd64")).not.toHaveLength(0);
    expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("lego-v5.3.1")).toBeInTheDocument();

    const adopt = screen.getByRole("button", {
      name: "Adopt reviewed executable",
    });
    expect(adopt).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I reviewed the canonical path/i,
      }),
    );
    expect(adopt).toBeEnabled();
    fireEvent.click(adopt);

    await waitFor(() =>
      expect(client.adoptCandidate).toHaveBeenCalledWith(
        evidence,
        "lego-v5.3.1",
        "b".repeat(64),
      ),
    );
    expect(
      await screen.findByText("Runtime ready for workspace adoption"),
    ).toBeInTheDocument();
  });

  it("requires a new acknowledgement when full evidence changes for the same bytes", () => {
    const first: RuntimeCandidate = {
      state: "review_required",
      candidate: evidence,
      compatibility: {
        state: "supported",
        code: "compatible",
        manifestId: "lego-v5.3.1",
        summary: "Exact release and platform match.",
      },
      reviewedEvidenceSha256: "b".repeat(64),
    };
    const second: RuntimeCandidate = {
      ...first,
      candidate: {
        ...evidence,
        canonicalPath: "/opt/acmemux/bin/lego",
        metadata: { ...evidence.metadata, inode: "654321" },
      },
      reviewedEvidenceSha256: "c".repeat(64),
    };
    const controller = (candidate: RuntimeCandidate): RuntimeController => ({
      adopt: vi.fn(async () => undefined),
      candidate,
      error: null,
      inspect: vi.fn(async () => undefined),
      path:
        candidate.state === "review_required"
          ? candidate.candidate.canonicalPath
          : candidate.path,
      pathError: null,
      phase: "idle",
      requestRevision: 1,
      refresh: vi.fn(async () => undefined),
      setPath: vi.fn(),
      snapshot: null,
    });
    const { rerender } = render(
      <RuntimePanel controller={controller(first)} />,
    );

    const checkbox = screen.getByRole("checkbox", {
      name: /I reviewed the canonical path/i,
    });
    fireEvent.click(checkbox);
    expect(checkbox).toBeChecked();
    expect(
      screen.getByRole("button", { name: "Adopt reviewed executable" }),
    ).toBeEnabled();

    rerender(<RuntimePanel controller={controller(second)} />);
    expect(screen.getByText("/opt/acmemux/bin/lego")).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: /I reviewed the canonical path/i,
      }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Adopt reviewed executable" }),
    ).toBeDisabled();
  });

  it("shows unverified evidence but keeps adoption disabled", async () => {
    const client = clientWith(
      { state: "unselected" },
      {
        state: "review_required",
        candidate: {
          ...evidence,
          version: null,
          commit: "2a58c3522708e4c7393a67be691bd0c3a16d8441",
          versionOutput:
            "lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/amd64",
          build: {
            ...evidence.build,
            mainVersion: "v5.3.2-0.20260803101616-2a58c3522708",
            vcsRevision: "2a58c3522708e4c7393a67be691bd0c3a16d8441",
          },
        },
        compatibility: {
          state: "unverified",
          code: "unknown_identity",
          summary:
            "This source identity has not completed compatibility qualification.",
        },
      },
    );
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(await screen.findByText("Support not verified")).toBeInTheDocument();
    expect(
      screen.getByText(
        /only an executable matched by an exact supported manifest/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adoption blocked" }),
    ).toBeDisabled();
    expect(client.adoptCandidate).not.toHaveBeenCalled();
  });

  it("identifies an incompatible candidate without offering adoption", async () => {
    const client = clientWith(
      { state: "unselected" },
      {
        state: "review_required",
        candidate: evidence,
        compatibility: {
          state: "incompatible",
          code: "unsupported_platform",
          summary: "The release is known but outside this platform manifest.",
        },
      },
    );
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(await screen.findByText("Incompatible runtime")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Adoption blocked" }),
    ).toBeDisabled();
  });

  it("announces the bounded probing state", async () => {
    let finishInspection: (candidate: RuntimeCandidate) => void = () =>
      undefined;
    const pending = new Promise<RuntimeCandidate>((resolve) => {
      finishInspection = resolve;
    });
    const client = clientWith({ state: "unselected" });
    client.inspectCandidate = vi.fn(() => pending);
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(
      await screen.findAllByText("Inspecting executable"),
    ).not.toHaveLength(0);
    expect(screen.getByLabelText("Host executable path")).toBeDisabled();

    await act(async () => {
      finishInspection({
        state: "timed_out",
        path: "/usr/local/bin/lego",
        diagnostic: { code: "probe_timeout", message: "Probe timed out" },
      });
    });
    expect(await screen.findAllByText("Candidate blocked")).not.toHaveLength(0);
  });

  it("validates an explicit absolute path without making a request", async () => {
    const client = clientWith({ state: "unselected" });
    renderApp(client);

    await inspectPath("usr/local/bin/lego");

    expect(
      await screen.findByText(
        "Enter an absolute Linux host path beginning with /.",
      ),
    ).toBeInTheDocument();
    expect(client.inspectCandidate).not.toHaveBeenCalled();
  });

  it("explains that pending native configuration recovery blocks runtime changes", async () => {
    const client = clientWith({ state: "unselected" });
    client.inspectCandidate = vi.fn(async () => {
      throw new RuntimeRequestError("recovery_required", 409);
    });
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(await screen.findByText("Runtime unavailable")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Native configuration recovery is required. Reconcile the interrupted edit before inspecting or adopting an executable.",
      ),
    ).toBeInTheDocument();
  });

  it("explains that another native workspace action blocks runtime changes", async () => {
    const client = clientWith({ state: "unselected" });
    client.inspectCandidate = vi.fn(async () => {
      throw new RuntimeRequestError("service_busy", 429);
    });
    renderApp(client);

    await inspectPath("/usr/local/bin/lego");

    expect(await screen.findByText("Runtime unavailable")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Another native workspace action is in progress. Check the runtime again after it finishes.",
      ),
    ).toBeInTheDocument();
  });

  it("invalidates stale supported readiness when a later runtime request fails", async () => {
    const client = clientWith({
      state: "supported",
      runtime: evidence,
      compatibility: {
        state: "supported",
        code: "compatible",
        manifestId: "lego-v5.3.1",
        summary: "Exact release and platform match.",
      },
    });
    client.inspectCandidate = vi.fn(async () => {
      throw new RuntimeRequestError("service_unavailable", 503);
    });
    renderApp(client);

    expect(
      await screen.findByText("Runtime ready for workspace adoption"),
    ).toBeInTheDocument();
    const inspect = screen.getByRole("button", { name: "Inspect executable" });
    await waitFor(() => expect(inspect).toBeEnabled());
    fireEvent.click(inspect);

    expect(await screen.findByText("Runtime unavailable")).toBeInTheDocument();
    expect(
      screen.getByText("Managed operations remain blocked"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Runtime trusted")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Exact manifest supported"),
    ).not.toBeInTheDocument();
  });

  it.each([
    [
      "missing",
      "No file is available at the selected host path",
      "path_unavailable",
    ],
    [
      "unsafe",
      "The selected path is a symlink or crosses one",
      "symlink_not_allowed",
    ],
    [
      "changed",
      "The selected file no longer matches its reviewed identity",
      "executable_replaced",
    ],
    [
      "malformed_output",
      "did not return a recognized lego release or source identity",
      "malformed_version_output",
    ],
    [
      "timed_out",
      "bounded runtime inspection exceeded its deadline",
      "probe_timeout",
    ],
  ] as const)(
    "renders a specific %s block state",
    async (state, message, code) => {
      const client = clientWith({
        state,
        path: "/usr/local/bin/lego",
        diagnostic: { code, message: "Safe backend diagnostic" },
      });
      renderApp(client);

      expect(await screen.findByText(new RegExp(message))).toBeInTheDocument();
      expect(
        screen.getByText("Managed operations remain blocked"),
      ).toBeInTheDocument();
    },
  );

  it("keeps prior reviewed evidence visible and clearly labelled when verification blocks", async () => {
    const client = clientWith({
      state: "changed",
      path: evidence.canonicalPath,
      diagnostic: {
        code: "executable_replaced",
        message: "The executable changed.",
      },
      runtime: evidence,
    });
    renderApp(client);

    const disclosure = await screen.findByText(
      "Show previously reviewed runtime evidence",
    );
    fireEvent.click(disclosure);
    expect(
      screen.getByRole("heading", {
        name: "Previously reviewed executable identity",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(evidence.versionOutput)).toBeInTheDocument();
  });

  it("returns to the locked sign-in surface when a protected runtime request expires", async () => {
    const runtimeClient: RuntimeClient = {
      getRuntime: vi.fn(async () => {
        throw new RuntimeRequestError("authentication_required", 401);
      }),
      inspectCandidate: vi.fn(),
      adoptCandidate: vi.fn(),
    };
    renderApp(runtimeClient);

    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Session expired")).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();
  });
});
