import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { vi } from "vitest";

import { App } from "./App";
import {
  SessionRequestError,
  type SessionClient,
  type SessionSnapshot,
} from "./api/session";
import type { RuntimeClient, RuntimeSnapshot } from "./api/runtime";

function clientWith(
  session: SessionSnapshot,
  overrides: Partial<SessionClient> = {},
): SessionClient {
  return {
    getSession: vi.fn(async () => session),
    signIn: vi.fn(async () => ({ state: "authenticated" as const })),
    signOut: vi.fn(async () => undefined),
    ...overrides,
  };
}

function runtimeClientWith(
  snapshot: RuntimeSnapshot = { state: "unselected" },
  overrides: Partial<RuntimeClient> = {},
): RuntimeClient {
  return {
    adoptCandidate: vi.fn(async () => snapshot),
    getRuntime: vi.fn(async () => snapshot),
    inspectCandidate: vi.fn(async () => ({
      state: "missing" as const,
      path: "/missing/lego",
      diagnostic: {
        code: "path_unavailable" as const,
        message: "Path not found",
      },
    })),
    ...overrides,
  };
}

describe("App authentication boundary", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("keeps the application shell locked while session state is checked", async () => {
    let resolveSession: (session: SessionSnapshot) => void = () => undefined;
    const pendingSession = new Promise<SessionSnapshot>((resolve) => {
      resolveSession = resolve;
    });
    const getSession = vi.fn(() => pendingSession);

    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "signed_out" }, { getSession })}
      />,
    );

    expect(
      screen.getByRole("heading", { name: "Confirming administrator access" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();

    await act(async () => resolveSession({ state: "signed_out" }));
    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
  });

  it("renders the honest application shell only after authentication", async () => {
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "authenticated" })}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Certificate operations" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Primary navigation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Managed operations remain blocked"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign out" }),
    ).toBeInTheDocument();
  });

  it("keeps the development component catalog independent of the API", async () => {
    window.history.replaceState({}, "", "/?catalog=components");
    const getSession = vi.fn(async () => ({ state: "signed_out" as const }));
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "signed_out" }, { getSession })}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Component catalog" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Operational status")).toBeInTheDocument();
    expect(getSession).not.toHaveBeenCalled();
  });

  it("cannot initialize or recover the administrator through the browser", async () => {
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "uninitialized" })}
      />,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Administrator not initialized",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Administrator password")).toBeNull();
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(
      screen.getByText(/cannot be claimed or initialized/),
    ).toBeInTheDocument();
    expect(screen.getByText("acmemux admin bootstrap")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /create|reset|recover/i }),
    ).toBeNull();
  });

  it("clears and refocuses the password after a uniform sign-in failure", async () => {
    const signIn = vi.fn(async () => {
      throw new SessionRequestError("invalid_credentials", 401);
    });
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "signed_out" }, { signIn })}
      />,
    );

    const password = await screen.findByLabelText("Administrator password");
    fireEvent.change(password, { target: { value: "test-only-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(
      await screen.findByText(
        "Sign-in failed. Check the password and try again.",
      ),
    ).toBeInTheDocument();
    expect(signIn).toHaveBeenCalledWith("test-only-password");
    expect(password).toHaveValue("");
    expect(password).toHaveFocus();
  });

  it("presents an expired session without retrying a prior request", async () => {
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "expired" })}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Session expired")).toBeInTheDocument();
    expect(
      screen.getByText(/no previous request will be retried/i),
    ).toBeInTheDocument();
  });

  it("distinguishes a blocked request from unavailable session state", async () => {
    const blocked = clientWith(
      { state: "signed_out" },
      {
        getSession: vi.fn(async () => {
          throw new SessionRequestError("request_not_allowed", 403);
        }),
      },
    );
    const { unmount } = render(
      <App runtimeClient={runtimeClientWith()} sessionClient={blocked} />,
    );
    expect(
      await screen.findByRole("heading", {
        name: "AcmeMux rejected this browser request",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/permission/i)).toBeNull();

    unmount();
    const unavailable = clientWith(
      { state: "signed_out" },
      {
        getSession: vi.fn(async () => {
          throw new SessionRequestError("network_failure", 0);
        }),
      },
    );
    render(
      <App runtimeClient={runtimeClientWith()} sessionClient={unavailable} />,
    );
    expect(
      await screen.findByRole("heading", {
        name: "Administrator state is unavailable",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("revokes the session before returning to sign-in", async () => {
    const signOut = vi.fn(async () => undefined);
    render(
      <App
        runtimeClient={runtimeClientWith()}
        sessionClient={clientWith({ state: "authenticated" }, { signOut })}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(signOut).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByRole("heading", { name: "Administrator sign in" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Signed out")).toBeInTheDocument();
  });
});
