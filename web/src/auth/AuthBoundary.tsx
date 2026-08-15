import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  SessionRequestError,
  type AuthenticatedSession,
  type SessionClient,
  type SessionSnapshot,
} from "../api/session";
import {
  CheckingSessionPage,
  RequestBlockedPage,
  SessionUnavailablePage,
  SignInPage,
  UninitializedPage,
  type SignInError,
  type SignInNotice,
} from "./AuthPages";

type AuthView =
  | { kind: "checking" }
  | { kind: "uninitialized" }
  | { kind: "signedOut"; notice: SignInNotice }
  | { kind: "expired" }
  | { kind: "authenticated"; session: AuthenticatedSession }
  | { kind: "requestBlocked" }
  | { kind: "unavailable" };

type AuthenticatedSessionContextValue = {
  isSigningOut: boolean;
  signOutError: string | null;
  signOut(): Promise<void>;
};

const AuthenticatedSessionContext =
  createContext<AuthenticatedSessionContextValue | null>(null);

export function useOptionalAuthenticatedSession(): AuthenticatedSessionContextValue | null {
  return useContext(AuthenticatedSessionContext);
}

export function useAuthenticatedSession(): AuthenticatedSessionContextValue {
  const value = useOptionalAuthenticatedSession();
  if (!value) {
    throw new Error("Authenticated session context is unavailable");
  }
  return value;
}

function viewForSession(session: SessionSnapshot): AuthView {
  switch (session.state) {
    case "uninitialized":
      return { kind: "uninitialized" };
    case "signed_out":
      return { kind: "signedOut", notice: null };
    case "expired":
      return { kind: "expired" };
    case "authenticated":
      return { kind: "authenticated", session };
  }
}

function requestView(error: unknown): AuthView {
  if (error instanceof SessionRequestError) {
    if (error.code === "request_not_allowed") {
      return { kind: "requestBlocked" };
    }
    if (error.code === "session_expired") {
      return { kind: "expired" };
    }
    if (error.code === "authentication_required") {
      return { kind: "signedOut", notice: null };
    }
  }
  return { kind: "unavailable" };
}

export function AuthBoundary({
  children,
  client,
}: {
  children: ReactNode;
  client: SessionClient;
}) {
  const [view, setView] = useState<AuthView>({ kind: "checking" });
  const [signInError, setSignInError] = useState<SignInError>(null);
  const [isSigningIn, setIsSigningIn] = useState(false);
  const [isSigningOut, setIsSigningOut] = useState(false);
  const [signOutError, setSignOutError] = useState<string | null>(null);
  const requestVersion = useRef(0);

  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    setView({ kind: "checking" });
    setSignInError(null);
    try {
      const session = await client.getSession();
      if (requestVersion.current === version) {
        setView(viewForSession(session));
      }
    } catch (error) {
      if (requestVersion.current === version) {
        setView(requestView(error));
      }
    }
  }, [client]);

  useEffect(() => {
    const version = ++requestVersion.current;
    void client.getSession().then(
      (session) => {
        if (requestVersion.current === version) {
          setView(viewForSession(session));
        }
      },
      (error: unknown) => {
        if (requestVersion.current === version) {
          setView(requestView(error));
        }
      },
    );
    return () => {
      requestVersion.current += 1;
    };
  }, [client]);

  async function signIn(password: string) {
    setIsSigningIn(true);
    setSignInError(null);
    try {
      const session = await client.signIn(password);
      const nextView = viewForSession(session);
      if (nextView.kind === "signedOut") {
        setView({ kind: "signedOut", notice: null });
        setSignInError("invalid");
      } else {
        setView(nextView);
      }
    } catch (error) {
      if (error instanceof SessionRequestError) {
        if (
          error.code === "invalid_credentials" ||
          error.code === "authentication_required"
        ) {
          setSignInError("invalid");
          return;
        }
        if (error.code === "rate_limited") {
          setSignInError("rateLimited");
          return;
        }
      }
      setView(requestView(error));
    } finally {
      setIsSigningIn(false);
    }
  }

  async function signOut() {
    if (view.kind !== "authenticated") {
      return;
    }
    setIsSigningOut(true);
    setSignOutError(null);
    try {
      await client.signOut();
      setView({ kind: "signedOut", notice: "loggedOut" });
    } catch (error) {
      if (error instanceof SessionRequestError) {
        if (
          error.code === "session_expired" ||
          error.code === "authentication_required"
        ) {
          setView({ kind: "expired" });
          return;
        }
        if (error.code === "request_not_allowed") {
          setView({ kind: "requestBlocked" });
          return;
        }
      }
      setSignOutError(
        "Sign-out could not be confirmed. The current session may still be active.",
      );
    } finally {
      setIsSigningOut(false);
    }
  }

  const authenticatedValue: AuthenticatedSessionContextValue = {
    isSigningOut,
    signOut,
    signOutError,
  };

  switch (view.kind) {
    case "checking":
      return <CheckingSessionPage />;
    case "uninitialized":
      return <UninitializedPage onRetry={() => void refresh()} />;
    case "signedOut":
      return (
        <SignInPage
          error={signInError}
          isSubmitting={isSigningIn}
          notice={view.notice}
          onSignIn={signIn}
        />
      );
    case "expired":
      return (
        <SignInPage
          error={signInError}
          isSubmitting={isSigningIn}
          notice="expired"
          onSignIn={signIn}
        />
      );
    case "requestBlocked":
      return <RequestBlockedPage onRetry={() => void refresh()} />;
    case "unavailable":
      return <SessionUnavailablePage onRetry={() => void refresh()} />;
    case "authenticated":
      return (
        <AuthenticatedSessionContext.Provider value={authenticatedValue}>
          {children}
        </AuthenticatedSessionContext.Provider>
      );
  }
}
