import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";

import { ActionButton } from "../components/ActionButton";
import { BrandMark } from "../components/BrandMark";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { FormField } from "../components/FormField";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";

type AuthSurfaceProps = {
  status: string;
  tone: StatusTone;
  kicker: string;
  heading: string;
  lede: string;
  children: ReactNode;
};

function AuthSurface({
  status,
  tone,
  kicker,
  heading,
  lede,
  children,
}: AuthSurfaceProps) {
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [heading]);

  return (
    <div className="am-auth-shell">
      <a className="am-skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="am-auth-topbar">
        <div className="am-auth-brand">
          <BrandMark decorative />
          <span>
            <strong>AcmeMux</strong>
            <small>Native lego control plane</small>
          </span>
        </div>
        <span className="am-scope">Single administrator / one workspace</span>
      </header>
      <main className="am-auth-main" id="main-content">
        <section className="am-auth-card" aria-labelledby="auth-heading">
          <div className="am-auth-card__heading">
            <StatusBadge tone={tone}>{status}</StatusBadge>
            <p className="am-kicker">{kicker}</p>
            <h1 id="auth-heading" ref={headingRef} tabIndex={-1}>
              {heading}
            </h1>
            <p className="am-lede">{lede}</p>
          </div>
          <div className="am-auth-card__body">{children}</div>
        </section>
      </main>
    </div>
  );
}

export function CheckingSessionPage() {
  return (
    <AuthSurface
      status="Checking session"
      tone="info"
      kicker="Protected control plane"
      heading="Confirming administrator access"
      lede="AcmeMux is checking the local administrator and browser session before showing any workspace information."
    >
      <div className="am-auth-progress" aria-live="polite" aria-busy="true">
        <span className="am-spinner" aria-hidden="true" />
        <p>Checking administrator session</p>
      </div>
    </AuthSurface>
  );
}

export function UninitializedPage({ onRetry }: { onRetry: () => void }) {
  return (
    <AuthSurface
      status="Local setup required"
      tone="warning"
      kicker="Administrator boundary"
      heading="Administrator not initialized"
      lede="This service cannot be claimed or initialized through a browser."
    >
      <div className="am-auth-instructions">
        <p>
          Run the documented <code>acmemux admin bootstrap</code> command
          interactively on the AcmeMux host. The password is never accepted in
          command arguments or environment variables.
        </p>
        <p>
          After local setup completes, check again to open the password-only
          sign-in screen.
        </p>
      </div>
      <div className="am-auth-actions">
        <ActionButton onPress={onRetry}>Check again</ActionButton>
      </div>
    </AuthSurface>
  );
}

export type SignInError = "invalid" | "rateLimited" | null;
export type SignInNotice = "expired" | "loggedOut" | null;

function signInErrorMessage(error: SignInError): string | undefined {
  switch (error) {
    case "invalid":
      return "Sign-in failed. Check the password and try again.";
    case "rateLimited":
      return "Sign-in is temporarily limited. Wait before trying again.";
    case null:
      return undefined;
  }
}

export function SignInPage({
  error,
  isSubmitting,
  notice,
  onSignIn,
}: {
  error: SignInError;
  isSubmitting: boolean;
  notice: SignInNotice;
  onSignIn: (password: string) => Promise<void>;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const [localError, setLocalError] = useState<string>();
  const serverError = signInErrorMessage(error);
  const displayedError = localError ?? serverError;

  useEffect(() => {
    if (displayedError) {
      passwordRef.current?.focus();
    }
  }, [displayedError]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const password = new FormData(form).get("password");
    if (typeof password !== "string" || password.length === 0) {
      setLocalError("Enter the administrator password.");
      passwordRef.current?.focus();
      return;
    }

    setLocalError(undefined);
    form.reset();
    await onSignIn(password);
  }

  return (
    <AuthSurface
      status={notice === "expired" ? "Session ended" : "Protected access"}
      tone={notice === "expired" ? "warning" : "info"}
      kicker="Administrator boundary"
      heading="Administrator sign in"
      lede="Enter the password configured locally for this single AcmeMux administrator."
    >
      {notice === "expired" ? (
        <FeedbackPanel
          announcement="polite"
          tone="warning"
          title="Session expired"
        >
          <p>
            Your administrator session expired. Sign in again; no previous
            request will be retried automatically.
          </p>
        </FeedbackPanel>
      ) : null}
      {notice === "loggedOut" ? (
        <FeedbackPanel announcement="polite" tone="success" title="Signed out">
          <p>The administrator session was revoked in this browser.</p>
        </FeedbackPanel>
      ) : null}
      <form
        className="am-auth-form"
        onSubmit={(event) => void submit(event)}
        aria-busy={isSubmitting}
        ref={formRef}
      >
        <FormField
          autoComplete="current-password"
          description="Passwords are sent only to this same-origin AcmeMux service."
          errorMessage={displayedError}
          inputRef={passwordRef}
          isDisabled={isSubmitting}
          isInvalid={Boolean(displayedError)}
          isRequired
          label="Administrator password"
          name="password"
          type="password"
        />
        <ActionButton
          isDisabled={isSubmitting}
          isPending={isSubmitting}
          type="submit"
        >
          {isSubmitting ? "Signing in" : "Sign in"}
        </ActionButton>
      </form>
      <p className="am-auth-footnote">
        Password replacement and revocation of all sessions require local host
        access. This browser does not provide account setup or recovery.
      </p>
    </AuthSurface>
  );
}

export function RequestBlockedPage({ onRetry }: { onRetry: () => void }) {
  return (
    <AuthSurface
      status="Request blocked"
      tone="danger"
      kicker="Request integrity"
      heading="AcmeMux rejected this browser request"
      lede="The service could not verify this request against its same-origin security boundary."
    >
      <FeedbackPanel announcement="assertive" tone="danger" title="No retry">
        <p>
          No request was retried. Reload AcmeMux from its configured HTTPS
          address and inspect reverse-proxy settings if the problem continues.
        </p>
      </FeedbackPanel>
      <div className="am-auth-actions">
        <ActionButton onPress={onRetry}>Check session again</ActionButton>
      </div>
    </AuthSurface>
  );
}

export function SessionUnavailablePage({ onRetry }: { onRetry: () => void }) {
  return (
    <AuthSurface
      status="Session unavailable"
      tone="interrupted"
      kicker="Protected control plane"
      heading="Administrator state is unavailable"
      lede="AcmeMux could not safely determine whether this browser has an administrator session."
    >
      <FeedbackPanel
        announcement="assertive"
        tone="interrupted"
        title="Application remains locked"
      >
        <p>
          No workspace information is shown until the same-origin session
          service responds with a valid state.
        </p>
      </FeedbackPanel>
      <div className="am-auth-actions">
        <ActionButton onPress={onRetry}>Try again</ActionButton>
      </div>
    </AuthSurface>
  );
}
