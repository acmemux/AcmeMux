import type { ReactNode } from "react";

import { useOptionalAuthenticatedSession } from "../auth/AuthBoundary";
import { ActionButton } from "../components/ActionButton";
import { BrandMark } from "../components/BrandMark";
import { StatusBadge } from "../components/StatusBadge";

const navigation = [
  { label: "Overview", state: "current" },
  { label: "Certificates", state: "planned" },
  { label: "Configuration", state: "planned" },
  { label: "Operations", state: "available", href: "#manual-operation" },
  { label: "Workspace", state: "planned" },
  { label: "Settings", state: "planned" },
] as const;

export function AppShell({
  children,
  isCatalog = false,
  operationStatus = "Unavailable",
  runtimeStatus = "Not connected",
  workspaceStatus = "Not adopted",
}: {
  children: ReactNode;
  isCatalog?: boolean;
  operationStatus?: string;
  runtimeStatus?: string;
  workspaceStatus?: string;
}) {
  const session = useOptionalAuthenticatedSession();
  if (!isCatalog && !session) {
    throw new Error("Authenticated session context is unavailable");
  }

  return (
    <div className="am-shell">
      <a className="am-skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="am-topbar">
        <a className="am-brand" href="/" aria-label="AcmeMux overview">
          <BrandMark decorative />
          <span>
            <strong>AcmeMux</strong>
            <small>Native lego control plane</small>
          </span>
        </a>
        <div className="am-session-controls">
          {session ? (
            <>
              <StatusBadge tone="success">Session active</StatusBadge>
              <span className="am-scope">
                Single administrator / one workspace
              </span>
              <ActionButton
                isDisabled={session.isSigningOut}
                isPending={session.isSigningOut}
                onPress={() => void session.signOut()}
                variant="quiet"
              >
                {session.isSigningOut ? "Signing out" : "Sign out"}
              </ActionButton>
            </>
          ) : (
            <>
              <StatusBadge tone="info">Component catalog</StatusBadge>
              <span className="am-scope">Development only</span>
            </>
          )}
        </div>
      </header>

      {session?.signOutError ? (
        <div className="am-session-notice" role="alert">
          <strong>Sign-out not confirmed.</strong>
          <span>{session.signOutError}</span>
        </div>
      ) : null}

      <div className="am-shell__frame">
        <aside className="am-sidebar">
          <nav aria-label="Primary navigation">
            <p className="am-kicker">Control surfaces</p>
            <ul className="am-navigation">
              {navigation.map((item, index) => (
                <li key={item.label}>
                  {item.state === "current" ? (
                    <a href="/" aria-current="page">
                      <span aria-hidden="true">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <strong>{item.label}</strong>
                    </a>
                  ) : item.state === "available" ? (
                    <a href={item.href}>
                      <span aria-hidden="true">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <strong>{item.label}</strong>
                    </a>
                  ) : (
                    <span className="is-planned" aria-disabled="true">
                      <span aria-hidden="true">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <strong>{item.label}</strong>
                      <small>Planned</small>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </nav>

          <section className="am-system-signal" aria-labelledby="system-signal">
            <p className="am-kicker" id="system-signal">
              System signal
            </p>
            <dl>
              <div>
                <dt>Runtime</dt>
                <dd>{runtimeStatus}</dd>
              </div>
              <div>
                <dt>Workspace</dt>
                <dd>{workspaceStatus}</dd>
              </div>
              <div>
                <dt>Managed operation</dt>
                <dd>{operationStatus}</dd>
              </div>
            </dl>
          </section>

          <p className="am-ownership-note">
            Native configuration, accounts, certificates, and private keys
            remain in the upstream lego workspace.
          </p>
        </aside>
        {children}
      </div>
    </div>
  );
}
