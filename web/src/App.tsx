import { lazy, Suspense } from "react";

import { browserSessionClient, type SessionClient } from "./api/session";
import { browserRuntimeClient, type RuntimeClient } from "./api/runtime";
import { browserWorkspaceClient, type WorkspaceClient } from "./api/workspace";
import { AuthBoundary } from "./auth/AuthBoundary";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { RouteLoading } from "./components/RouteLoading";
import { OverviewPage } from "./app/OverviewPage";

const ComponentCatalog = lazy(() => import("./app/ComponentCatalog"));

export function App({
  sessionClient = browserSessionClient,
  runtimeClient = browserRuntimeClient,
  workspaceClient = browserWorkspaceClient,
}: {
  sessionClient?: SessionClient;
  runtimeClient?: RuntimeClient;
  workspaceClient?: WorkspaceClient;
} = {}) {
  const showCatalog =
    import.meta.env.DEV &&
    new URLSearchParams(window.location.search).get("catalog") === "components";

  if (showCatalog) {
    return (
      <ErrorBoundary>
        <Suspense
          fallback={<RouteLoading message="Loading component catalog" />}
        >
          <ComponentCatalog />
        </Suspense>
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      <AuthBoundary client={sessionClient}>
        <OverviewPage
          runtimeClient={runtimeClient}
          workspaceClient={workspaceClient}
        />
      </AuthBoundary>
    </ErrorBoundary>
  );
}
