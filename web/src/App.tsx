import { lazy, Suspense } from "react";

import { browserSessionClient, type SessionClient } from "./api/session";
import { AuthBoundary } from "./auth/AuthBoundary";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { RouteLoading } from "./components/RouteLoading";
import { OverviewPage } from "./app/OverviewPage";

const ComponentCatalog = lazy(() => import("./app/ComponentCatalog"));

export function App({
  sessionClient = browserSessionClient,
}: {
  sessionClient?: SessionClient;
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
        <OverviewPage />
      </AuthBoundary>
    </ErrorBoundary>
  );
}
