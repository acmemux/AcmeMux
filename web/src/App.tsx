import { lazy, Suspense } from "react";

import { ErrorBoundary } from "./components/ErrorBoundary";
import { RouteLoading } from "./components/RouteLoading";
import { OverviewPage } from "./app/OverviewPage";

const ComponentCatalog = lazy(() => import("./app/ComponentCatalog"));

export function App() {
  const showCatalog =
    new URLSearchParams(window.location.search).get("catalog") === "components";

  return (
    <ErrorBoundary>
      {showCatalog ? (
        <Suspense fallback={<RouteLoading />}>
          <ComponentCatalog />
        </Suspense>
      ) : (
        <OverviewPage />
      )}
    </ErrorBoundary>
  );
}
