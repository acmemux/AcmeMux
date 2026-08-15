import { Component, type ErrorInfo, type ReactNode } from "react";

import { ActionButton } from "./ActionButton";

type ErrorBoundaryState = { failed: boolean };

export class ErrorBoundary extends Component<
  { children: ReactNode },
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("AcmeMux interface error", error, info.componentStack);
  }

  render() {
    if (this.state.failed) {
      return (
        <main className="am-fatal" role="alert">
          <p className="am-kicker">Interface unavailable</p>
          <h1>AcmeMux could not render this view.</h1>
          <p>
            No native operation was started. Reload the interface; if the
            problem continues, inspect the service diagnostics.
          </p>
          <ActionButton onPress={() => window.location.reload()}>
            Reload interface
          </ActionButton>
        </main>
      );
    }
    return this.props.children;
  }
}
