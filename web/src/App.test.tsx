import { render, screen } from "@testing-library/react";

import { App } from "./App";

describe("App", () => {
  it("renders the honest empty application shell", () => {
    window.history.replaceState({}, "", "/");
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "Certificate operations" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Primary navigation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("No native workspace connected"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "No illustrative certificate counts or operation results are shown as live product data.",
      ),
    ).toBeInTheDocument();
  });

  it("loads the isolated component catalog", async () => {
    window.history.replaceState({}, "", "/?catalog=components");
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Component catalog" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Operational status")).toBeInTheDocument();
    expect(
      screen.getByText("Unsupported", {
        selector: ".am-status span:last-child",
      }),
    ).toBeInTheDocument();
  });
});
