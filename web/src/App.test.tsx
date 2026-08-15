import { render, screen } from "@testing-library/react";

import { App } from "./App";

describe("App", () => {
  it("states the native ownership boundary", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "AcmeMux" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Upstream lego will continue to own/),
    ).toBeInTheDocument();
  });
});
