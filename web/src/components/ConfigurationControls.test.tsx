import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { vi } from "vitest";

import { ConfigurationReviewDialog } from "./ConfigurationReviewDialog";
import { WriteOnlySecretField, type SecretDraft } from "./WriteOnlySecretField";

function SecretHarness() {
  const [draft, setDraft] = useState<SecretDraft>({ action: "keep" });
  return (
    <WriteOnlySecretField
      description="A write-only test field."
      draft={draft}
      id="test-secret"
      label="Write-only secret"
      onChange={setDraft}
      presence="present"
    />
  );
}

describe("configuration review controls", () => {
  it("never loads a stored secret and clears replacement input when keep is selected", () => {
    const { container } = render(<SecretHarness />);

    expect(screen.getByText("Present and hidden")).toBeInTheDocument();
    expect(screen.queryByLabelText("New secret value")).toBeNull();

    fireEvent.click(screen.getByLabelText("Replace value"));
    const replacement = screen.getByLabelText("New secret value");
    expect(replacement).toHaveAttribute("type", "password");
    expect(replacement).toHaveValue("");
    fireEvent.change(replacement, { target: { value: "test-only-secret" } });
    expect(replacement).toHaveValue("test-only-secret");

    fireEvent.click(screen.getByLabelText("Keep stored value"));
    expect(screen.queryByLabelText("New secret value")).toBeNull();
    expect(container).not.toHaveTextContent("test-only-secret");
  });

  it("renders only secret presence in review and requires acknowledgement", async () => {
    const confirm = vi.fn();
    render(
      <ConfigurationReviewDialog
        executionAllowed
        onCancel={() => undefined}
        onConfirm={confirm}
        summary={[
          {
            fieldId: "provider.credential",
            bindings: [{ id: "challenge", value: "home" }],
            label: "Provider credential",
            file: "dotenv",
            action: "secret_replaced",
            sensitive: true,
            before: { state: "present_secret" },
            after: { state: "present_secret" },
          },
        ]}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: /Review 1 native change/ }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Review configuration changes",
      }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Stored value present (hidden)")).toHaveLength(
      2,
    );
    const save = screen.getByRole("button", { name: "Save reviewed changes" });
    expect(save).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it("reports dismissal so the caller can clear drafts and previews", async () => {
    const cancel = vi.fn();
    render(
      <ConfigurationReviewDialog
        executionAllowed={false}
        onCancel={cancel}
        onConfirm={() => undefined}
        summary={[
          {
            fieldId: "workspace.storage",
            bindings: [],
            label: "Native storage directory",
            file: "configuration",
            action: "changed",
            sensitive: false,
            before: { state: "value", value: "./data" },
            after: { state: "value", value: "./native-data" },
          },
        ]}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: /Review 1 native change/ }),
    );
    await screen.findByRole("dialog");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(cancel).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
