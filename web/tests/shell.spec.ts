import { expect, test } from "@playwright/test";

import { mockSession } from "./support/session";
import { mockRuntime } from "./support/runtime";
import { mockWorkspace } from "./support/workspace";
import { mockOperations } from "./support/operations";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
  await mockRuntime(page);
  await mockWorkspace(page);
  await mockOperations(page);
});

test("renders an honest application shell", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Certificate operations" }),
  ).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Primary navigation" }),
  ).toBeVisible();
  await expect(
    page.getByText("Managed operations remain blocked"),
  ).toBeVisible();
  await expect(
    page
      .getByLabel("System signal")
      .getByText("Not connected", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
});

test("catalog exposes required operational states", async ({ page }) => {
  await page.goto("/?catalog=components");

  await expect(
    page.getByRole("heading", { name: "Component catalog" }),
  ).toBeVisible();
  for (const state of [
    "Loading",
    "Success",
    "Warning",
    "Error",
    "Unsupported",
    "Partial",
    "Interrupted",
    "Not attempted",
  ]) {
    await expect(page.getByText(state, { exact: true }).first()).toBeVisible();
  }
});
