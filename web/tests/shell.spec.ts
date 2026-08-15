import { expect, test } from "@playwright/test";

import { mockSession } from "./support/session";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
});

test("renders an honest application shell", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Certificate operations" }),
  ).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Primary navigation" }),
  ).toBeVisible();
  await expect(page.getByText("No native workspace connected")).toBeVisible();
  await expect(page.getByText("Not connected", { exact: true })).toBeVisible();
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
