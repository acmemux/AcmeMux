import { expect, test } from "@playwright/test";

test("renders the application foundation", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "AcmeMux" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "One authoritative workspace" }),
  ).toBeVisible();
});
