import { expect, test } from "@playwright/test";

import { mockSession } from "./support/session";
import { mockRuntime } from "./support/runtime";

const fullPageSnapshot = {
  animations: "disabled" as const,
  fullPage: true,
  maxDiffPixelRatio: 0.001,
};

test.describe("wide visual contract", () => {
  test.use({ viewport: { width: 1440, height: 1100 } });

  test("application shell", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Certificate operations" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "application-shell-wide.png",
      fullPageSnapshot,
    );
  });

  test("component catalog and interaction states", async ({ page }) => {
    await page.goto("/?catalog=components");
    await expect(
      page.getByRole("heading", { name: "Component catalog" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "component-catalog-wide.png",
      fullPageSnapshot,
    );
    await expect(
      page.getByRole("region", { name: "Controls and forms" }),
    ).toHaveScreenshot("component-controls-wide.png", {
      animations: "disabled",
      maxDiffPixelRatio: 0.001,
    });
  });

  test("administrator sign-in", async ({ page }) => {
    await mockSession(page, "signed_out");
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Administrator sign in" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "administrator-sign-in-wide.png",
      fullPageSnapshot,
    );
  });

  test("local administrator bootstrap guidance", async ({ page }) => {
    await mockSession(page, "uninitialized");
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Administrator not initialized" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "administrator-uninitialized-wide.png",
      fullPageSnapshot,
    );
  });
});

test.describe("narrow visual contract", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("application shell", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Certificate operations" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "application-shell-narrow.png",
      fullPageSnapshot,
    );
  });

  test("component catalog", async ({ page }) => {
    await page.goto("/?catalog=components");
    await expect(
      page.getByRole("heading", { name: "Component catalog" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "component-catalog-narrow.png",
      fullPageSnapshot,
    );
  });

  test("administrator sign-in", async ({ page }) => {
    await mockSession(page, "signed_out");
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Administrator sign in" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "administrator-sign-in-narrow.png",
      fullPageSnapshot,
    );
  });
});
