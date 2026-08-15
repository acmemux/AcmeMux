import { expect, test } from "@playwright/test";

const fullPageSnapshot = {
  animations: "disabled" as const,
  fullPage: true,
  maxDiffPixelRatio: 0.001,
};

test.describe("wide visual contract", () => {
  test.use({ viewport: { width: 1440, height: 1100 } });

  test("application shell", async ({ page }) => {
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
});

test.describe("narrow visual contract", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("application shell", async ({ page }) => {
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
});
