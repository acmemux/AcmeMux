import { expect, test } from "@playwright/test";

import { openDock, preparePage } from "./support";

test("homepage wide visual", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await preparePage(page);
  await page.goto("/");
  await expect(page).toHaveScreenshot("homepage-wide.png", {
    animations: "disabled",
    fullPage: true,
  });
});

test("homepage narrow visual", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await preparePage(page);
  await page.goto("/");
  await expect(page).toHaveScreenshot("homepage-narrow.png", {
    animations: "disabled",
    fullPage: true,
  });
});

test("expanded dogfood dock visual", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await preparePage(page);
  await page.goto("/certificate-status/");
  await openDock(page);
  await expect(page.locator("[data-dogfood-dock]")).toHaveScreenshot(
    "dogfood-dock-expanded.png",
    { animations: "disabled" },
  );
});
