import { expect, test } from "@playwright/test";

import { mockSession } from "./support/session";
import { mockRuntime, supportedRuntime } from "./support/runtime";
import { mockWorkspace, readyWorkspace } from "./support/workspace";
import {
  mockConfiguration,
  recoveryConfiguration,
  unsupportedConfiguration,
} from "./support/configuration";

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
    await mockWorkspace(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Certificate operations" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "application-shell-wide.png",
      fullPageSnapshot,
    );
  });

  test("workspace evidence review", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page, { initial: supportedRuntime });
    await mockWorkspace(page);
    await page.goto("/");
    await page.getByLabel("Effective working directory").fill("/srv/lego");
    await page.getByRole("button", { name: "Inspect workspace" }).click();
    await expect(
      page.getByRole("heading", { name: "Review native workspace evidence" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "workspace-review-wide.png",
      fullPageSnapshot,
    );
  });

  test("reviewed workspace inventory", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page, { initial: supportedRuntime });
    await mockWorkspace(page, { initial: readyWorkspace });
    await mockConfiguration(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Native workspace ready" }),
    ).toBeVisible();
    await expect(page.getByText("gateway.home.example").first()).toBeVisible();
    await expect(page).toHaveScreenshot(
      "workspace-ready-wide.png",
      fullPageSnapshot,
    );
  });

  test("unsupported native configuration", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page, { initial: supportedRuntime });
    await mockWorkspace(page, { initial: readyWorkspace });
    await mockConfiguration(page, { initial: unsupportedConfiguration });
    await page.goto("/");
    await expect(page.getByText("Native content unsupported")).toBeVisible();
    await expect(page).toHaveScreenshot(
      "configuration-unsupported-wide.png",
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
    await mockWorkspace(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Certificate operations" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "application-shell-narrow.png",
      fullPageSnapshot,
    );
  });

  test("reviewed workspace inventory", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page, { initial: supportedRuntime });
    await mockWorkspace(page, { initial: readyWorkspace });
    await mockConfiguration(page);
    await page.goto("/");
    await expect(
      page.getByRole("heading", { name: "Native workspace ready" }),
    ).toBeVisible();
    await expect(page).toHaveScreenshot(
      "workspace-ready-narrow.png",
      fullPageSnapshot,
    );
  });

  test("configuration recovery", async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page, { initial: supportedRuntime });
    await mockWorkspace(page, { initial: readyWorkspace });
    await mockConfiguration(page, { initial: recoveryConfiguration });
    await page.goto("/");
    await expect(page.getByText("Recovery required").first()).toBeVisible();
    await expect(page).toHaveScreenshot(
      "configuration-recovery-narrow.png",
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
