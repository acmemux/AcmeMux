import { expect, test } from "@playwright/test";

import {
  mockConfiguration,
  readyConfiguration,
  recoveryConfiguration,
  unsupportedConfiguration,
} from "./support/configuration";
import { mockRuntime, supportedRuntime } from "./support/runtime";
import { mockSession } from "./support/session";
import { mockWorkspace, readyWorkspace } from "./support/workspace";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
  await mockRuntime(page, { initial: supportedRuntime });
  await mockWorkspace(page, { initial: readyWorkspace });
});

test("shows a secret-safe native configuration projection", async ({
  page,
}) => {
  await mockConfiguration(page, { initial: readyConfiguration });
  await page.goto("/");

  await expect(page.getByText("Configuration engine ready")).toBeVisible();
  await expect(page.getByText("2 known")).toBeVisible();
  await expect(page.getByText("Stored secret values present")).toBeVisible();
  const configuration = page.getByRole("region", {
    name: "Configuration mediation",
  });
  await expect(configuration.getByText("./data", { exact: true })).toHaveCount(
    0,
  );
  await expect(
    page.getByText(readyConfiguration.source.baseRevisionToken, {
      exact: true,
    }),
  ).toHaveCount(0);
});

test("preserves and clearly blocks unsupported native content", async ({
  page,
}) => {
  await mockConfiguration(page, { initial: unsupportedConfiguration });
  await page.goto("/");

  await expect(page.getByText("Native content unsupported")).toBeVisible();
  await expect(page.getByText("unsupported_provider")).toBeVisible();
  await expect(page.getByText("unknown_field")).toBeVisible();
  await expect(
    page.getByText(/managed execution stays blocked/i),
  ).toBeVisible();
});

test("shows an interrupted multi-file phase without replay controls", async ({
  page,
}) => {
  await mockConfiguration(page, { initial: recoveryConfiguration });
  await page.goto("/");

  await expect(page.getByText("Recovery required").first()).toBeVisible();
  await expect(page.getByText(/will not replay or roll back/i)).toBeVisible();
  await expect(page.getByText("ambiguous").last()).toBeVisible();
  await expect(
    page.getByRole("button", { name: /retry|replay|roll back/i }),
  ).toHaveCount(0);
});

test("reloads evidence after a recovery response cannot confirm its outcome", async ({
  page,
}) => {
  const recoveredConfiguration = {
    ...readyConfiguration,
    source: {
      ...readyConfiguration.source,
      baseRevisionToken: "B".repeat(43),
    },
  };
  const observations = await mockConfiguration(page, {
    initial: recoveryConfiguration,
    recovered: recoveredConfiguration,
    recoveryFailure: { code: "service_unavailable", status: 503 },
  });
  await page.goto("/");

  await page
    .getByRole("checkbox", {
      name: /I repaired the active files and removed the interrupted staging entries/,
    })
    .check();
  await page
    .getByRole("button", { name: "Validate and adopt current files" })
    .click();

  await expect(page.getByText("Recovery outcome unknown")).toBeVisible();
  await expect(
    page.getByText(/Current native configuration evidence was reloaded/),
  ).toBeVisible();
  await expect(page.getByText("Configuration engine ready")).toBeVisible();
  expect(observations.recoveries).toEqual([
    {
      baseRevisionToken: recoveryConfiguration.source.baseRevisionToken,
      resolution: "adopt_current",
    },
  ]);
  await expect(page.getByText("No native files were changed")).toHaveCount(0);
});

test("configuration evidence remains usable at a narrow viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await mockConfiguration(page, { initial: unsupportedConfiguration });
  await page.goto("/");

  await expect(page.getByText("Native content unsupported")).toBeVisible();
  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);
});
