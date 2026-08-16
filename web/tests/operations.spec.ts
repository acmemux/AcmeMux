import { expect, test } from "@playwright/test";

import { mockConfiguration, readyConfiguration } from "./support/configuration";
import {
  manualOperationPreview,
  mockOperations,
  partialOperationResult,
  runningOperation,
} from "./support/operations";
import { mockRuntime, supportedRuntime } from "./support/runtime";
import { mockSession } from "./support/session";
import { mockWorkspace, readyWorkspace } from "./support/workspace";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
  await mockRuntime(page, { initial: supportedRuntime });
  await mockWorkspace(page, { initial: readyWorkspace });
  await mockConfiguration(page, { initial: readyConfiguration });
});

test("reviews and durably enqueues one semantic whole-workspace operation", async ({
  page,
}) => {
  const observations = await mockOperations(page);
  await page.goto("/");

  const preview = page.getByRole("button", {
    name: "Preview manual workspace operation",
  });
  await expect(preview).toBeEnabled();
  await preview.click();

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("/srv/lego/.lego.yml");
  await expect(dialog).toContainText("gateway.home.example");
  await expect(dialog).toContainText("2 name-sorted");
  await expect(dialog).toContainText(
    "AcmeMux revalidates the complete native sources before execution",
  );
  await expect(dialog).toContainText("Browser cancellation is not supported");
  await expect(dialog).not.toContainText(/every certificate|native order/i);
  await expect(dialog).not.toContainText(
    manualOperationPreview.reviewedPreviewToken,
  );
  await expect(dialog).not.toContainText(/PRIVATE KEY|EAB|argv|environment=/);

  const start = page.getByRole("button", {
    name: "Start reviewed operation",
  });
  await expect(start).toBeDisabled();
  await page
    .getByRole("checkbox", {
      name: /I reviewed the runtime, native paths, configured certificate targets/i,
    })
    .check();
  await start.click();

  await expect(
    page.getByRole("heading", { name: "Operation queued" }),
  ).toBeVisible();
  expect(observations.previews).toEqual([{}]);
  expect(observations.enqueues).toEqual([
    {
      reviewedPreviewToken: manualOperationPreview.reviewedPreviewToken,
    },
  ]);
  await expect(
    page.getByRole("button", { name: /cancel operation/i }),
  ).toHaveCount(0);
});

test("keeps active work visible and blocks native mutations without a cancel action", async ({
  page,
}) => {
  await mockOperations(page, {
    initialStatus: { state: "active", operation: runningOperation },
  });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Operation running" }),
  ).toBeVisible();
  await expect(page.getByText(/Closing or navigating away/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Preview native configuration changes" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /cancel|stop|kill operation/i }),
  ).toHaveCount(0);
  await expect(
    page.getByLabel("System signal").getByText("Running", { exact: true }),
  ).toBeVisible();
});

test("adopts authoritative active status when another request wins the enqueue race", async ({
  page,
}) => {
  const observations = await mockOperations(page, {
    enqueueFailure: { code: "operation_active", status: 409 },
  });
  await page.goto("/");

  await page
    .getByRole("button", { name: "Preview manual workspace operation" })
    .click();
  await page
    .getByRole("checkbox", {
      name: /I reviewed the runtime, native paths, configured certificate targets/i,
    })
    .check();
  await page.getByRole("button", { name: "Start reviewed operation" }).click();

  await expect(
    page.getByRole("heading", { name: "Operation running" }),
  ).toBeVisible();
  await expect(page.getByText(/already active/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Preview native configuration changes" }),
  ).toBeDisabled();
  expect(observations.enqueues).toHaveLength(1);
});

test("reports fail-fast partial and not-attempted evidence without hiding ambiguity", async ({
  page,
}) => {
  await mockOperations(page, {
    initialLatest: {
      state: "available",
      result: partialOperationResult,
    },
  });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Partially completed" }),
  ).toBeVisible();
  const results = page.getByRole("region", {
    name: "Latest certificate operation results",
  });
  await expect(results).toContainText("gateway");
  await expect(results).toContainText("completed");
  await expect(results).toContainText("media");
  await expect(results).toContainText("failed");
  await expect(results).toContainText("router");
  await expect(results).toContainText("not attempted");
  await expect(page.getByText("External state may have changed")).toBeVisible();
  await expect(page.getByText(/Do not retry blindly/)).toBeVisible();

  await page.getByText("Show redacted upstream transcript").click();
  await expect(page.getByText(/gateway completed/)).toBeVisible();
  await expect(page.getByText(/media failed/)).toBeVisible();
});

test("does not retry an enqueue whose response is unavailable", async ({
  page,
}) => {
  const observations = await mockOperations(page, {
    enqueueFailure: { code: "service_unavailable", status: 503 },
  });
  await page.goto("/");

  await page
    .getByRole("button", { name: "Preview manual workspace operation" })
    .click();
  await page
    .getByRole("checkbox", {
      name: /I reviewed the runtime, native paths, configured certificate targets/i,
    })
    .check();
  await page.getByRole("button", { name: "Start reviewed operation" }).click();

  await expect(page.getByText("Enqueue outcome unknown")).toBeVisible();
  await expect(page.getByText(/did not retry/i)).toBeVisible();
  expect(observations.enqueues).toHaveLength(1);
  await expect(
    page.getByRole("button", {
      name: "Preview manual workspace operation",
    }),
  ).toBeDisabled();
});

test("operation review and result remain usable at a narrow viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await mockOperations(page, {
    initialLatest: {
      state: "available",
      result: partialOperationResult,
    },
  });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Manual certificate operation" }),
  ).toBeVisible();
  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);

  const results = page.getByRole("region", {
    name: "Latest certificate operation results",
  });
  const resultWidths = await results.evaluate((element) => ({
    client: element.clientWidth,
    scroll: element.scrollWidth,
  }));
  expect(resultWidths.scroll).toBeGreaterThan(resultWidths.client);
});
