import { expect, test } from "@playwright/test";

import {
  creationRequiredConfiguration,
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
  await expect(page.getByText("18 known")).toBeVisible();
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
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
});

test("reviews and saves a typed certificate edit without exposing secrets", async ({
  page,
}) => {
  const reviewedPreviewToken = "C".repeat(43);
  const expectedChanges = [
    {
      fieldId: "certificate.domains",
      bindings: [{ id: "certificate", value: "home" }],
      operation: "set",
      value: ["home.example.com", "router.example.com"],
    },
  ];
  const saved = {
    ...readyConfiguration,
    source: {
      ...readyConfiguration.source,
      baseRevisionToken: "B".repeat(43),
    },
    projection: readyConfiguration.projection.map((field) =>
      field.fieldId === "certificate.domains"
        ? { ...field, value: ["home.example.com", "router.example.com"] }
        : field,
    ),
  };
  const observations = await mockConfiguration(page, {
    initial: readyConfiguration,
    preview: {
      state: "review_required",
      baseRevisionToken: readyConfiguration.source.baseRevisionToken,
      reviewedPreviewToken,
      resultingState: "ready",
      summary: [
        {
          fieldId: "certificate.domains",
          bindings: [{ id: "certificate", value: "home" }],
          label: "DNS names",
          file: "configuration",
          action: "changed",
          sensitive: false,
          before: { state: "value", value: ["home.example.com"] },
          after: {
            state: "value",
            value: ["home.example.com", "router.example.com"],
          },
        },
      ],
      diagnostics: [],
      executionAllowed: true,
    },
    saved,
  });
  await page.goto("/");

  await page
    .getByLabel("DNS names")
    .fill("home.example.com\nrouter.example.com");
  await page
    .getByRole("button", { name: "Preview native configuration changes" })
    .click();
  await page.getByRole("button", { name: "Review 1 native change" }).click();
  await expect(page.getByRole("dialog")).not.toContainText(
    "test-only-super-secret",
  );
  await page
    .getByRole("checkbox", {
      name: /I reviewed every affected native file/i,
    })
    .check();
  await page.getByRole("button", { name: "Save reviewed changes" }).click();

  await expect(page.getByLabel("DNS names")).toHaveValue(
    "home.example.com\nrouter.example.com",
  );
  expect(observations.previews).toEqual([
    {
      baseRevisionToken: readyConfiguration.source.baseRevisionToken,
      changes: expectedChanges,
    },
  ]);
  expect(observations.saves).toEqual([
    {
      baseRevisionToken: readyConfiguration.source.baseRevisionToken,
      reviewedPreviewToken,
      changes: expectedChanges,
    },
  ]);
  expect(JSON.stringify(observations)).not.toContain("test-only-super-secret");
});

test("creates a reviewed native workspace from typed bootstrap fields", async ({
  page,
}) => {
  const reviewedPreviewToken = "C".repeat(43);
  const observations = await mockConfiguration(page, {
    initial: creationRequiredConfiguration,
    creationPreview: {
      state: "review_required",
      baseRevisionToken: creationRequiredConfiguration.source.baseRevisionToken,
      reviewedPreviewToken,
      resultingState: "ready",
      summary: [
        {
          fieldId: "workspace.storage",
          bindings: [],
          label: "Native storage directory",
          file: "configuration",
          action: "added",
          sensitive: false,
          before: { state: "absent" },
          after: { state: "value", value: ".lego" },
        },
      ],
      diagnostics: [],
      executionAllowed: true,
    },
    created: {
      ...readyConfiguration,
      source: {
        ...readyConfiguration.source,
        baseRevisionToken: "D".repeat(43),
      },
    },
  });
  await page.goto("/");

  await expect(
    page.getByText("Prepare the first supported configuration"),
  ).toBeVisible();
  await page.getByLabel("Working directory", { exact: true }).fill("/srv/lego");
  await page.getByLabel("Account email").fill("admin@example.com");
  await page
    .getByRole("checkbox", {
      name: /acknowledge this CA's subscriber agreement/i,
    })
    .check();
  await page.getByLabel("DNS names").fill("home.example.com");
  await page
    .getByRole("button", { name: "Preview native workspace creation" })
    .click();
  await page.getByRole("button", { name: "Review 1 native change" }).click();
  await page
    .getByRole("checkbox", {
      name: /I reviewed every affected native file/i,
    })
    .check();
  await page.getByRole("button", { name: "Save reviewed changes" }).click();

  await expect(page.getByText("Configuration engine ready")).toBeVisible();
  expect(observations.creationPreviews).toHaveLength(1);
  expect(observations.creationPreviews[0]).toMatchObject({
    baseRevisionToken: creationRequiredConfiguration.source.baseRevisionToken,
    workingDirectory: "/srv/lego",
    configurationPath: null,
    changes: expect.arrayContaining([
      expect.objectContaining({
        fieldId: "challenge.http.delay",
        operation: "set",
        value: "0s",
      }),
      expect.objectContaining({
        fieldId: "certificate.renew.ari.wait_to_renew_duration",
        operation: "set",
        value: "0s",
      }),
    ]),
  });
  expect(observations.creations).toEqual([
    expect.objectContaining({
      baseRevisionToken: creationRequiredConfiguration.source.baseRevisionToken,
      reviewedPreviewToken,
      workingDirectory: "/srv/lego",
      configurationPath: null,
    }),
  ]);
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
    page.getByText("Hidden native values require explicit repair"),
  ).toBeVisible();
  await expect(
    page.getByRole("option", { name: "Unsupported native endpoint" }),
  ).toBeAttached();
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

test("typed creation fields remain usable at a narrow viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await mockConfiguration(page, { initial: creationRequiredConfiguration });
  await page.goto("/");

  await expect(
    page.getByText("Prepare the first supported configuration"),
  ).toBeVisible();
  await expect(
    page.getByLabel("Working directory", { exact: true }),
  ).toBeVisible();
  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);
});
