import { expect, test } from "@playwright/test";

import { mockSession } from "./support/session";
import {
  mockRuntime,
  runtimeEvidence,
  supportedCandidate,
} from "./support/runtime";
import { mockWorkspace } from "./support/workspace";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
  await mockWorkspace(page);
});

test("reviews exact executable evidence before adoption", async ({ page }) => {
  const observations = await mockRuntime(page);
  await page.goto("/");

  await page
    .getByLabel("Host executable path")
    .fill(runtimeEvidence.canonicalPath);
  await page.getByRole("button", { name: "Inspect executable" }).click();

  await expect(
    page.getByRole("heading", { name: "Review executable evidence" }),
  ).toBeVisible();
  await expect(page.getByText(runtimeEvidence.canonicalPath)).toBeVisible();
  await expect(
    page.getByText(runtimeEvidence.version ?? "", { exact: true }).first(),
  ).toBeVisible();
  await expect(page.getByText("linux / amd64").first()).toBeVisible();
  await expect(page.getByText(runtimeEvidence.sha256)).toBeVisible();
  await expect(page.getByText("none", { exact: true })).toBeVisible();
  await expect(
    page.getByText(runtimeEvidence.versionOutput, { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(runtimeEvidence.build.dependencyGraphSha256),
  ).toBeVisible();
  await expect(page.getByText("lego-v5.3.1")).toBeVisible();
  await expect(page.getByRole("button", { name: /browse/i })).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /download|upgrade/i }),
  ).toHaveCount(0);

  const adopt = page.getByRole("button", { name: "Adopt reviewed executable" });
  await expect(adopt).toBeDisabled();
  await page
    .getByRole("checkbox", { name: /I reviewed the canonical path/i })
    .check();
  await expect(adopt).toBeEnabled();
  await adopt.click();

  await expect(
    page.getByText("Runtime ready for workspace adoption"),
  ).toBeVisible();
  expect(observations.inspections).toEqual([
    { path: runtimeEvidence.canonicalPath },
  ]);
  expect(observations.adoptions).toEqual([
    {
      path: runtimeEvidence.canonicalPath,
      reviewedSha256: runtimeEvidence.sha256,
      reviewedManifestId: "lego-v5.3.1",
      reviewedEvidenceSha256: "b".repeat(64),
    },
  ]);
});

test("shows unverified evidence while keeping adoption blocked", async ({
  page,
}) => {
  await mockRuntime(page, {
    candidate: {
      state: "review_required",
      candidate: {
        ...runtimeEvidence,
        version: null,
        commit: "2a58c3522708e4c7393a67be691bd0c3a16d8441",
        versionOutput:
          "lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/amd64",
        build: {
          ...runtimeEvidence.build,
          mainVersion: "v5.3.2-0.20260803101616-2a58c3522708",
          vcsRevision: "2a58c3522708e4c7393a67be691bd0c3a16d8441",
        },
      },
      compatibility: {
        state: "unverified",
        code: "unknown_identity",
        summary: "This exact source identity has not completed qualification.",
      },
    },
  });
  await page.goto("/");

  await page
    .getByLabel("Host executable path")
    .fill(runtimeEvidence.canonicalPath);
  await page.getByRole("button", { name: "Inspect executable" }).click();

  await expect(page.getByText("Support not verified")).toBeVisible();
  await expect(
    page.getByText(
      /only an executable matched by an exact supported manifest/i,
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Adoption blocked" }),
  ).toBeDisabled();
});

test("changed runtime blocks managed operations pending a new review", async ({
  page,
}) => {
  await mockRuntime(page, {
    initial: {
      state: "changed",
      path: runtimeEvidence.canonicalPath,
      diagnostic: {
        code: "executable_replaced",
        message: "Fingerprint changed",
      },
    },
  });
  await page.goto("/");

  await expect(page.getByText("Reviewed executable changed")).toBeVisible();
  await expect(
    page.getByText(
      /Managed operations stay blocked until the new evidence is reviewed/,
    ),
  ).toBeVisible();
  await expect(page.getByLabel("Host executable path")).toHaveValue(
    runtimeEvidence.canonicalPath,
  );
});

test("runtime evidence review fits a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await mockRuntime(page, { candidate: supportedCandidate });
  await page.goto("/");

  await page
    .getByLabel("Host executable path")
    .fill(runtimeEvidence.canonicalPath);
  await page.getByRole("button", { name: "Inspect executable" }).click();
  await expect(
    page.getByRole("heading", { name: "Review executable evidence" }),
  ).toBeVisible();

  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);
});
