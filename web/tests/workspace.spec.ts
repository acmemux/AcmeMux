import { expect, test } from "@playwright/test";

import { mockRuntime, supportedRuntime } from "./support/runtime";
import { mockSession } from "./support/session";
import {
  mockWorkspace,
  readyWorkspace,
  reviewedWorkspaceCandidate,
  workspaceCertificate,
} from "./support/workspace";

test.beforeEach(async ({ page }) => {
  await mockSession(page);
});

test("reviews every native path before adopting a conventional workspace", async ({
  page,
}) => {
  await mockRuntime(page, { initial: supportedRuntime });
  const observations = await mockWorkspace(page);
  await page.goto("/");

  await page.getByLabel("Effective working directory").fill("/srv/lego");
  await page.getByRole("button", { name: "Inspect workspace" }).click();

  const heading = page.getByRole("heading", {
    name: "Review native workspace evidence",
  });
  await expect(heading).toBeVisible();
  await expect(heading).toBeFocused();
  await expect(page.getByText(/Conventional \.lego\.yml/)).toBeVisible();
  await expect(page.getByText("./cloudflare.env")).toBeVisible();
  await expect(page.getByText("/srv/lego/cloudflare.env")).toBeVisible();
  await expect(page.getByText("./public")).toBeVisible();
  await expect(page.getByText("/srv/lego/public")).toBeVisible();
  await expect(page.getByText("uid 991 / gid 991").first()).toBeVisible();

  const adopt = page.getByRole("button", { name: "Adopt reviewed workspace" });
  await expect(adopt).toBeDisabled();
  const confirmation = page.getByRole("checkbox", {
    name: /I reviewed the effective working directory/i,
  });
  await confirmation.focus();
  await page.keyboard.press("Space");
  await expect(confirmation).toBeChecked();
  await expect(adopt).toBeEnabled();
  await adopt.click();

  await expect(page.getByText("Native workspace ready")).toBeVisible();
  expect(observations.inspections).toEqual([
    { workingDirectory: "/srv/lego", configurationPath: null },
  ]);
  expect(observations.adoptions).toEqual([
    {
      workingDirectory: "/srv/lego",
      configurationPath: null,
      reviewedEvidenceSha256: "c".repeat(64),
    },
  ]);
});

test("shows bounded certificate inventory from native evidence", async ({
  page,
}) => {
  await mockRuntime(page, { initial: supportedRuntime });
  await mockWorkspace(page, { initial: readyWorkspace });
  await page.goto("/");

  await expect(page.getByText("Native workspace connected")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: workspaceCertificate.name }),
  ).toBeVisible();
  await expect(
    page.getByText(workspaceCertificate.dnsNames.join(", ")),
  ).toBeVisible();
  await expect(page.getByText(workspaceCertificate.issuer)).toBeVisible();
  await expect(
    page.getByText(workspaceCertificate.artifact.nativePath),
  ).toBeVisible();
  await expect(page.getByText("uid 991 / gid 991 / 0640")).toBeVisible();
  await expect(page.getByText(/Mar 31, 2030.*UTC/)).toBeVisible();
  await expect(page.getByText(/BEGIN CERTIFICATE/)).toHaveCount(0);
  await expect(page.getByText(/PRIVATE KEY/)).toHaveCount(0);
});

test("shows shadowed conventional configuration without blocking adoption", async ({
  page,
}) => {
  await mockRuntime(page, { initial: supportedRuntime });
  const precedenceNotice = {
    code: "configuration_precedence",
    severity: "notice",
    role: "configuration",
    message: "The yml file wins.",
    path: "/srv/lego/.lego.yml",
    component: "/srv/lego/.lego.yaml",
  } as const;
  await mockWorkspace(page, {
    candidate: {
      ...reviewedWorkspaceCandidate,
      diagnostics: [precedenceNotice],
    },
    adopted: { ...readyWorkspace, diagnostics: [precedenceNotice] },
  });
  await page.goto("/");
  await page.getByLabel("Effective working directory").fill("/srv/lego");
  await page.getByRole("button", { name: "Inspect workspace" }).click();

  await expect(page.getByText("configuration_precedence")).toBeVisible();
  await expect(
    page.getByText(/Upstream priority selects \.lego\.yml/),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Adopt reviewed workspace" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("checkbox", {
      name: /I reviewed the effective working directory/i,
    }),
  ).toBeVisible();
  await page
    .getByRole("checkbox", {
      name: /I reviewed the effective working directory/i,
    })
    .check();
  await page.getByRole("button", { name: "Adopt reviewed workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Native workspace ready" }),
  ).toBeFocused();
  await expect(page.getByText("configuration_precedence")).toBeVisible();
});

test("workspace evidence review fits a narrow viewport without overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await mockRuntime(page, { initial: supportedRuntime });
  await mockWorkspace(page, { candidate: reviewedWorkspaceCandidate });
  await page.goto("/");

  await page.getByLabel("Effective working directory").fill("/srv/lego");
  await page.getByRole("button", { name: "Inspect workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Review native workspace evidence" }),
  ).toBeVisible();

  const widths = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(widths.scroll).toBeLessThanOrEqual(widths.client);
});
