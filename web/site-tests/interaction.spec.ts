import { expect, test } from "@playwright/test";

import { fixedNow, openDock, preparePage, validEvidence } from "./support";

test("dogfood dock is quiet, truthful, and keyboard operable", async ({
  page,
}) => {
  await preparePage(page);
  await page.goto("/");

  const toggle = page.locator("[data-dock-toggle]");
  const panel = page.locator("[data-dock-panel]");
  const countdown = page.locator("[data-dogfood-countdown]");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(panel).toBeHidden();
  await expect(page.locator("[data-dogfood-dock]")).toHaveAttribute(
    "data-state",
    "healthy",
  );
  await expect(toggle).toContainText("Expected replacement in");

  await toggle.focus();
  await toggle.press("Enter");
  await expect(panel).toBeVisible();
  await expect(countdown).toContainText("Expected replacement in");
  await expect(panel.locator("[data-cert-fingerprint]")).toHaveText(
    validEvidence.fingerprintSha256,
  );
  expect(
    await countdown.evaluate((node) => node.closest("[aria-live]") !== null),
  ).toBe(false);
  const before = await countdown.textContent();
  await page.clock.fastForward(30_000);
  await expect(countdown).toHaveText(before ?? "");
  await expect(panel.getByRole("link", { name: "Privacy" })).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(toggle).toBeFocused();
  await expect(page.locator("body")).not.toContainText(/renewal due/i);
});

test("ended replacement window asks for evidence inspection", async ({
  page,
}) => {
  await preparePage(page, {
    ...validEvidence,
    nextRenewalAt: "2026-08-17T09:35:00Z",
  });
  await page.goto("/");
  await expect(page.locator("[data-dogfood-dock]")).toHaveAttribute(
    "data-state",
    "ended",
  );
  await expect(page.locator("[data-dogfood-summary]")).toContainText(
    "Expected window reached",
  );
  await openDock(page);
  await expect(page.locator("[data-cert-basis]")).toContainText(
    "does not prove renewal failure",
  );
});

test("expired evidence is distinct from a reached replacement window", async ({
  page,
}) => {
  await preparePage(page, {
    ...validEvidence,
    expiresAt: "2026-08-17T23:00:00Z",
    issuedAt: "2026-08-10T01:05:35Z",
    lastDeployedAt: "2026-08-10T03:20:35Z",
    nextRenewalAt: "2026-08-15T09:35:00Z",
  });
  await page.goto("/certificate-status/");
  await expect(page.locator("[data-dogfood-dock]")).toHaveAttribute(
    "data-state",
    "expired",
  );
  await expect(page.locator("[data-status-page]")).toHaveAttribute(
    "data-state",
    "expired",
  );
  await expect(page.locator("[data-status-page-summary]")).toHaveText(
    "Public evidence expired",
  );
});

for (const scenario of [
  "unavailable",
  "malformed",
  "invalid",
  "chronology",
] as const) {
  test(`${scenario} certificate evidence fails safely`, async ({ page }) => {
    await page.clock.install({ time: fixedNow });
    await page.route("**/certificate-status.json", async (route) => {
      if (scenario === "unavailable") {
        await route.fulfill({
          status: 503,
          body: "service detail must not render",
        });
      } else if (scenario === "malformed") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: "{broken",
        });
      } else if (scenario === "invalid") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...validEvidence,
            fingerprintSha256: "not-a-fingerprint",
          }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...validEvidence,
            nextRenewalAt: "2026-12-01T09:35:00Z",
          }),
        });
      }
    });
    await page.goto("/certificate-status/");
    await expect(page.locator("[data-dogfood-dock]")).toHaveAttribute(
      "data-state",
      "unavailable",
    );
    await expect(page.locator("[data-dogfood-summary]")).toHaveText(
      "Live certificate evidence is unavailable",
    );
    await expect(page.locator("[data-status-page-summary]")).toHaveText(
      "Public evidence unavailable",
    );
    await expect(page.locator("body")).not.toContainText(
      "service detail must not render",
    );
  });
}

test("a hanging status request becomes unavailable after its bound", async ({
  page,
}) => {
  await page.clock.install({ time: fixedNow });
  await page.addInitScript(() => {
    window.fetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
  });
  await page.goto("/");
  await page.clock.fastForward(8001);
  await expect(page.locator("[data-dogfood-dock]")).toHaveAttribute(
    "data-state",
    "unavailable",
  );
});

test("reminder validates locally and preserves the honeypot", async ({
  page,
}) => {
  await preparePage(page);
  let requests = 0;
  let requestBody: { email?: string; website?: string } = {};
  await page.route("**/api/renewal-alerts/subscriptions", async (route) => {
    requests += 1;
    requestBody = route.request().postDataJSON();
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: "{}",
    });
  });
  await page.goto("/");
  await openDock(page);
  const form = page.locator("[data-reminder-form]");
  await form.locator("[data-reminder-submit]").click();
  await expect(form.locator("[data-reminder-result]")).toHaveText(
    "Enter a valid email address.",
  );
  expect(requests).toBe(0);

  await form.locator("[name='email']").fill("operator@example.com");
  await form.locator("[name='website']").evaluate((input: HTMLInputElement) => {
    input.value = "trap-value";
  });
  await form.locator("[data-reminder-submit]").click();
  await expect(form.locator("[data-reminder-result]")).toHaveText(
    "Check your inbox to confirm. No reminder is active until you confirm.",
  );
  expect(requests).toBe(1);
  expect(requestBody).toEqual({
    email: "operator@example.com",
    website: "trap-value",
  });
});

test("reminder exposes pending state and fixed safe failures", async ({
  page,
}) => {
  await preparePage(page);
  let releaseRequest: (() => void) | undefined;
  let status = 202;
  await page.route("**/api/renewal-alerts/subscriptions", async (route) => {
    await new Promise<void>((resolve) => {
      releaseRequest = resolve;
    });
    await route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify({ message: "private server implementation detail" }),
    });
  });
  await page.goto("/");
  await openDock(page);
  const form = page.locator("[data-reminder-form]");
  const submit = form.locator("[data-reminder-submit]");
  await form.locator("[name='email']").fill("operator@example.com");
  await submit.click();
  await expect(submit).toBeDisabled();
  await expect(form).toHaveAttribute("aria-busy", "true");
  await expect(form.locator("[data-reminder-result]")).toHaveText(
    "Sending confirmation...",
  );
  releaseRequest?.();
  await expect(submit).toBeEnabled();

  status = 500;
  await form.locator("[name='email']").fill("operator@example.com");
  await submit.click();
  await expect(submit).toBeDisabled();
  releaseRequest?.();
  await expect(form.locator("[data-reminder-result]")).toContainText(
    "Signup could not be completed",
  );
  await expect(form).not.toContainText("private server implementation detail");
});

test("a hanging reminder request returns the form to a safe state", async ({
  page,
}) => {
  await preparePage(page);
  await page.addInitScript(() => {
    const originalFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
      if (String(input).includes("/api/renewal-alerts/subscriptions")) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        });
      }
      return originalFetch(input, init);
    };
  });
  await page.goto("/");
  await openDock(page);
  const form = page.locator("[data-reminder-form]");
  const submit = form.locator("[data-reminder-submit]");
  await form.locator("[name='email']").fill("operator@example.com");
  await submit.click();
  await expect(submit).toBeDisabled();
  await page.clock.fastForward(10001);
  await expect(submit).toBeEnabled();
  await expect(form).not.toHaveAttribute("aria-busy", "true");
  await expect(form.locator("[data-reminder-result]")).toContainText(
    "Signup could not be completed",
  );
});

test("mobile navigation opens, closes, and restores focus", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await preparePage(page);
  await page.goto("/roadmap/");
  const toggle = page.locator("[data-nav-toggle]");
  const navigation = page.locator("[data-site-nav]");
  await expect(toggle).toBeVisible();
  await expect(navigation).toBeHidden();
  await toggle.focus();
  await toggle.press("Enter");
  await expect(navigation).toBeVisible();
  await expect(
    navigation.getByRole("link", { name: "Roadmap" }),
  ).toHaveAttribute("aria-current", "page");
  await page.keyboard.press("Escape");
  await expect(navigation).toBeHidden();
  await expect(toggle).toBeFocused();
});

test("desktop navigation stays visible without a menu control", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await preparePage(page);
  await page.goto("/product/");
  await expect(page.locator("[data-nav-toggle]")).toBeHidden();
  await expect(page.locator("[data-site-nav]")).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Product", exact: true }),
  ).toHaveAttribute("aria-current", "page");
});
