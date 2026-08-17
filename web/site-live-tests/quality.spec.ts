import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function liveRoutes(page: Page): Promise<string[]> {
  const response = await page.request.get("/sitemap.xml");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("application/xml");
  const sitemap = await response.text();
  const routes = Array.from(
    sitemap.matchAll(/<loc>https:\/\/acmemux\.com([^<]+)<\/loc>/g),
    (match) => match[1],
  );
  expect(routes.length).toBeGreaterThan(0);
  expect(new Set(routes).size).toBe(routes.length);
  return [...routes, "/404.html"];
}

async function waitForPublicEvidence(page: Page): Promise<void> {
  await expect(page.locator("body")).toHaveAttribute(
    "data-dogfood-page-state",
    /^(?:healthy|ended|expired)$/,
    { timeout: 12_000 },
  );
}

for (const width of [320, 375, 768, 1440]) {
  test(`live pages reflow and expose the dogfood dock at ${width}px`, async ({
    page,
  }) => {
    test.slow();
    await page.setViewportSize({ width, height: width < 700 ? 812 : 900 });
    for (const route of await liveRoutes(page)) {
      const response = await page.goto(route);
      expect(response?.status(), route).toBe(route === "/404.html" ? 404 : 200);
      await waitForPublicEvidence(page);
      await expect(page.locator("[data-dock-toggle]"), route).toBeVisible();
      const collapsedDock = await page
        .locator("[data-dogfood-dock]")
        .boundingBox();
      expect(collapsedDock, route).not.toBeNull();
      expect(collapsedDock?.x ?? -1, route).toBeGreaterThanOrEqual(0);
      expect(collapsedDock?.y ?? -1, route).toBeGreaterThanOrEqual(0);
      expect(
        (collapsedDock?.x ?? 0) + (collapsedDock?.width ?? 0),
        route,
      ).toBeLessThanOrEqual(width);
      expect(
        (collapsedDock?.y ?? 0) + (collapsedDock?.height ?? 0),
        route,
      ).toBeLessThanOrEqual(width < 700 ? 812 : 900);
      const report = await page.evaluate(() => {
        const viewport = document.documentElement.clientWidth;
        const offenders = Array.from(
          document.querySelectorAll<HTMLElement>("body *"),
        )
          .filter((element) => {
            const style = getComputedStyle(element);
            if (style.display === "none" || style.position === "fixed") {
              return false;
            }
            const rect = element.getBoundingClientRect();
            return rect.left < -1 || rect.right > viewport + 1;
          })
          .slice(0, 8)
          .map((element) => ({
            className: element.className,
            left: Math.round(element.getBoundingClientRect().left),
            node: element.tagName,
            right: Math.round(element.getBoundingClientRect().right),
          }));
        return {
          clientWidth: viewport,
          offenders,
          scrollWidth: document.documentElement.scrollWidth,
        };
      });
      expect(
        report,
        `${route}: ${JSON.stringify(report.offenders)}`,
      ).toMatchObject({
        clientWidth: width,
        offenders: [],
        scrollWidth: width,
      });
    }

    await page.goto("/");
    await waitForPublicEvidence(page);
    await page.locator("[data-dock-toggle]").click();
    await expect(page.locator("[data-dock-panel]")).toBeVisible();
    const expandedDock = await page
      .locator("[data-dogfood-dock]")
      .boundingBox();
    expect(expandedDock).not.toBeNull();
    expect(expandedDock?.x ?? -1).toBeGreaterThanOrEqual(0);
    expect(expandedDock?.y ?? -1).toBeGreaterThanOrEqual(0);
    expect(
      (expandedDock?.x ?? 0) + (expandedDock?.width ?? 0),
    ).toBeLessThanOrEqual(width);
    expect(
      (expandedDock?.y ?? 0) + (expandedDock?.height ?? 0),
    ).toBeLessThanOrEqual(width < 700 ? 812 : 900);
  });
}

for (const width of [375, 1440]) {
  test(`live pages have no WCAG A or AA axe violations at ${width}px`, async ({
    page,
  }) => {
    test.slow();
    await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
    for (const route of await liveRoutes(page)) {
      await page.goto(route);
      await waitForPublicEvidence(page);
      const results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
      expect(
        results.violations,
        `${route}: ${results.violations.map((violation) => violation.id).join(", ")}`,
      ).toEqual([]);
    }
  });
}

test("live dock remains quiet, truthful, and keyboard operable", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/");
  await waitForPublicEvidence(page);

  const toggle = page.locator("[data-dock-toggle]");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.focus();
  await toggle.press("Enter");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("[data-dock-panel]")).toBeVisible();
  await expect(page.locator("[data-cert-fingerprint]")).toHaveText(
    /^[0-9a-f]{64}$/i,
  );
  await expect(page.locator("[data-dogfood-dock]")).not.toContainText(
    /renewal due/i,
  );
  await expect(page.locator("[data-reminder-form]")).toHaveAttribute(
    "action",
    "/api/renewal-alerts/subscriptions",
  );
  await expect(
    page.locator('[data-dogfood-dock] a[href="/privacy/"]'),
  ).toBeVisible();

  const runningAnimations = await page.evaluate(
    () =>
      document
        .getAnimations()
        .filter(
          (animation) =>
            animation.playState === "running" &&
            (animation.effect?.getTiming().duration === "auto" ||
              Number(animation.effect?.getTiming().duration) > 1),
        ).length,
  );
  expect(runningAnimations).toBe(0);

  await page.keyboard.press("Escape");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toBeFocused();
});

test("live mobile navigation is keyboard operable and identifies the page", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/");
  await waitForPublicEvidence(page);

  const toggle = page.locator("[data-nav-toggle]");
  await expect(toggle).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.focus();
  await toggle.press("Enter");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("[data-site-nav]")).toBeVisible();
  await expect(
    page.locator('[data-site-nav] a[aria-current="page"]'),
  ).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toBeFocused();
});
