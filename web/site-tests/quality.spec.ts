import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { openDock, preparePage, siteRoutes } from "./support";

const routes = [...siteRoutes(), "/404.html"];

for (const width of [320, 375, 768, 1440]) {
  test(`all pages reflow without horizontal overflow at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: width < 700 ? 812 : 900 });
    await preparePage(page);
    for (const route of routes) {
      await page.goto(route);
      const report = await page.evaluate(() => {
        const viewport = document.documentElement.clientWidth;
        const offenders = Array.from(
          document.querySelectorAll<HTMLElement>("body *"),
        )
          .filter((element) => {
            const style = getComputedStyle(element);
            if (style.display === "none" || style.position === "fixed")
              return false;
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
    await openDock(page);
    const dockBox = await page.locator("[data-dogfood-dock]").boundingBox();
    expect(dockBox).not.toBeNull();
    expect(dockBox?.x ?? -1).toBeGreaterThanOrEqual(0);
    expect((dockBox?.x ?? 0) + (dockBox?.width ?? 0)).toBeLessThanOrEqual(
      width,
    );
  });
}

for (const width of [375, 1440]) {
  test(`all pages have no WCAG A or AA axe violations at ${width}px`, async ({
    page,
  }) => {
    test.slow();
    await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
    await preparePage(page);
    for (const route of routes) {
      await page.goto(route);
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

test("representative pages remain usable at 200 percent text", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await preparePage(page);
  for (const route of ["/", "/roadmap/", "/learn/lets-encrypt-route-53/"]) {
    await page.goto(route);
    await page.evaluate(() => {
      document.documentElement.style.fontSize = "200%";
    });
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    expect(overflow, route).toBeLessThanOrEqual(1);
    await expect(page.locator("h1")).toBeVisible();
    await expect(page.locator("[data-dock-toggle]")).toBeVisible();
  }
});

test("lifecycle visual uses a legible narrow-screen composition", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await preparePage(page);
  await page.goto("/");
  await expect(page.locator(".lifecycle-figure > svg")).toBeHidden();
  const mobile = page.locator(".lifecycle-mobile");
  await expect(mobile).toBeVisible();
  await expect(mobile.locator(".mobile-direction > span")).toHaveCount(8);
  const smallestText = await mobile.evaluate((element) =>
    Math.min(
      ...Array.from(element.querySelectorAll("small, strong, span"), (node) =>
        Number.parseFloat(getComputedStyle(node).fontSize),
      ),
    ),
  );
  expect(smallestText).toBeGreaterThanOrEqual(10);

  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.locator(".lifecycle-figure > svg")).toBeVisible();
  await expect(mobile).toBeHidden();
});

test("reduced motion preserves navigation and dock interaction", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await preparePage(page);
  await page.goto("/");
  await page.locator("[data-nav-toggle]").click();
  await expect(page.locator("[data-site-nav]")).toBeVisible();
  await openDock(page);
  await expect(page.locator("[data-dock-panel]")).toBeVisible();
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
});

test("preview server returns correct not-found and manifest responses", async ({
  request,
}) => {
  const missing = await request.get("/definitely-not-a-real-route");
  expect(missing.status()).toBe(404);
  expect(await missing.text()).toContain("noindex,nofollow");

  const manifest = await request.get("/site.webmanifest");
  expect(manifest.status()).toBe(200);
  expect(manifest.headers()["content-type"]).toContain(
    "application/manifest+json",
  );

  const statusPost = await request.post("/certificate-status.json");
  expect(statusPost.status()).toBe(405);

  const reminderGet = await request.get("/api/renewal-alerts/subscriptions");
  expect(reminderGet.status()).toBe(405);
  const reminderWrongType = await request.post(
    "/api/renewal-alerts/subscriptions",
    { data: "operator@example.com", headers: { "Content-Type": "text/plain" } },
  );
  expect(reminderWrongType.status()).toBe(415);
  const reminderBadJson = await request.post(
    "/api/renewal-alerts/subscriptions",
    { data: "{", headers: { "Content-Type": "application/json" } },
  );
  expect(reminderBadJson.status()).toBe(400);
  const reminderAccepted = await request.post(
    "/api/renewal-alerts/subscriptions",
    { data: { email: "operator@example.com", website: "" } },
  );
  expect(reminderAccepted.status()).toBe(202);

  const malformedPath = await request.get("/%E0%A4%A");
  expect(malformedPath.status()).toBe(400);
});
