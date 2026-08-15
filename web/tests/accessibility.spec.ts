import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { mockSession, mockSessionFailure } from "./support/session";
import {
  mockRuntime,
  supportedCandidate,
  supportedRuntime,
} from "./support/runtime";
import { mockWorkspace } from "./support/workspace";

const desktopViewport = { width: 1440, height: 1000 };

async function expectNoWcagViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa"])
    .analyze();

  expect(results.violations).toEqual([]);
}

test.describe("application accessibility", () => {
  test.beforeEach(async ({ page }) => {
    await mockSession(page);
    await mockRuntime(page);
    await mockWorkspace(page);
  });

  test("default desktop shell has no WCAG A or AA violations", async ({
    page,
  }) => {
    await page.setViewportSize(desktopViewport);
    await page.goto("/");

    await expect(
      page.getByRole("heading", {
        name: "Certificate operations",
        exact: true,
      }),
    ).toBeVisible();
    await expect(
      page.getByRole("navigation", { name: "Primary navigation" }),
    ).toBeVisible();

    await expectNoWcagViolations(page);
  });

  test("component catalog has no WCAG A or AA violations", async ({ page }) => {
    await page.setViewportSize(desktopViewport);
    await page.goto("/?catalog=components");

    await expect(
      page.getByRole("heading", { name: "Component catalog", exact: true }),
    ).toBeVisible();

    await expectNoWcagViolations(page);

    await page
      .getByRole("button", { name: "Review confirmation", exact: true })
      .click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expectNoWcagViolations(page);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeHidden();
  });

  test("narrow shell and catalog preserve landmarks without document overflow", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    for (const route of ["/", "/?catalog=components"]) {
      await page.goto(route);

      await expect(page.getByRole("main")).toBeVisible();
      await expect(
        page.getByRole("navigation", { name: "Primary navigation" }),
      ).toBeVisible();

      const widths = await page.evaluate(() => ({
        client: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      }));

      expect(widths.scroll, route).toBeLessThanOrEqual(widths.client);
    }
  });

  test("first meaningful action has a visible keyboard focus indicator", async ({
    page,
  }) => {
    await page.setViewportSize(desktopViewport);
    await page.goto("/");

    const firstAction = page.getByRole("link", {
      name: "View component catalog",
      exact: true,
    });
    await expect(firstAction).toBeVisible();

    await firstAction.focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Shift+Tab");

    await expect(firstAction).toBeFocused();
    const focusIndicator = await firstAction.evaluate((element) => {
      const styles = window.getComputedStyle(element);
      return {
        boxShadow: styles.boxShadow,
        focusVisible: element.matches(":focus-visible"),
        outlineStyle: styles.outlineStyle,
        outlineWidth: Number.parseFloat(styles.outlineWidth),
      };
    });

    expect(focusIndicator.focusVisible).toBe(true);
    expect(
      (focusIndicator.outlineStyle !== "none" &&
        focusIndicator.outlineWidth > 0) ||
        focusIndicator.boxShadow !== "none",
    ).toBe(true);
  });

  test("two-hundred-percent text remains readable without document overflow", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/");
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });

    await expect(
      page.getByRole("heading", { name: "Certificate operations" }),
    ).toBeVisible();
    const layout = await page.evaluate(() => {
      const client = document.documentElement.clientWidth;
      const overflow = Array.from(document.querySelectorAll("*"))
        .map((element) => {
          const bounds = element.getBoundingClientRect();
          const styles = window.getComputedStyle(element);
          return {
            clientWidth: element.clientWidth,
            element: `${element.tagName.toLowerCase()}.${element.className}`,
            left: Math.round(bounds.left),
            overflowX: styles.overflowX,
            right: Math.round(bounds.right),
            scrollWidth: element.scrollWidth,
          };
        })
        .filter(
          (element) =>
            element.right > client + 1 ||
            element.left < -1 ||
            (element.scrollWidth > element.clientWidth + 1 &&
              element.overflowX === "visible"),
        )
        .slice(0, 20);
      return {
        client,
        overflow,
        scroll: document.documentElement.scrollWidth,
      };
    });
    expect(layout.scroll, JSON.stringify(layout.overflow)).toBeLessThanOrEqual(
      layout.client,
    );
  });

  test("reduced-motion preference removes meaningful animation", async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/?catalog=components");

    const pendingButton = page.getByRole("button", { name: /Saving/ });
    const spinner = pendingButton.locator(".am-spinner");
    await expect(spinner).toBeVisible();
    const timing = await spinner.evaluate((element) => {
      const styles = window.getComputedStyle(element);
      return {
        animationDuration: Number.parseFloat(styles.animationDuration),
        transitionDuration: Number.parseFloat(styles.transitionDuration),
      };
    });
    expect(timing.animationDuration).toBeLessThanOrEqual(0.00001);
    expect(timing.transitionDuration).toBeLessThanOrEqual(0.00001);
  });

  test("runtime evidence review has no WCAG A or AA violations", async ({
    page,
  }) => {
    await page.setViewportSize(desktopViewport);
    await page.goto("/");
    await page
      .getByLabel("Host executable path")
      .fill(supportedCandidate.candidate.canonicalPath);
    await page.getByRole("button", { name: "Inspect executable" }).click();

    await expect(
      page.getByRole("heading", { name: "Review executable evidence" }),
    ).toBeVisible();
    await expectNoWcagViolations(page);
  });

  test("runtime setup remains usable without narrow document overflow", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");

    await expect(page.getByLabel("Host executable path")).toBeVisible();
    const widths = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(widths.scroll).toBeLessThanOrEqual(widths.client);
    await expectNoWcagViolations(page);
  });

  test("workspace path review has no WCAG A or AA violations", async ({
    page,
  }) => {
    await page.setViewportSize(desktopViewport);
    await mockRuntime(page, { initial: supportedRuntime });
    await page.goto("/");
    await page.getByLabel("Effective working directory").fill("/srv/lego");
    await page.getByRole("button", { name: "Inspect workspace" }).click();

    await expect(
      page.getByRole("heading", { name: "Review native workspace evidence" }),
    ).toBeVisible();
    await expectNoWcagViolations(page);
  });
});

test.describe("authentication accessibility", () => {
  for (const state of ["signed_out", "uninitialized", "expired"] as const) {
    test(`${state} state has no WCAG A or AA violations`, async ({ page }) => {
      await page.setViewportSize(desktopViewport);
      await mockSession(page, state);
      await page.goto("/");

      await expect(page.getByRole("main")).toBeVisible();
      await expectNoWcagViolations(page);
    });
  }

  test("request-blocked state has no WCAG A or AA violations", async ({
    page,
  }) => {
    await page.setViewportSize(desktopViewport);
    await mockSessionFailure(page, 403, "request_not_allowed");
    await page.goto("/");

    await expect(
      page.getByRole("heading", {
        name: "AcmeMux rejected this browser request",
      }),
    ).toBeVisible();
    await expectNoWcagViolations(page);
  });

  test("sign-in remains usable at a narrow viewport", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await mockSession(page, "signed_out");
    await page.goto("/");

    await expect(page.getByLabel("Administrator password")).toBeVisible();
    const widths = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(widths.scroll).toBeLessThanOrEqual(widths.client);
    await expectNoWcagViolations(page);
  });
});
