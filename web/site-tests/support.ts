import { readFileSync } from "node:fs";

import type { Page } from "@playwright/test";

export const fixedNow = new Date("2026-08-18T00:00:00Z");

export const validEvidence = {
  estimateBasis:
    "Expected public replacement window from dogfood schedule evidence.",
  expiresAt: "2026-11-15T01:05:34Z",
  fingerprintSha256:
    "3564029b1580f99ed3b91d8a9c2160ba33260cda00955812ed95eefc74e8cbe7",
  issuedAt: "2026-08-17T01:05:35Z",
  lastDeployedAt: "2026-08-17T03:20:35Z",
  managedBy: "AcmeMux",
  nextRenewalAt: "2026-08-20T09:35:00Z",
  profile: "Classic Let's Encrypt profile",
};

export function siteRoutes(): string[] {
  const sitemap = readFileSync(
    new URL("../../site/dist/sitemap.xml", import.meta.url),
    "utf8",
  );
  return Array.from(
    sitemap.matchAll(/<loc>https:\/\/acmemux\.com([^<]+)<\/loc>/g),
    (match) => match[1],
  );
}

export async function preparePage(
  page: Page,
  evidence: Record<string, unknown> = validEvidence,
): Promise<void> {
  await page.clock.install({ time: fixedNow });
  await page.route("**/certificate-status.json", async (route) => {
    await route.fulfill({
      body: JSON.stringify(evidence),
      contentType: "application/json",
      status: 200,
    });
  });
}

export async function openDock(page: Page): Promise<void> {
  await page.locator("[data-dock-toggle]").click();
  await page.locator("[data-dock-panel]").waitFor({ state: "visible" });
}
