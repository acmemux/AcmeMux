import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./site-live-tests",
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4174",
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
  },
  workers: 1,
  webServer: {
    command: "node ../site/scripts/serve.mjs",
    reuseExistingServer: false,
    timeout: 30_000,
    url: "http://127.0.0.1:4174",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
