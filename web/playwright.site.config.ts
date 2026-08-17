import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./site-tests",
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  snapshotPathTemplate:
    "{testDir}/{testFilePath}-snapshots/{arg}-{projectName}{ext}",
  use: {
    baseURL: "http://127.0.0.1:4174",
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node ../site/scripts/serve.mjs",
    url: "http://127.0.0.1:4174",
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
