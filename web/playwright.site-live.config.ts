import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./site-live-tests",
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: "https://acmemux.com",
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
  },
  workers: 1,
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
