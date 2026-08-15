import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/webassets/dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: "./src/test-setup.ts",
  },
});
