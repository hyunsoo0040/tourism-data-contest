import { defineConfig } from "@playwright/test";

/** Frontend-only checks deliberately run without a Docker/backend dependency. */
export default defineConfig({
  testDir: "./e2e",
  testMatch: "frontend-questionnaire.spec.ts",
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:3011",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node node_modules/next/dist/bin/next dev -H 127.0.0.1 -p 3011",
    url: "http://127.0.0.1:3011/start",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
