import { defineConfig } from "@playwright/test";

const port = process.env.ITDA_MOCK_WEB_PORT ?? "3012";
const baseURL = `http://127.0.0.1:${port}`;

/** Design integration checks use synthetic data and never require model/provider access. */
export default defineConfig({
  testDir: "./e2e",
  testMatch: ["mock-server.spec.ts", "main-header.spec.ts", "photo-mood-flow.spec.ts"],
  workers: 1,
  reporter: "list",
  use: { baseURL, browserName: "chromium", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: {
    command: "node mock/dev.mjs",
    url: `${baseURL}/start`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
