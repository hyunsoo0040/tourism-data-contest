import { defineConfig } from "@playwright/test";
const port = process.env.ITDA_MOCK_WEB_PORT ?? "3012";
const baseURL = `http://127.0.0.1:${port}`;
export default defineConfig({
  testDir: "./e2e", testMatch: "mock-server.spec.ts", workers: 1, reporter: "list",
  use: { baseURL, browserName: "chromium", trace: "retain-on-failure" },
  webServer: { command: "node mock/dev.mjs", url: `${baseURL}/start`, reuseExistingServer: !process.env.CI, timeout: 120_000 },
});
