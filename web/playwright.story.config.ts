import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e", testMatch: "profile-story.spec.ts", workers: 1, reporter: "list",
  use: { baseURL: "http://127.0.0.1:3018", browserName: "chromium", trace: "retain-on-failure" },
  webServer: {
    command: "node mock/dev.mjs",
    env: { ITDA_MOCK_WEB_PORT: "3018", ITDA_MOCK_API_PORT: "8028", ITDA_NEXT_DIST_DIR: ".next-story" },
    url: "http://127.0.0.1:3018/start", reuseExistingServer: !process.env.CI, timeout: 120_000,
  },
});
