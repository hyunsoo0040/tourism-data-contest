import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e", testMatch: ["authenticity-journey.spec.ts","authenticity-preferences.spec.ts"], workers: 1, timeout: 240_000,
  // Emulated deployment rehearsal has a separate budget; normal checks retain 5 seconds.
  expect: { timeout: Number(process.env.ITDA_E2E_EXPECT_TIMEOUT_MS ?? 5000) },
  use: {
    baseURL: process.env.ITDA_AUTHENTICITY_E2E_URL ?? "http://127.0.0.1:3082",
    ignoreHTTPSErrors: process.env.ITDA_E2E_IGNORE_HTTPS_ERRORS === "1",
    trace: "retain-on-failure",
  },
  outputDir: process.env.ITDA_E2E_OUTPUT_DIR ?? "../artifacts/authenticity-v1/20260911/browser-tests",
});
