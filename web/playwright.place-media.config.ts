import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e", testMatch: "place-media.spec.ts", workers: 1, timeout: 240_000,
  expect: { timeout: 30_000 },
  use: { baseURL: process.env.ITDA_AUTHENTICITY_E2E_URL ?? "https://localhost:3443", ignoreHTTPSErrors: true, actionTimeout: 60_000, trace: "retain-on-failure" },
  outputDir: "../artifacts/ui/place-media-20260914/browser-tests",
});
