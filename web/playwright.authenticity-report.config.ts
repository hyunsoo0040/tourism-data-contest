import {defineConfig} from "@playwright/test";
export default defineConfig({testDir:"./e2e",testMatch:"authenticity-report.spec.ts",workers:1,timeout:90_000,
  use:{baseURL:"http://127.0.0.1:8768",trace:"retain-on-failure"},
  outputDir:"../artifacts/authenticity-v1/20260911/report-browser-tests"});
