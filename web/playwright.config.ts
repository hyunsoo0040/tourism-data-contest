import { defineConfig, devices } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(webRoot, "..");
const backendReadinessTimeoutMs = 2_070_000;
const frontendReadinessTimeoutMs = 300_000;
const frontendPort = 5173;
const frontendOrigin = `http://127.0.0.1:${frontendPort}`;
const reuseExistingServers = process.env.ITDA_E2E_REUSE_SERVERS === "1";
const phase3CapabilityNames = [
  "EVALUATOR_A",
  "EVALUATOR_B",
  "EVALUATOR_C",
  "ADJUDICATOR",
  "MODEL_RUNNER",
  "BUILDER",
  "APPROVER",
] as const;

for (const capabilityName of phase3CapabilityNames) {
  const environmentName = `ITDA_E2E_PHASE3_${capabilityName}_CAPABILITY`;
  process.env[environmentName] ??= randomBytes(32).toString("base64url");
}

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: frontendOrigin,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: "make e2e-backend",
      cwd: repoRoot,
      reuseExistingServer: reuseExistingServers,
      timeout: backendReadinessTimeoutMs,
      url: "http://127.0.0.1:8000/v1/questionnaires/current",
      stdout: "pipe",
      stderr: "pipe",
      gracefulShutdown: {
        signal: "SIGTERM",
        timeout: 60_000,
      },
    },
    {
      command: `pnpm dev -H 127.0.0.1 -p ${frontendPort}`,
      cwd: webRoot,
      reuseExistingServer: reuseExistingServers,
      timeout: frontendReadinessTimeoutMs,
      url: `${frontendOrigin}/start`,
      stdout: "pipe",
      stderr: "pipe",
      gracefulShutdown: {
        signal: "SIGTERM",
        timeout: 10_000,
      },
    },
  ],
});
