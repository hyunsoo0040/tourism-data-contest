import { expect, test } from "@playwright/test";

const mode = process.env.ITDA_E2E_LIFECYCLE_MODE ?? "success";

test.beforeEach(async ({ page }) => {
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    ) {
      if (url.hostname.endsWith("fonts.googleapis.com") || url.hostname === "fonts.gstatic.com") {
        await route.abort();
        return;
      }
      throw new Error(`non-loopback browser request blocked: ${url.href}`);
    }
    await route.continue();
  });
});

test("success probe readies both Playwright-owned servers", async ({ page }) => {
  test.skip(mode !== "success", `lifecycle mode is ${mode}`);

  await page.goto("/start");
  const questionnaire = page.waitForResponse(
    (response) => response.url().endsWith("/v1/questionnaires/current"),
  );
  await page.evaluate(() => fetch("/v1/questionnaires/current"));
  const response = await questionnaire;

  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("application/json");
  await expect(
    page.getByRole("heading", { name: "이번 경주, 어떤 시간을 보내고 싶나요?" }),
  ).toBeVisible();
});

test("intentional failure probe still tears down webServers", async ({ page }) => {
  test.skip(mode !== "intentional-failure", `lifecycle mode is ${mode}`);

  await page.goto("/start");
  console.log("ITDA_E2E_INTENTIONAL_FAILURE_REACHED");
  await expect(page.getByText("intentional lifecycle failure sentinel")).toBeVisible({
    timeout: 1_000,
  });
});

test("interruption probe waits with both servers ready", async ({ page }) => {
  test.skip(mode !== "wait-for-interruption", `lifecycle mode is ${mode}`);

  await page.goto("/start");
  await expect(
    page.getByRole("heading", { name: "이번 경주, 어떤 시간을 보내고 싶나요?" }),
  ).toBeVisible();
  console.log("ITDA_E2E_READY_FOR_INTERRUPTION");
  await new Promise(() => undefined);
});
