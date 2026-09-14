import { expect, test } from "@playwright/test";
import { JOURNEY_COPY, TRIP_CHOICES } from "../src/content/journey.ko";

test.beforeEach(async ({ page }) => {
  await page.clock.install({ time: new Date("2026-09-14T03:00:00Z") });
  await page.goto("/start");
});

test("rejects past values emitted by a date input and submits the last valid date", async ({ page }, info) => {
  const date = page.getByLabel("방문 날짜 (선택)");
  await expect(date).toHaveAttribute("min", "2026-09-14");
  await date.fill("2026-09-13");
  await expect(date).toHaveValue("2026-09-14");
  await expect(page.getByText("지난 날짜는 선택할 수 없어요. 2026-09-14로 되돌렸어요.")).toBeVisible();
  await date.fill("2026-10-03");
  await date.fill("2026-09-13");
  await expect(date).toHaveValue("2026-10-03");
  await expect(page.getByText("지난 날짜는 선택할 수 없어요. 2026-10-03로 되돌렸어요.")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("itda.phase2.draft.v2"))).toBeNull();
  await date.scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("date-rejected.png") });
  for (const choices of Object.values(TRIP_CHOICES)) {
    await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
  }
  await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
  await expect(page).toHaveURL(/\/quiz$/);
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("itda.phase2.draft.v2")!).trip_conditions.visit_date)).toBe("2026-10-03");
});

test("still permits clearing the optional date", async ({ page }) => {
  const date = page.getByLabel("방문 날짜 (선택)");
  await date.fill("2026-09-13");
  await date.fill("");
  await expect(date).toHaveValue("");
  await expect(page.getByText(/지난 날짜는 선택할 수 없어요/)).toHaveCount(0);
  for (const choices of Object.values(TRIP_CHOICES)) {
    await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
  }
  await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
  await expect(page).toHaveURL(/\/quiz$/);
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("itda.phase2.draft.v2")!).trip_conditions.visit_date)).toBeNull();
});
