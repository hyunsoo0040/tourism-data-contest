import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { JOURNEY_COPY, TRIP_CHOICES } from "../src/content/journey.ko";

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`frontend questions remain usable without a backend (${viewport.name})`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    const apiCalls: Array<{ path: string; method: string }> = [];
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    // Explicit outage fixture: no scoring, database writes, or provider requests.
    await page.route("**/v1/**", (route) => {
      apiCalls.push({ path: new URL(route.request().url()).pathname, method: route.request().method() });
      return route.fulfill({ status: 503, contentType: "application/json", body: '{"detail":"offline UI verification"}' });
    });
    await page.goto("/start");
    await expect(page.getByRole("heading", { name: JOURNEY_COPY.start.title })).toBeVisible();
    for (const choices of Object.values(TRIP_CHOICES)) {
      await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
    }
    await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
    const questions = FRONTEND_QUESTIONNAIRE.questions;
    await expect(page.getByRole("heading", { name: questions[0]!.title_ko, exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("quiz.png"), fullPage: true });
    for (const question of questions.slice(0, -1)) {
      await expect(page.getByRole("heading", { name: question.title_ko, exact: true })).toBeVisible();
      await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
    }
    await expect(page.getByRole("heading", { name: questions.at(-1)!.title_ko, exact: true })).toBeVisible();
    expect(apiCalls.filter((call) => call.path === "/v1/questionnaires/current")).toHaveLength(0);

    await page.getByRole("radio").first().click();
    await expect(page.locator(".up-quiz").getByRole("alert")).toContainText("프로필을 만들지 못했어요.");
    expect(apiCalls.filter((call) => call.path === "/v1/questionnaires/current")).toHaveLength(1);
    expect(apiCalls.filter((call) => call.method === "POST")).toHaveLength(0);
    expect(await page.evaluate(() => Object.keys(JSON.parse(localStorage.getItem("itda.phase2.draft.v2")!).answers))).toHaveLength(12);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
