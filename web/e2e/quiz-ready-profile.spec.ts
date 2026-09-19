import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { TRIP_CHOICES } from "../src/content/journey.ko";

for (const width of [1440, 390]) test(`quiz opens a ready profile without an intermediate screen at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 900 });
  await page.goto("/start");
  for (const choices of Object.values(TRIP_CHOICES)) {
    await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
  }
  await page.getByRole("button", { name: "취향 테스트 시작하기", exact: true }).click();
  for (const question of FRONTEND_QUESTIONNAIRE.questions.slice(0, -1)) {
    await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
  }

  let profileReads = 0;
  page.on("request", request => {
    if (request.method() === "GET" && new URL(request.url()).pathname.startsWith("/v1/preference-profiles/")) profileReads++;
  });
  let releaseSubmission!: () => void;
  const gate = new Promise<void>(resolve => { releaseSubmission = resolve; });
  let submitting = false;
  await page.route("**/v1/preference-profiles", async route => {
    if (route.request().method() === "POST") { submitting = true; await gate; }
    await route.continue();
  });
  await page.evaluate(() => {
    const seen: string[] = [];
    (window as unknown as { profileLoadingScreens: string[] }).profileLoadingScreens = seen;
    new MutationObserver(records => {
      for (const record of records) for (const node of record.addedNodes) {
        if (node instanceof Element && (node.matches("#profile-loading-title") || node.querySelector("#profile-loading-title"))) {
          seen.push("profile-loading");
        }
      }
    }).observe(document.body, { childList: true, subtree: true });
  });
  const lastQuestion = FRONTEND_QUESTIONNAIRE.questions.at(-1)!;
  await page.getByRole("radio", { name: lastQuestion.options[0].text_ko, exact: true }).click();
  await expect.poll(() => submitting).toBe(true);
  await expect(page).toHaveURL(/\/quiz$/);
  await expect(page.locator("#profile-loading-title")).toHaveCount(0);
  releaseSubmission();

  await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
  await expect(page).toHaveURL(/\/profile$/);
  expect(await page.evaluate(() => (window as unknown as { profileLoadingScreens: string[] }).profileLoadingScreens)).toEqual([]);
  expect(profileReads).toBe(0);

  // A fresh document still restores its saved profile from the API.
  await page.reload();
  await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
  expect(profileReads).toBeGreaterThan(0);
});
