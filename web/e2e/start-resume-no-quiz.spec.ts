import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { TRIP_CHOICES } from "../src/content/journey.ko";

for (const width of [1440, 390]) test(`saved test resumes without showing quiz at ${width}px`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  await page.goto("/start");
  for (const choices of Object.values(TRIP_CHOICES)) await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
  await page.getByRole("button", { name: "취향 테스트 시작하기", exact: true }).click();
  for (const question of FRONTEND_QUESTIONNAIRE.questions) {
    await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
  }
  await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
  let profileReads = 0;
  page.on("request", request => {
    if (request.method() === "GET" && new URL(request.url()).pathname.startsWith("/v1/preference-profiles/")) profileReads++;
  });
  let releaseSubmission!: () => void;
  const submissionGate = new Promise<void>(resolve => { releaseSubmission = resolve; });
  let submitting = false;
  await page.route("**/v1/preference-profiles", async route => {
    if (route.request().method() === "POST") { submitting = true; await submissionGate; }
    await route.continue();
  });
  await page.goto("/start");
  await expect(page.getByRole("button", { name: "여행 조건 그대로 유지", exact: true })).toBeVisible();
  await page.evaluate(() => {
    const seen: string[] = [];
    (window as unknown as { resumeScreens: string[] }).resumeScreens = seen;
    new MutationObserver(records => {
      for (const record of records) for (const node of record.addedNodes) {
        if (node instanceof Element && (node.matches('[data-upstream-surface="quiz"]') || node.querySelector('[data-upstream-surface="quiz"]'))) seen.push("quiz");
        if (node instanceof Element && (node.matches("#profile-loading-title") || node.querySelector("#profile-loading-title"))) seen.push("profile-loading");
      }
    }).observe(document.body, { childList: true, subtree: true });
    window.addEventListener("itda:navigate", () => seen.push(location.pathname));
  });
  await page.getByRole("button", { name: "여행 조건 그대로 유지", exact: true }).click();
  await expect.poll(() => submitting).toBe(true);
  await expect(page).toHaveURL(/\/start$/);
  await expect(page.getByRole("button", { name: "프로필 만드는 중…", exact: true })).toBeDisabled();
  releaseSubmission();
  await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
  const seen = await page.evaluate(() => (window as unknown as { resumeScreens: string[] }).resumeScreens);
  await info.attach("resume-screens", { body: JSON.stringify(seen), contentType: "application/json" });
  expect(seen).not.toContain("quiz");
  expect(seen).not.toContain("/quiz");
  expect(seen).not.toContain("profile-loading");
  expect(profileReads).toBe(1);
  await expect(page).toHaveURL(/\/profile$/);
  await page.reload();
  await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
  // Development StrictMode may abort and repeat the reload request.
  expect(profileReads).toBeGreaterThan(1);
});
