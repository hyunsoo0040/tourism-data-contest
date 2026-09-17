import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { TRIP_CHOICES } from "../src/content/journey.ko";

for (const width of [1440, 390]) test(`mock photo upload → automatic cues → results at ${width}px`, async ({ page }, info) => {
  await page.setViewportSize({ width, height: 900 });
  const errors: string[] = [], external: string[] = [];
  const submissions: { visual_input_kind?: string; visual_targets?: Record<string, number> }[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/v1/authenticity/scenario-profiles" && request.method() === "POST") submissions.push(request.postDataJSON());
  });
  // Exercise the actual local mock server. Never substitute an API response.
  await page.route("**/*", route => {
    const url = new URL(route.request().url());
    if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost"].includes(url.hostname)) {
      external.push(url.origin); return route.abort();
    }
    return route.continue();
  });
  await page.goto("/start");
  for (const choices of Object.values(TRIP_CHOICES)) await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
  await page.getByRole("button", { name: "취향 테스트 시작하기", exact: true }).click();
  for (const question of FRONTEND_QUESTIONNAIRE.questions) await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
  await page.getByRole("button", { name: "사진으로 추천받기", exact: true }).click();
  await expect(page).toHaveURL(/\/photo$/);
  await expect(page.getByText(/목업에서는 선택한 사진을 실제로 분석하지 않고/)).toBeVisible();
  await page.getByRole("checkbox", { name: "사진을 분위기 분석에 사용하는 데 동의해요." }).check();
  const file = { name: "test.png", mimeType: "image/png", buffer: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a4ZkAAAAASUVORK5CYII=", "base64") };
  const picker = page.getByLabel("여행 분위기 참고 사진");
  await picker.setInputFiles(file);
  await expect(page.getByRole("heading", { name: "사진 분위기 예시가 준비됐어요" })).toBeVisible();
  await page.getByRole("button", { name: "사진 분석 결과 삭제", exact: true }).click();
  await expect(page.getByRole("button", { name: "사진 분위기로 추천 보기", exact: true })).toHaveCount(0);
  await picker.setInputFiles(file);
  await expect(page.getByRole("button", { name: "사진 분위기로 추천 보기", exact: true })).toBeEnabled();
  await expect(page.getByRole("checkbox")).toHaveCount(1);
  await expect(page.getByText(/greenery|open_composition|녹지 3\/4/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "사진 없이 추천 보기", exact: true })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("mock-photo.png"), fullPage: true });
  await page.getByRole("button", { name: "사진 분위기로 추천 보기", exact: true }).click();
  await expect(page).toHaveURL(/\/recommendations\/a-[a-f0-9]{64}$/);
  await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
  expect(submissions).toHaveLength(1);
  expect(submissions[0]?.visual_input_kind).toBe("CONFIRMED_PHOTO");
  expect(Object.keys(submissions[0]?.visual_targets ?? {})).toHaveLength(8);
  await expect(page.locator("[data-scenario-place]").first().getByRole("link", { name: "지도에서 보기" })).toBeVisible();
  await page.reload();
  await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
  await page.goto("/photo");
  await expect(page.getByRole("button", { name: "사진 분위기로 추천 보기", exact: true })).toBeEnabled();
  await expect(page.getByRole("heading", { name: "사진 분위기 예시가 준비됐어요" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  expect(errors).toEqual([]); expect(external).toEqual([]);
});
