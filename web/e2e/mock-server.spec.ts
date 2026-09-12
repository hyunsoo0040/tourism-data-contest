import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { JOURNEY_COPY, TRIP_CHOICES } from "../src/content/journey.ko";

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`real mock server: quiz → profile → results → compare → detail → saved (${viewport.name})`, async ({ page }, info) => {
    test.setTimeout(120_000);
    await page.setViewportSize(viewport);
    const errors: string[] = [];
    const external: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost"].includes(url.hostname)) { external.push(url.origin); return route.abort(); }
      return route.continue();
    });
    await page.goto("/start");
    await expect(page.getByRole("complementary", { name: "UI 목업 설정" })).toBeVisible();
    await page.screenshot({ path: info.outputPath("design-start.png"), fullPage: true });
    for (const choices of Object.values(TRIP_CHOICES)) await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
    await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
    for (const question of FRONTEND_QUESTIONNAIRE.questions) {
      await expect(page.getByRole("heading", { name: question.title_ko, exact: true })).toBeVisible();
      await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
    }
    await expect(page.getByRole("button", { name: "바로 추천 보기", exact: true })).toBeVisible();
    const profileUrl = page.url();
    await page.screenshot({ path: info.outputPath("design-profile.png"), fullPage: true });
    await page.getByRole("button", { name: "바로 추천 보기", exact: true }).click();
    await expect(page.locator("[data-grounded-item]")).toHaveCount(5);
    await page.screenshot({ path: info.outputPath("mock-results.png"), fullPage: true });
    const first = page.locator("[data-grounded-item]").first();
    await first.getByRole("button", { name: "가상 느린 정원 저장", exact: true }).click();
    for (const name of ["가상 느린 정원", "가상 빛의 거리"]) await page.getByRole("button", { name: `${name} 비교에 추가`, exact: true }).click();
    await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
    await expect(page.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" })).toBeVisible();
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    await page.getByRole("link", { name: "가상 느린 정원 상세 보기", exact: true }).click();
    await expect(page.getByRole("heading", { name: "사진에서 확인한 분위기" })).toBeVisible();
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    await page.reload();
    await expect(page.getByRole("button", { name: "가상 느린 정원 저장됨", exact: true })).toHaveAttribute("aria-pressed", "true");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    for (const [scenario, heading] of [["empty", "이 조건에 맞는 여행지가 아직 충분하지 않아요."], ["error", "추천 준비가 아직 끝나지 않았어요."]]) {
      await page.goto(profileUrl);
      await page.getByLabel("추천 상태").selectOption(scenario!);
      await expect(page.getByRole("button", { name: "바로 추천 보기", exact: true })).toBeVisible();
      await page.getByRole("button", { name: "바로 추천 보기", exact: true }).click();
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    }
    await page.getByRole("button", { name: "목업 초기화", exact: true }).click();
    await expect(page.getByRole("heading", { name: JOURNEY_COPY.start.title })).toBeVisible();
    expect(errors).toEqual([]); expect(external).toEqual([]);
  });
}
