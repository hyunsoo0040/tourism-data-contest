import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { JOURNEY_COPY, TRIP_CHOICES } from "../src/content/journey.ko";

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`local mock: home → conditions → quiz → profile → results → detail → map (${viewport.name})`, async ({ page }, info) => {
    test.setTimeout(120_000);
    await page.setViewportSize(viewport);
    const errors: string[] = [];
    const external: string[] = [];
    let recommendationRequests = 0;
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname === "/v1/authenticity/runs") recommendationRequests++;
    });
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost"].includes(url.hostname)) { external.push(url.origin); return route.abort(); }
      return route.continue();
    });
    await page.goto("/");
    await page.getByRole("link", { name: "시작하기", exact: true }).click();
    await expect(page).toHaveURL(/\/start$/);
    await expect(page.getByRole("complementary", { name: "UI 목업 설정" })).toBeVisible();
    await page.screenshot({ path: info.outputPath("design-start.png"), fullPage: true });
    for (const choices of Object.values(TRIP_CHOICES)) await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
    await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
    await expect(page).toHaveURL(/\/quiz$/);
    for (const question of FRONTEND_QUESTIONNAIRE.questions) {
      await expect(page.getByRole("heading", { name: question.title_ko, exact: true })).toBeVisible();
      await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
    }
    await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
    await expect(page).toHaveURL(/\/profile$/);
    expect(recommendationRequests).toBe(0);
    await expect(page.getByRole("meter")).toHaveCount(3);
    const display = await page.getByRole("meter").evaluateAll((meters) => meters.map((meter) => Number(meter.getAttribute("aria-valuenow"))));
    expect(display).toEqual([34, 33, 33]);
    expect(display.reduce((sum, value) => sum + value, 0)).toBe(100);
    await expect(page.getByText(/의 원점수가 같아요/)).toHaveCount(0);
    await expect(page.getByText(/표시 점수 1점 차이/)).toHaveCount(0);
    for (const label of ["대상•원형형 34점 / 100점", "의미•이미지형 33점 / 100점", "자기•몰입형 33점 / 100점"]) {
      await expect(page.getByRole("meter", { name: label, exact: true })).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    const profileUrl = page.url();
    const previousAnswers = await page.evaluate(() => JSON.parse(localStorage.getItem("itda.phase2.draft.v2")!).answers);
    await page.goto("/");
    await expect(page.locator(".photo-intro-copy")).toHaveCount(0);
    const start = page.getByRole("link", { name: "시작하기", exact: true });
    await expect(start).toHaveAttribute("href", "/start");
    await start.click();
    await expect(page).toHaveURL(/\/start$/);
    await expect(page.getByRole("button", { name: "여행 조건 그대로 유지", exact: true })).toBeVisible();
    await page.getByLabel("방문 날짜 (선택)").fill("2099-10-03");
    await page.getByRole("radio", { name: "친구", exact: true }).check();
    const updatedRequest = page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === "/v1/preference-profiles");
    await page.getByRole("button", { name: "여행 조건 그대로 유지", exact: true }).click();
    const updatedBody = (await updatedRequest).postDataJSON();
    expect(updatedBody.answers).toEqual(previousAnswers);
    expect(updatedBody.trip_conditions).toMatchObject({ visit_date: "2099-10-03", companion: "FRIEND_OR_PARTNER" });
    await expect(page).toHaveURL(profileUrl);
    await expect(page.getByRole("button", { name: "추천 장소 보기", exact: true })).toBeVisible();
    const photoIntro = page.locator(".profile-photo-intro");
    await expect(photoIntro).toBeVisible();
    await expect(photoIntro.getByText("선택 입력", { exact: true })).toHaveCount(0);
    await expect(photoIntro.getByText("내가 끌리는 장면이, 여행의 힌트가 되도록.")).toHaveCount(0);
    expect(await photoIntro.evaluate((section) => section.previousElementSibling?.classList.contains("profile-result"))).toBe(true);
    await photoIntro.screenshot({ path: info.outputPath("profile-photo-intro.png") });
    await page.screenshot({ path: info.outputPath("design-profile.png"), fullPage: true });
    expect(recommendationRequests).toBe(0);
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect(page.locator("[data-scenario-place]")).toHaveCount(5);
    await expect(page).toHaveURL(/\/recommendations\/a-[a-f0-9]{64}$/);
    const resultsUrl = page.url();
    for (const label of ["취향 결과 확인", "여행 지역·방문 조건 수정", "저장한 장소"]) {
      await expect(page.locator(".recommendations-intro").getByRole("link", { name: label, exact: true })).toHaveCount(0);
    }
    await expect(page.getByText("내 답변과 추천의 연결 방식", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "확인할 점", exact: true })).toHaveCount(0);
    expect(recommendationRequests).toBe(1);
    await expect(page.locator('[data-scenario-place][data-details-loaded="true"]')).toHaveCount(5);
    for (const image of await page.locator('[data-scenario-place] img').all()) {
      await expect(image).toBeVisible();
      expect(await image.evaluate((node: HTMLImageElement) => node.complete && node.naturalWidth > 0)).toBe(true);
    }
    await page.screenshot({ path: info.outputPath("mock-results.png"), fullPage: true });
    const first = page.locator("[data-scenario-place]").first();
    await first.screenshot({ path: info.outputPath("first-place.png") });
    await expect(first.getByRole("heading", { name: "1위 천장호", exact: true })).toBeVisible();
    await expect(first.locator(".recommendation-location")).toContainText("충청남도");
    await expect(first.getByRole("link", { name: "지도에서 보기", exact: true })).toHaveAttribute("href", /^https:\/\/map\.kakao\.com\/link\/search\//);
    await expect(first.getByRole("button", { name: /저장/ })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /비교/ })).toHaveCount(0);
    await first.getByRole("link", { name: "상세 보기", exact: true }).click();
    await expect(page.getByRole("heading", { name: "장소 소개", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "이 점수의 근거", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "추천 목록으로", exact: true }).click();
    await page.reload();
    await expect(first.getByRole("link", { name: "상세 보기", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.goto(profileUrl);
    await page.getByLabel("추천 상태").selectOption("empty");
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect(page.getByRole("heading", { name: "이 조건에 맞는 여행지가 아직 충분하지 않아요.", exact: true })).toBeVisible();
    await expect(page.locator("[data-scenario-place]")).toHaveCount(0);
    await page.goto(profileUrl);
    await page.getByLabel("추천 상태").selectOption("error");
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect(page.locator('section[role="alert"]')).toContainText("목업에서 선택한 서버 오류 상태입니다.");
    await page.getByLabel("추천 상태").selectOption("normal");
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect(page.locator("[data-scenario-place]")).toHaveCount(5);
    await page.getByRole("button", { name: "목업 초기화", exact: true }).click();
    await expect(page.getByRole("heading", { name: JOURNEY_COPY.start.title })).toBeVisible();
    expect(errors).toEqual([]); expect(external).toEqual([]);
  });
}
