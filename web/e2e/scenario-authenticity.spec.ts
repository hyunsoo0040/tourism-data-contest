import { expect, test } from "@playwright/test";
import { FRONTEND_QUESTIONNAIRE } from "../src/content/questionnaire";
import { JOURNEY_COPY, TRIP_CHOICES } from "../src/content/journey.ko";
import contract from "../../contracts/questionnaire-v2.json" with { type: "json" };

test.afterEach(async ({ page }, info) => {
  if (!page.url().startsWith("http://127.0.0.1:")) return;
  const evidence = await page.evaluate(async () => {
    const profile = localStorage.getItem("itda.phase1.profile.v1");
    const token = sessionStorage.getItem("itda.authenticity.session.v1");
    const deleted = token ? (await fetch("/v1/authenticity/session", { method: "DELETE", headers: { Authorization: `Bearer ${token}` } })).ok : true;
    sessionStorage.clear(); return { profile, latest_session_deleted: deleted };
  });
  await info.attach("synthetic-session-cleanup", { body: JSON.stringify(evidence), contentType: "application/json" });
});

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`real PUBLIC API: retained scenarios → profile → current results (${viewport.name})`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    const errors: string[] = [], posts: string[] = [], profileIds: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => { if (request.method() === "POST") posts.push(new URL(request.url()).pathname); });
    page.on("response", async response => {
      if (new URL(response.url()).pathname === "/v1/preference-profiles" && response.status() === 201) profileIds.push((await response.json()).profile_id);
    });
    await page.goto("/");
    await expect(page.getByRole("link", { name: "시작하기", exact: true })).toHaveAttribute("href", "/start");
    await page.getByRole("link", { name: "시작하기", exact: true }).click();
    await expect(page).toHaveURL(/\/start$/);
    await expect(page.getByRole("heading", { name: JOURNEY_COPY.start.title })).toBeVisible();
    const region = page.getByRole("combobox", { name: "어디로 떠날까요?" });
    await expect(region.locator('option[value="11"]')).toHaveCount(1);
    await region.selectOption("11");
    for (const choices of Object.values(TRIP_CHOICES)) await page.getByRole("radio", { name: choices[0]!.label, exact: true }).check();
    await page.screenshot({ path: info.outputPath("start.png"), fullPage: true });
    await page.getByRole("button", { name: JOURNEY_COPY.start.primaryLabel, exact: true }).click();
    await expect(page).toHaveURL(/\/quiz$/);
    const answers: Record<string, number> = {};
    for (const question of FRONTEND_QUESTIONNAIRE.questions) {
      await expect(page.getByRole("heading", { name: question.title_ko, exact: true })).toBeVisible();
      await expect(page.getByRole("radio")).toHaveCount(3);
      const options = [...question.options].sort((a, b) => contract.scoring_matrix[b.choice_id as keyof typeof contract.scoring_matrix].REST_IMMERSION - contract.scoring_matrix[a.choice_id as keyof typeof contract.scoring_matrix].REST_IMMERSION);
      answers[question.question_id] = options[0]!.value;
      if (question.ordinal === 1) await page.screenshot({ path: info.outputPath("quiz.png"), fullPage: true });
      await page.getByRole("radio", { name: options[0]!.text_ko, exact: true }).click();
    }
    await expect(page).toHaveURL(/\/profile$/);
    await expect(page.getByRole("meter")).toHaveCount(3);
    await expect(page.getByRole("heading", { name: "당신이 기대하는 여행의 시간" })).toBeVisible();
    expect(posts.filter(path => path === "/v1/authenticity/runs")).toHaveLength(0);
    await page.reload();
    const recommend = page.getByRole("button", { name: "바로 추천 보기", exact: true });
    await expect(recommend).toBeEnabled();
    await page.screenshot({ path: info.outputPath("profile.png"), fullPage: true });
    const bridge = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/v1/authenticity/scenario-profiles");
    await recommend.click();
    const body = (await bridge).postDataJSON();
    expect(body.answers).toEqual(answers);
    expect(body.requirements).toEqual({ region_code: "11", required_facilities: [] });
    expect(body.photo_receipt_sha256).toBeNull();
    expect(body.trip_conditions.companion).toBe(TRIP_CHOICES.companion[0]!.value);
    await expect(page).toHaveURL(/\/recommendations\/a-[a-f0-9]{64}$/);
    const resultUrl = page.url();
    const cards = page.locator("[data-scenario-place]");
    await expect(cards).toHaveCount(5);
    await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
    for (const card of await cards.all()) await expect(card).toContainText("서울특별시");
    const photoCard = cards.filter({ has: page.locator("figure img") }).first();
    await expect(photoCard).toBeVisible();
    const realPhoto = photoCard.locator("figure img").first();
    await realPhoto.scrollIntoViewIfNeeded();
    await expect.poll(() => realPhoto.evaluate(node => (node as HTMLImageElement).complete && (node as HTMLImageElement).naturalWidth > 0)).toBe(true);
    if (await photoCard.getByRole("button", { name: /사진 2 보기$/ }).count()) await photoCard.getByRole("button", { name: /사진 2 보기$/ }).click();
    await page.getByText("내 답변과 추천의 연결 방식", { exact: true }).click();
    await expect(page.getByText(/변환 규칙: scenario-expectation-bridge.v1/)).toBeVisible();
    await page.screenshot({ path: info.outputPath("results.png"), fullPage: true });
    for (const card of await cards.all()) expect(await card.evaluate(node => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
    const first = cards.first();
    await first.getByRole("button", { name: / 저장$/ }).click();
    await expect(first.getByRole("button", { name: / 저장됨$/ })).toHaveAttribute("aria-pressed", "true");
    for (const card of [cards.nth(0), cards.nth(1)]) await card.getByRole("button", { name: / 비교에 추가$/ }).click();
    await page.getByRole("link", { name: "선택한 장소 비교하기" }).click();
    await expect(page).toHaveURL(/\/recommendations\/a-[a-f0-9]{64}\/compare\?/);
    await expect(page.getByRole("table")).toBeVisible();
    await page.screenshot({ path: info.outputPath("compare.png"), fullPage: true });
    await page.getByRole("link", { name: "추천 목록으로", exact: true }).click();
    await expect(cards).toHaveCount(5);
    await cards.first().getByRole("link", { name: / 상세 보기$/ }).click();
    await expect(page.getByRole("heading", { name: "이 점수의 근거" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "장소 소개" })).toBeVisible();
    await page.screenshot({ path: info.outputPath("detail.png"), fullPage: true });
    await page.goto(resultUrl); await expect(cards).toHaveCount(5);
    await expect(cards.first().getByRole("button", { name: / 저장됨$/ })).toHaveAttribute("aria-pressed", "true");
    await page.getByRole("link", { name: "저장한 장소", exact: true }).click();
    await expect(page).toHaveURL(/\/saved$/);
    await page.reload();
    await expect(page.locator('a[href*="/recommendations/a-"]')).toHaveCount(1);
    await page.goto("/photo");
    await expect(page.getByRole("button", { name: "사진 없이 추천 보기", exact: true })).toBeEnabled();
    await expect(page.getByText(/현재 사진 분석을 사용할 수 없어요/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    expect(posts).not.toContain("/v1/recommendation-runs"); expect(errors).toEqual([]);
    await info.attach("synthetic-legacy-profile-ids", { body: JSON.stringify(profileIds), contentType: "application/json" });
  });
}
