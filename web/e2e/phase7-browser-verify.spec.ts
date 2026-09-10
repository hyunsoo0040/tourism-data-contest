import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";
import { expect, type Page, test } from "@playwright/test";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(import.meta.url), "../../..");

async function guardLoopbackTraffic(page: Page) {
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
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(() => ({
    body: document.body.scrollWidth - document.body.clientWidth,
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect(overflow.body).toBeLessThanOrEqual(1);
  expect(overflow.document).toBeLessThanOrEqual(1);
}

async function enterQuiz(page: Page) {
  await page.goto("/start");
  await expect(
    page.getByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" }),
  ).toBeVisible();
  await page.getByLabel("방문 날짜 (선택)").fill("2026-10-09");
  for (const label of [
    "해질녘",
    "친구·연인",
    "도보·대중교통",
    "1시간 안팎",
    "상관없어요",
    "조금 피하고 싶어요",
  ]) {
    await page.getByRole("radio", { name: label, exact: true }).check();
  }
  const questionnaireResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "GET" &&
      response.url().endsWith("/v1/questionnaires/current"),
  );
  await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
  await questionnaireResponse;
  await expect(page).toHaveURL(/\/quiz$/);
  await expect(page.getByText("1 / 12", { exact: true })).toBeVisible();
}

async function createV2Profile(page: Page) {
  await enterQuiz(page);

  const profileResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/preference-profiles"),
  );
  for (let ordinal = 1; ordinal <= 12; ordinal += 1) {
    await expect(page).toHaveURL(/\/quiz$/);
    await expect(page.getByText(`${ordinal} / 12`, { exact: true })).toBeVisible();
    const question = questionnaire.questions.find((candidate) => candidate.ordinal === ordinal)!;
    await expect(page.getByText(question.title_ko)).toBeVisible();
    await page.getByRole("radio").nth(2).click();
  }
  await profileResponse;
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("heading", { name: "당신이 기대하는 여행의 시간" })).toBeVisible();
}

test.describe("07-02 upstream main page", () => {
  test("self-hosts the upstream fonts and rotates the preview every three seconds", async ({ page }) => {
    test.setTimeout(30_000);
    const externalRequests: string[] = [];
    const fontResponses: string[] = [];
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (
        (url.protocol === "http:" || url.protocol === "https:") &&
        !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      ) {
        externalRequests.push(url.href);
      }
    });
    page.on("response", (response) => {
      if (response.url().includes("/fonts/")) fontResponses.push(response.url());
    });

    await page.goto("/");
    await page.evaluate(async () => {
      await document.fonts.load('400 20px "Noto Sans KR"', "경주 여행");
      await document.fonts.load('700 20px "Inter"', "IT-DA 84%");
      await document.fonts.ready;
    });
    expect(
      await page.evaluate(() => ({
        noto: document.fonts.check('400 20px "Noto Sans KR"', "경주 여행"),
        inter: document.fonts.check('700 20px "Inter"', "IT-DA 84%"),
        family: getComputedStyle(document.querySelector(".up-main")!).fontFamily,
        heroWeight: getComputedStyle(document.querySelector(".hero h1")!).fontWeight,
      })),
    ).toEqual({
      noto: true,
      inter: true,
      family: '"Noto Sans KR", Inter, system-ui, sans-serif',
      heroWeight: "700",
    });
    expect(fontResponses.some((url) => url.endsWith("/fonts/NotoSansKR-wght.ttf"))).toBe(true);
    expect(fontResponses.some((url) => url.endsWith("/fonts/Inter-opsz-wght.ttf"))).toBe(true);
    expect(externalRequests).toEqual([]);

    await expect(page.locator(".hero-title-line")).toHaveCount(2);
    await expect(page.locator(".phone .type-card")).toHaveCount(3);
    await expect(page.locator(".phone .type-icon")).toHaveText(["古", "景", "休"]);
    await expect(page.locator(".phone .type-card strong")).toHaveText([
      "역사·전통형",
      "감성·이미지형",
      "휴식·몰입형",
    ]);
    await expect(page.locator(".phone .type-card span")).toHaveText([
      "문화, 유적, 자연 보존",
      "SNS, 분위기, 포토 스팟",
      "산책, 조용함, 감정적 만족",
    ]);
    await expect(page.locator("#matchScore")).toHaveCount(0);

    await expect(page.locator("#phoneType")).toContainText("휴식·몰입형 여행자");
    await expect(page.locator("#resultTitle")).toHaveText("휴식·몰입형 추천 결과");
    await expect(page.locator("#phoneType")).toContainText("감성·이미지형 여행자", {
      timeout: 4_000,
    });
    await expect(page.locator("#phoneMatch")).toHaveText("86% match");
    await expect(page.locator("#resultTitle")).toHaveText("감성·이미지형 추천 결과");
    await expect(page.locator("#phoneType")).toContainText("역사·전통형 여행자", {
      timeout: 4_000,
    });
    await expect(page.locator("#phoneMatch")).toHaveText("89% match");
    await expect(page.locator("#resultTitle")).toHaveText("역사·전통형 추천 결과");
  });

  for (const viewport of [
    { name: "mobile-375", width: 375, height: 812 },
    { name: "mobile-390", width: 390, height: 844 },
    { name: "laptop-1366", width: 1366, height: 768 },
    { name: "laptop-1440", width: 1440, height: 900 },
    { name: "desktop-1920", width: 1920, height: 1080 },
  ]) {
    test(`renders the exact upstream main port at ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await guardLoopbackTraffic(page);
      await page.goto("/");
      await expect(page.locator(".up-main")).toBeVisible();
      await expect(page).toHaveTitle(/IT-DA/);
      await expect(page.getByRole("heading", { name: /내가 기대한 여행과/ })).toBeVisible();
      await expect(page.getByText("관광데이터 기반 개인 맞춤 여행 큐레이션")).toBeVisible();
      await page.locator('#demo .choice[data-type="history"]').click();
      await expect(page.locator("#resultTitle")).toHaveText("역사·전통형 추천 결과");
      await expect(page.locator("#recommendations h4")).toHaveText(["불국사", "경주 양동마을"]);
      await page.locator('#demo .choice[data-type="rest"]').click();
      await expect(page.locator("#resultTitle")).toHaveText("휴식·몰입형 추천 결과");
      await expect(page.locator("#recommendations h4")).toHaveText(["보문호반길", "동궁과 월지"]);
      await page.locator('#demo .choice[data-type="image"]').click();
      await expect(page.locator("#resultTitle")).toHaveText("감성·이미지형 추천 결과");
      await expect(page.locator("#recommendations h4")).toHaveText(["황리단길", "대릉원 일원"]);
      await expect(page.getByRole("link", { name: "여행 취향 찾기" })).toBeVisible();
      await expect(page.getByRole("link", { name: "12문항 취향 테스트로 자세히 보기" })).toBeVisible();
      await expect(
        page.getByRole("link", { name: /취향 테스트 후 사진 분위기 더하기/ }),
      ).toHaveAttribute("href", "/start");
      await expectNoHorizontalOverflow(page);
    });
  }
});

test.describe("07-02 conditions → quiz → profile journey", () => {
  test("travel conditions precede the quiz and the 12 scenarios come from the served contract", async ({
    page,
  }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width: 390, height: 844 });
    await guardLoopbackTraffic(page);
    await createV2Profile(page);
  });

  for (const viewport of [
    { name: "mobile-375", width: 375, height: 812 },
    { name: "mobile-390", width: 390, height: 844 },
    { name: "laptop-1366", width: 1366, height: 768 },
    { name: "laptop-1440", width: 1440, height: 900 },
    { name: "desktop-1920", width: 1920, height: 1080 },
  ]) {
    test(`keeps quiz panels aligned at ${viewport.name}`, async ({ page }) => {
      test.setTimeout(120_000);
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await guardLoopbackTraffic(page);
      await enterQuiz(page);

      const status = page.getByRole("complementary", { name: "질문 진행 상황" });
      const question = page.locator(".up-quiz .question");
      await expect(status).toBeVisible();
      await expect(question).toBeVisible();

      const boxes = await page.locator(".up-quiz .status, .up-quiz .question").evaluateAll(
        (elements) => elements.map((element) => element.getBoundingClientRect().toJSON()),
      );
      expect(boxes).toHaveLength(2);
      const [statusBox, questionBox] = boxes;
      if (viewport.width > 900) {
        expect(questionBox.x).toBeGreaterThan(statusBox.x + statusBox.width);
        expect(questionBox.y).toBeCloseTo(statusBox.y, 0);
        expect(questionBox.width).toBeGreaterThan(700);
      } else {
        expect(questionBox.x).toBeCloseTo(statusBox.x, 0);
        expect(questionBox.y).toBeGreaterThan(statusBox.y + statusBox.height);
        expect(questionBox.width).toBeCloseTo(statusBox.width, 0);
      }
      await expectNoHorizontalOverflow(page);
    });
  }
});

test.describe("07-02 no-photo recommendation journey", () => {
  test("profile recommendation reaches Top 5, detail, save, and compare", async ({ page }) => {
    test.setTimeout(240_000);
    await page.setViewportSize({ width: 1280, height: 800 });
    await guardLoopbackTraffic(page);
    await createV2Profile(page);

    const resultsResponse = page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().includes("/v1/recommendation-runs"),
      { timeout: 180_000 },
    );
    await page.getByRole("button", { name: "바로 추천 보기", exact: true }).click();
    await resultsResponse;

    await page.waitForURL(/\/recommendations\//, { timeout: 180_000 });
    await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeVisible({
      timeout: 30_000,
    });
    const headerCenters = await page
      .locator('.up-etc[data-upstream-surface="recommendations"] .topbar, .up-etc[data-upstream-surface="recommendations"] .topbar nav a')
      .evaluateAll((elements) =>
        elements.map((element) => {
          const box = element.getBoundingClientRect();
          return box.y + box.height / 2;
        }),
      );
    expect(headerCenters).toHaveLength(4);
    for (const linkCenter of headerCenters.slice(1)) {
      expect(Math.abs(linkCenter - headerCenters[0]!)).toBeLessThanOrEqual(1);
    }
    const cards = page.locator("[data-recommendation-card]");
    await expect(cards).toHaveCount(5, { timeout: 30_000 });

    const firstCard = cards.first();
    await firstCard.getByRole("button", { name: / 저장$/ }).click();
    await expect(firstCard.getByRole("button", { name: / 저장됨$/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    await firstCard.getByRole("link", { name: /상세 보기/ }).click();
    await page.waitForURL(/\/places\//);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

    await page.goBack();
    await page.waitForURL(/\/recommendations\/[^/]+$/);
    await page.reload();
    await expect(page.getByRole("heading", { name: "저장한 장소" })).toBeVisible();
    await page.getByRole("button", { name: /비교에 추가/ }).first().click();
    await page.getByRole("button", { name: /비교에 추가/ }).nth(1).click();
    await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
    await page.waitForURL(/\/compare$/, { timeout: 60_000 });
    await expect(page.getByRole("region", { name: "장소 비교표" })).toBeVisible();
  });
});

test.describe("07-02 internal route smoke", () => {
  test("internal access and protected consoles render their retained UI", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await guardLoopbackTraffic(page);
    await page.goto("/internal/access");
    await expect(page.getByText("내부 작업 접근 확인")).toBeVisible();
    await expect(page.getByText("IT-DA · 내부 역할 세션")).toBeVisible();

    await page.goto("/internal/profile-releases/builder");
    await expect(page.getByText("DEV profile release 후보 준비")).toBeVisible({ timeout: 20_000 });

    await page.goto("/internal/profile-releases/approver");
    await expect(page.getByText("내부 작업 접근 확인").or(page.getByText("DEV profile release 후보"))).toBeVisible();

    await page.goto("/internal/profile-releases/activator");
    await expect(
      page.getByText("내부 작업 접근 확인").or(page.getByText("DEV profile release 후보")),
    ).toBeVisible();
  });
});
