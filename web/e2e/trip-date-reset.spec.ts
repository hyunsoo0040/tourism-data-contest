import { expect, type Locator, type Page, test as base } from "@playwright/test";

const test = base.extend<{ engine: "chromium" | "webkit" }>({
  engine: ["chromium", { option: true }],
  context: async ({ playwright, engine, baseURL, viewport, isMobile, hasTouch, timezoneId }, use) => {
    const browser = await playwright[engine].launch();
    try {
      const context = await browser.newContext({ baseURL, viewport, isMobile, hasTouch, timezoneId });
      await use(context);
      await context.close();
    } finally {
      await browser.close();
    }
  },
});

const DRAFT_KEY = "itda.phase2.draft.v2";
const RESET_MESSAGE = "저장된 여행 내용을 지웠어요.";
const TODAY = "2026-09-09";
const YESTERDAY = "2026-09-08";

async function prepare(page: Page) {
  await page.clock.install({ time: new Date("2026-09-08T15:30:00Z") });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
      await route.abort();
      if (!['fonts.googleapis.com', 'fonts.gstatic.com'].includes(url.hostname)) {
        throw new Error(`외부 브라우저 요청 차단: ${url.origin}`);
      }
      return;
    }
    await route.continue();
  });
}

async function chooseRequired(page: Page) {
  for (const name of ["아직 미정", "혼자", "도보·대중교통", "30분 이내로 가볍게", "상관없어요", "조금 피하고 싶어요"]) {
    await page.getByRole("radio", { name, exact: true }).check();
  }
}

for (const environment of [
  { name: "desktop-chromium", browserName: "chromium", mobile: false },
  { name: "mobile-chromium", browserName: "chromium", mobile: true },
  { name: "mobile-webkit", browserName: "webkit", mobile: true },
] as const) {
  test.describe(environment.name, () => {
    test.use({
      engine: environment.browserName,
      viewport: environment.mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 },
      isMobile: environment.mobile,
      hasTouch: environment.mobile,
      timezoneId: "Asia/Seoul",
    });

    const press = (locator: Locator) => environment.mobile ? locator.tap() : locator.click();

    for (const entry of ["start", "profile"] as const) {
      test(`${entry} 초기화 확인과 성공 알림 자동 닫힘`, async ({ page }, testInfo) => {
        test.setTimeout(90_000);
        await prepare(page);
        await page.goto("/start");
        if (entry === "start") {
          await page.evaluate((key) => {
            localStorage.setItem(key, JSON.stringify({
              schema_version: "phase1-draft-v1",
              questionnaire_version: "questionnaire-v2",
              updated_at: new Date().toISOString(),
              current_route: "/start",
              current_question: 1,
              trip_conditions: { companion: "SOLO" },
              answers: {},
            }));
          }, DRAFT_KEY);
          await page.reload();
        } else {
          await chooseRequired(page);
          await press(page.getByRole("button", { name: "취향 테스트 시작하기" }));
          for (let question = 1; question <= 12; question += 1) {
            await expect(page).toHaveURL(/\/quiz$/);
            await expect(page.getByText(`${question} / 12`, { exact: true })).toBeVisible();
            await press(page.getByRole("radio").first());
          }
          await expect(page).toHaveURL(/\/profile$/);
        }

        const trigger = page.getByRole("button", { name: entry === "start" ? "처음부터 시작하기" : "처음부터 다시", exact: true });
        const dialog = page.getByRole("dialog", { name: "작성한 내용을 지울까요?" });
        const original = await page.evaluate((key) => localStorage.getItem(key), DRAFT_KEY);
        await press(trigger);
        await expect(dialog).toBeVisible();
        await press(dialog.getByRole("heading"));
        await expect(dialog).toBeVisible();
        await press(dialog.getByRole("button", { name: "계속 작성하기" }));
        await expect(dialog).toHaveCount(0);
        expect(await page.evaluate((key) => localStorage.getItem(key), DRAFT_KEY)).toBe(original);
        await press(trigger);
        if (environment.mobile) await page.touchscreen.tap(4, 4);
        else await page.mouse.click(4, 4);
        await expect(dialog).toHaveCount(0);
        expect(await page.evaluate((key) => localStorage.getItem(key), DRAFT_KEY)).toBe(original);

        await press(trigger);
        await press(dialog.getByRole("button", { name: "모두 지우고 새로 시작하기" }));
        await expect(dialog).toHaveCount(0);
        await expect(page).toHaveURL(/\/start$/);
        const notice = page.locator(".public-shell-notice").filter({ hasText: RESET_MESSAGE });
        await expect(notice).toBeVisible();
        await page.screenshot({ path: testInfo.outputPath("reset-notice-visible.png") });
        await expect(notice).toHaveCount(0, { timeout: 6_000 });
        await expect(page.locator(".dialog-backdrop")).toHaveCount(0);
        expect(await page.evaluate((key) => localStorage.getItem(key), DRAFT_KEY)).toBeNull();
        await expect(page.getByLabel("방문 날짜 (선택)")).toHaveValue(TODAY);
        await page.screenshot({ path: testInfo.outputPath("reset-notice-dismissed-portrait.png") });
        await press(page.getByRole("radio", { name: "혼자", exact: true }));
        await expect(page.getByRole("radio", { name: "혼자", exact: true })).toBeChecked();
        for (const viewport of [{ width: 320, height: 568 }, { width: 844, height: 390 }]) {
          await page.setViewportSize(viewport);
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        }
        await page.screenshot({ path: testInfo.outputPath("reset-notice-dismissed.png") });
      });
    }

    test("현지 오늘 기본값과 과거 날짜 제출 차단", async ({ page }, testInfo) => {
      await prepare(page);
      await page.goto("/start");
      const date = page.getByLabel("방문 날짜 (선택)");
      await expect(date).toHaveValue(TODAY);
      await expect(date).toHaveAttribute("min", TODAY);
      await chooseRequired(page);
      await date.fill(YESTERDAY);
      await press(page.getByRole("button", { name: "취향 테스트 시작하기" }));
      await expect(page.getByRole("alert").getByRole("link", { name: "오늘 또는 이후 날짜를 선택해 주세요." })).toBeVisible();
      await expect(page).toHaveURL(/\/start$/);
      expect(await page.evaluate((key) => localStorage.getItem(key), DRAFT_KEY)).toBeNull();
      await page.screenshot({ path: testInfo.outputPath("past-date-error.png") });
      await date.fill(TODAY);
      await press(page.getByRole("button", { name: "취향 테스트 시작하기" }));
      await expect(page).toHaveURL(/\/quiz$/);
      await expect(page.getByText("1 / 12", { exact: true })).toBeVisible();
    });
  });
}
