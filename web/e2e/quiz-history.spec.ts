import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";
import { expect, type Locator, type Page, test } from "@playwright/test";

const DRAFT_KEY = "itda.phase2.draft.v2";

async function guardLoopback(page: Page) {
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
      await route.abort();
      if (!["fonts.googleapis.com", "fonts.gstatic.com"].includes(url.hostname)) {
        throw new Error(`외부 브라우저 요청 차단: ${url.origin}`);
      }
      return;
    }
    await route.continue();
  });
}

async function expectQuestion(page: Page, ordinal: number, editingProfile = false) {
  await expect(page).toHaveURL(/\/quiz$/);
  await expect(page.getByText(`${ordinal} / 12`, { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: questionnaire.questions[ordinal - 1]!.title_ko, exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.history.state?.usr)).toEqual(
    editingProfile ? { questionOrdinal: ordinal, editingProfile: true } : { questionOrdinal: ordinal },
  );
  await expect.poll(() => page.evaluate((key) => JSON.parse(localStorage.getItem(key)!).current_question, DRAFT_KEY)).toBe(ordinal);
}

for (const mobile of [false, true]) {
  test.describe(mobile ? "mobile-chromium" : "desktop-chromium", () => {
    test.use({
      viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 },
      isMobile: mobile,
      hasTouch: mobile,
      timezoneId: "Asia/Seoul",
    });
    const press = (locator: Locator) => mobile ? locator.tap() : locator.click();

    async function enterQuiz(page: Page) {
      await guardLoopback(page);
      await page.goto("/start");
      for (const name of ["아직 미정", "혼자", "도보·대중교통", "30분 이내로 가볍게", "상관없어요", "조금 피하고 싶어요"]) {
        await press(page.getByRole("radio", { name, exact: true }));
      }
      await press(page.getByRole("button", { name: "취향 테스트 시작하기" }));
      await expectQuestion(page, 1);
    }

    test("동일 주소에서 Back/Forward·새로고침·이전 링크·처음부터를 보존한다", async ({ page }, testInfo) => {
      await enterQuiz(page);
      for (let ordinal = 1; ordinal <= 2; ordinal += 1) {
        await press(page.getByRole("radio").nth(2));
        await expectQuestion(page, ordinal + 1);
      }
      await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "2");
      await page.goBack();
      await expectQuestion(page, 2);
      await expect(page.getByRole("radio").nth(2)).toBeChecked();
      await page.goForward();
      await expectQuestion(page, 3);
      await page.goBack();
      await expectQuestion(page, 2);
      await page.reload();
      await expectQuestion(page, 2);
      await expect(page.getByRole("radio").nth(2)).toBeChecked();
      await page.screenshot({ path: testInfo.outputPath("quiz-restored.png") });

      await page.evaluate(() => window.history.replaceState({ ...window.history.state, usr: null }, "", "/quiz"));
      await page.reload();
      await expectQuestion(page, 2);
      await page.goto("/quiz?q=1#legacy");
      await expectQuestion(page, 1);
      await page.goBack();
      await expectQuestion(page, 2);
      await page.goForward();
      await expectQuestion(page, 1);
      await press(page.getByRole("button", { name: "이전", exact: true }));
      await expect(page).toHaveURL(/\/start$/);
      await page.goBack();
      await expectQuestion(page, 1);
      await press(page.getByRole("button", { name: "처음부터", exact: true }));
      await expectQuestion(page, 1);
      await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "0");
      expect(await page.evaluate((key) => JSON.parse(localStorage.getItem(key)!).answers, DRAFT_KEY)).toEqual({});
      await page.goto("/quiz?q=12");
      await expectQuestion(page, 1);
    });

    test("프로필 특정 답변 편집은 refresh와 제출까지 쿼리 없이 유지된다", async ({ page }, testInfo) => {
      test.setTimeout(60_000);
      await enterQuiz(page);
      for (let ordinal = 1; ordinal <= 12; ordinal += 1) {
        await expectQuestion(page, ordinal);
        await press(page.getByRole("radio").first());
      }
      await expect(page).toHaveURL(/\/profile$/);
      await press(page.getByText("입력한 내용", { exact: true }));
      await press(page.getByRole("button", { name: "시나리오 7 답변 수정", exact: true }));
      await expectQuestion(page, 7, true);
      await page.reload();
      await expectQuestion(page, 7, true);
      await expect(page.getByRole("radio").first()).toBeChecked();
      await press(page.getByRole("button", { name: "이전", exact: true }));
      await expectQuestion(page, 6, true);
      await page.goBack();
      await expectQuestion(page, 7, true);
      await page.screenshot({ path: testInfo.outputPath("quiz-edit-restored.png") });
      const response = page.waitForResponse((result) => result.request().method() === "POST" && result.url().endsWith("/v1/preference-profiles"));
      for (let ordinal = 7; ordinal <= 12; ordinal += 1) {
        await expectQuestion(page, ordinal, true);
        await press(page.getByRole("radio").nth(ordinal === 7 ? 2 : 0));
      }
      const profile = await response;
      expect(profile.status()).toBe(201);
      expect(profile.request().postDataJSON().answers.q7).toBe(3);
      await expect(page).toHaveURL(/\/profile$/);
      await expect(page.getByRole("status").filter({ hasText: "수정한 답변으로 기대 프로필을 다시 만들었어요." })).toBeAttached();
    });
  });
}
