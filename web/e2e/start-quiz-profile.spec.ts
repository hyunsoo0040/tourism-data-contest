import { FRONTEND_QUESTIONNAIRE as QUESTIONNAIRE } from "../src/content/questionnaire";
import { expect, type Page, type Response, test } from "@playwright/test";

const CANONICAL_TITLES = QUESTIONNAIRE.questions.map(({ title_ko }) => title_ko);
const CANONICAL_Q1 = CANONICAL_TITLES[0];

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

async function fillTripContext(page: Page) {
  const today = await page.evaluate(() => {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  });
  await page.getByLabel("방문 날짜 (선택)").fill(today);
  for (const label of [
    "해질녘",
    "친구",
    "도보·대중교통",
    "1시간 안팎",
    "상관없어요",
    "조금 피하고 싶어요",
  ]) {
    await page.getByRole("radio", { name: label, exact: true }).check();
  }
}

function waitForQuestionnaire(page: Page) {
  return page.waitForResponse(
    (response) =>
      response.request().method() === "GET" &&
      response.url().endsWith("/v1/questionnaires/current"),
  );
}

function waitForProfile(page: Page) {
  return page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/preference-profiles"),
  );
}

async function assertProfileEcho(response: Response) {
  expect(response.status()).toBe(201);
  expect(response.headers()["content-type"]).toContain("application/json");
  const request = response.request().postDataJSON();
  const profile = await response.json();
  expect(profile.request_id).toBe(request.request_id);
  expect(profile.answers).toEqual(request.answers);
  expect(profile.trip_conditions).toEqual(request.trip_conditions);
  return { profile, request };
}

async function answerFreshQuiz(page: Page) {
  let profileResponse: Promise<Response> | null = null;
  for (const [index] of QUESTIONNAIRE.questions.entries()) {
    await expect(page).toHaveURL(/\/quiz$/);
    await expect(page.getByText(`${index + 1} / 12`, { exact: true })).toBeVisible();
    await expect(page.getByText(CANONICAL_TITLES[index], { exact: true })).toBeVisible();
    if (index === QUESTIONNAIRE.questions.length - 1) {
      profileResponse = waitForProfile(page);
    }
    await page
      .getByRole("radio", { name: QUESTIONNAIRE.questions[index]!.options[0]!.text_ko, exact: true })
      .click();
  }

  if (profileResponse === null) throw new Error("profile submission was not observed");
  return assertProfileEcho(await profileResponse);
}

async function submitEditedAnswers(page: Page) {
  let profileResponse: Promise<Response> | null = null;
  for (const [index] of QUESTIONNAIRE.questions.entries()) {
    await expect(page).toHaveURL(/\/quiz$/);
    await expect(page.getByText(`${index + 1} / 12`, { exact: true })).toBeVisible();
    await expect(page.getByText(CANONICAL_TITLES[index], { exact: true })).toBeVisible();
    const option = QUESTIONNAIRE.questions[index]!.options[index === 0 ? 2 : 0]!;
    const radio = page.getByRole("radio", { name: option.text_ko, exact: true });
    if (index > 0) {
      await expect(radio).toBeChecked();
    }
    if (index === QUESTIONNAIRE.questions.length - 1) {
      profileResponse = waitForProfile(page);
    }
    await radio.click();
  }

  if (profileResponse === null) throw new Error("profile submission was not observed");
  return assertProfileEcho(await profileResponse);
}

async function expectInitialProfile(page: Page) {
  await expect(page).toHaveURL(/\/profile$/);
  await expect(
    page.getByRole("meter", { name: "역사·전통 29점 / 100점" }),
  ).toBeVisible();
  await expect(
    page.getByRole("meter", { name: "감성·이미지 36점 / 100점" }),
  ).toBeVisible();
  await expect(
    page.getByRole("meter", { name: "휴식·몰입 36점 / 100점" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "당신이 기대하는 여행의 시간" })).toBeVisible();
  await expect(
    page.getByText(
      "이번 여행에서는 감성·이미지와 휴식·몰입 경험을 더 기대하고 있어요.",
      { exact: true },
    ),
  ).toBeVisible();

  await expect(page.getByText("대표 유형 점수", { exact: true })).toHaveCount(0);
  await expect(page.locator(".type-badge b")).toHaveText("구성적 진정성");
  await expect(page.locator(".match-card > b")).toHaveCount(0);
  await expect(page.locator(".character-card b")).toHaveText("무드 위버");
  await page.getByText("프로필 계산 정보", { exact: true }).click();
  for (const version of [
    "preference-profile-v2",
    "questionnaire-v2",
    "choice-distribution-v3",
    "current-trip-expectation-v1",
    "de3b691fee11…6d2f",
  ]) {
    await expect(page.getByText(version, { exact: true })).toBeVisible();
  }
}

test("fresh loopback topology completes the canonical journey and both edits", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  await page.goto("/start");
  await expect(
    page.getByRole("heading", {
      name: "이번 여행, 어떤 시간을 보내고 싶나요?",
    }),
  ).toBeVisible();
  await fillTripContext(page);

  await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
  await expect(page.getByText(CANONICAL_Q1, { exact: true })).toBeVisible();

  // The backend contract is checked at submission; visible questions are local.
  const questionnaireResponse = waitForQuestionnaire(page);
  const initial = await answerFreshQuiz(page);
  const questionnaire = await questionnaireResponse;
  expect(questionnaire.status()).toBe(200);
  expect((await questionnaire.json()).config_hash).toBe(QUESTIONNAIRE.config_hash);
  expect(initial.request.answers.q1).toBe(1);
  expect(initial.request.trip_conditions.crowd_avoidance).toBe("MEDIUM");
  await expectInitialProfile(page);

  await page.getByRole("button", { name: "답변 수정하기" }).click();
  await expect(page).toHaveURL(/\/quiz$/);
  await expect(page.getByText("1 / 12", { exact: true })).toBeVisible();
  const answerEdit = await submitEditedAnswers(page);
  expect(answerEdit.request.request_id).not.toBe(initial.request.request_id);
  expect(answerEdit.request.answers.q1).toBe(3);
  await expect(
    page.getByRole("meter", { name: "역사·전통 36점 / 100점" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "이번 여행에서는 감성·이미지와 역사·전통 경험을 더 기대하고 있어요.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("status").filter({
      hasText: "수정한 답변으로 기대 프로필을 다시 만들었어요.",
    }),
  ).toBeAttached();

  await page.getByRole("button", { name: "여행 조건 수정하기" }).first().click();
  await expect(page).toHaveURL(/\/start\?mode=edit$/);
  await page
    .getByRole("radio", { name: "많이 피하고 싶어요", exact: true })
    .check();
  const tripEditResponse = waitForProfile(page);
  await page.getByRole("button", { name: "수정 내용 반영하기" }).click();
  const tripEdit = await assertProfileEcho(await tripEditResponse);
  expect(tripEdit.request.request_id).not.toBe(answerEdit.request.request_id);
  expect(tripEdit.request.trip_conditions.crowd_avoidance).toBe("HIGH");
  expect(tripEdit.profile.trip_conditions.crowd_avoidance).toBe("HIGH");
  await expect(page).toHaveURL(/\/profile$/);
  await expect(
    page.getByRole("meter", { name: "역사·전통 36점 / 100점" }),
  ).toBeVisible();
});
