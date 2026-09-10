import { FRONTEND_QUESTIONNAIRE as QUESTIONNAIRE } from "../src/content/questionnaire";
import { expect, type Page, type Response, type Route, test } from "@playwright/test";

/**
 * Controlled-RED Phase 6 Chromium contract (Wave 0).
 *
 * Freezes the optional-photo preference and privacy journey BEFORE any
 * production route or component exists. Synthetic `/v1/photo-jobs*`
 * interception only; the non-loopback guard keeps every request on loopback.
 * Execution stays RED because the photo routes/selectors are absent — never
 * because of live providers, credentials, or fixtures.
 *
 * Named held-out cases (IDs must remain unchanged through the browser gate):
 *   UI-BS-01 long copy reflows at minimum viewport and 200 percent zoom
 *   UI-BS-02 Korean trait boundary preserves row controls
 *   UI-BS-03 sticky safe area leaves terminal controls reachable
 *   UI-BS-05 reload preserves provenance and confirmed-only projection
 *   UI-BS-06 keyboard and accessibility journeys cover every optional-photo state
 * (UI-BS-04 is component-owned and must already be green; it is not duplicated here.)
 */

const PROFILE_RECOMMENDATION_CTA = "바로 추천 보기";
const PHOTO_RECOMMENDATION_CTA = "사진 취향을 반영해 추천 보기";
const NO_PHOTO_CTA = "사진 없이 추천 5곳 보기";
const PHOTO_PATH_CTA = "사진으로 취향 더하기";
const CONSENT_CHECKBOX =
  "위 내용을 읽었고, 이 사진들을 이번 여행 취향 분석에 사용하는 데 동의해요.";
const CONSENT_CTA = "동의하고 사진 고르기";
const CONSENT_ERROR =
  "사진 사용 내용을 확인하고 동의해 주세요. 동의하지 않아도 사진 없이 추천을 볼 수 있어요.";
const PICKER_TRIGGER = "사진 고르기";
const CONSENT_HEADING = "사진 사용 내용을 먼저 확인해 주세요";
const PICKER_HEADING = "분석할 사진을 골라 주세요";
const REVIEW_HEADING = "추천에 반영할 취향을 확인해 주세요";
const REVIEW_CONFIRM_CTA = "확정한 취향으로 추천 5곳 보기";
const QUEUED_HEADING = "사진 분석을 준비하고 있어요.";
const RUNNING_HEADING = "사진에서 여행 취향 후보를 찾고 있어요.";
const FAILED_HEADING = "사진 분석을 마치지 못했어요.";
const EXPIRED_COPY = "사진 작업 시간이 지나 분석을 이어갈 수 없어요.";
const TIMEOUT_COPY =
  "기다리는 시간이 길어 사진 분석을 중단했어요. 사진 없이 추천을 바로 계속할 수 있어요.";
const DELETE_TRIGGER = "사진 사용 중단하고 삭제하기";
const DELETE_DIALOG_HEADING = "사진 사용을 중단할까요?";
const DELETE_SAFE = "계속 사진 사용하기";
const DELETE_DESTRUCTIVE = "사진 삭제 요청하기";
const ZERO_TAG_HEADING = "반영할 사진 취향을 남기지 않았어요.";
const MALFORMED_FALLBACK =
  "사진 작업 상태를 확인하지 못했어요. 분석 결과를 사용하지 않고 사진 없이 계속해 주세요.";
const STORAGE_UNAVAILABLE_NOTICE =
  "이 브라우저에 사진 진행 상태를 저장하지 못했어요. 이 탭에서는 계속할 수 있지만, 화면을 닫으면 다시 이어서 확인하지 못할 수 있어요. 사진 파일은 브라우저 저장소에 보관하지 않아요.";
const RESTART_CTA = "새 사진으로 다시 시작하기";
const REFRESH_DELETION_CTA = "삭제 상태 다시 확인";
const DIRECT_ENTRY_FALLBACK =
  "이 사진 작업을 다시 확인할 수 없어요. 사진 없이 추천을 계속해 주세요.";
const UPLOAD_UNCERTAINTY =
  "사진을 보내지 못했어요. 다시 시도하거나 사진 없이 추천을 계속해 주세요.";
const PROVIDER_UNAVAILABLE =
  "사진 분석을 지금 사용할 수 없어요. 사진은 외부 분석으로 전송되지 않았어요.";
const CONFIRM_ERROR = "확정한 사진 취향을 저장하지 못했어요. 다시 시도해 주세요.";
const POLL_ERROR_COPY =
  "사진 진행 상태를 확인하지 못했어요. 연결을 확인하거나 사진 없이 추천을 계속해 주세요.";
const RESULTS_HEADING = "이번 여행에 맞는 5곳";
const PROVENANCE_PHOTO =
  "직접 확인한 사진 취향을 기대 프로필에 반영해 고른 여행지예요.";
const PROVENANCE_NO_PHOTO =
  "사진 없이 만든 기대 프로필로 고른 여행지예요.";

const CANONICAL_TITLES = QUESTIONNAIRE.questions.map(({ title_ko }) => title_ko);

type PhotoJobState = "queued" | "running" | "succeeded" | "failed" | "expired" | "deleted";

type PhotoJobSnapshot = {
  job_id: string;
  state: PhotoJobState | string;
  uploaded_count?: number;
  selected_count?: number;
  trait_candidates?: unknown;
  deletion?: { residue_verified: boolean; ledger_recorded: boolean } | null;
};

const TRAIT_TEXTS = {
  first: "조용한 사찰과 숲길 중심으로 둘러보고 싶어요",
  second: "사진 찍기 좋은 야경 명소도 포함됐으면 해요",
  third: "걷기 편한 코스 위주로 묶어 주세요",
  fourth: "바다가 보이는 카페에서 쉬어가고 싶어요",
  fifth: "사진 찍기 좋은 골목과 벽화를 함께 봤으면 해요",
  sixth: "야경이 아름다운 전망대를 마지막으로 둘러보고 싶어요",
} as const;

const TRAIT_24_CHAR = "바다 보이는 카페와 야경 산책 추가해 주세요";

function syntheticCandidates() {
  return {
    schema_version: "photo-trait-candidates-v1",
    authority_scope: "CANDIDATE_EVIDENCE_ONLY",
    traits: Object.values(TRAIT_TEXTS).map((text, index) => ({
      trait_id: `candidate-${index + 1}`,
      text_ko: text,
      origin: "MODEL_SUGGESTION",
    })),
  };
}

const PHOTO_JOBS_KEY = "itda.phase6.photo-draft.v1";
const JOB_ID = "1".repeat(64);
const PROFILE_ID = "synthetic-profile-1";
let authorityInterceptionRegistrationCount = 0;

function snapshot(state: PhotoJobState, extra: Partial<PhotoJobSnapshot> = {}): PhotoJobSnapshot {
  return { job_id: JOB_ID, state, ...extra };
}

function createJobResponse(): Record<string, unknown> {
  return { job_id: JOB_ID, state: "queued" as const };
}

/**
 * Installs the non-loopback guard plus synthetic photo-job interception.
 * Every `/v1/photo-jobs*` request is served from the given scripted queues;
 * any other `/v1/photo-jobs*` path fails the test (never escapes loopback).
 */
async function installSyntheticPhotoRoutes(
  page: Page,
  options: {
    creationResponses?: Array<Record<string, unknown> | { error: number }>;
    snapshots?: PhotoJobSnapshot[];
    finalSnapshot?: PhotoJobSnapshot;
    onCreation?: (request: Route) => Promise<void>;
    onSnapshot?: (request: Route) => Promise<void>;
    onConfirmation?: (request: Route) => Promise<void>;
    onDeletion?: (request: Route) => Promise<void>;
  } = {},
) {
  authorityInterceptionRegistrationCount += 2;
  await page.route("**/v1/photo-jobs", async (route) => {
    expect(route.request().method()).toBe("POST");
    if (options.onCreation) {
      await options.onCreation(route);
      return;
    }
    const next = options.creationResponses?.shift();
    if (next !== undefined) {
      const status = "error" in next ? (next.error as number) : 201;
      const body = "error" in next ? { detail: { code: "PHOTO_PROVIDER_UNAVAILABLE" } } : next;
      await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
      return;
    }
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify(createJobResponse()),
    });
  });
  await page.route("**/v1/photo-jobs/**", async (route) => {
    const method = route.request().method();
    const pathname = new URL(route.request().url()).pathname;
    if (method === "POST" && pathname.endsWith("/traits/confirm") && options.onConfirmation) {
      await options.onConfirmation(route);
      return;
    }
    if (method === "PUT" || method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job_id: JOB_ID, state: "queued" }),
      });
      return;
    }
    if (method === "DELETE") {
      if (options.onDeletion) {
        await options.onDeletion(route);
        return;
      }
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({ state: "delete_pending" }),
      });
      return;
    }
    expect(method).toBe("GET");
    if (options.onSnapshot) {
      await options.onSnapshot(route);
      return;
    }
    const next = options.snapshots?.shift() ?? options.finalSnapshot;
    if (next !== undefined) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(next),
      });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: "application/json",
      body: JSON.stringify({ detail: { code: "PHOTO_JOB_NOT_FOUND" } }),
    });
  });
}

async function guardLoopbackTraffic(page: Page) {
  const isDeclaredFontHost = (hostname: string) =>
    hostname.endsWith("fonts.googleapis.com") || hostname === "fonts.gstatic.com";
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) &&
      !isDeclaredFontHost(url.hostname)
    ) {
      throw new Error(`non-loopback browser request blocked: ${url.href}`);
    }
  });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (isDeclaredFontHost(url.hostname)) {
      await route.abort();
      return;
    }
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    ) {
      throw new Error(`non-loopback browser request blocked: ${url.href}`);
    }
    await route.fallback();
  });
}

test("browser network guard rejects external origins without issuing a request", () => {
  const blocked = (href: string) => {
    const url = new URL(href);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
    );
  };
  expect(blocked("https://example.com/v1/photo-jobs")).toBe(true);
  expect(blocked("http://127.0.0.1:5173/photo")).toBe(false);
});

async function createProfileJourney(page: Page) {
  // Reuses the shipped no-photo journey inputs; profile creation semantics unchanged.
  await page.goto("/start");
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
  await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
  let profileResponse: Promise<Response> | null = null;
  for (let question = 1; question <= 12; question += 1) {
    await expect(page).toHaveURL(/\/quiz$/);
    await expect(page.getByText(`${question} / 12`, { exact: true })).toBeVisible();
    await expect(page.getByText(CANONICAL_TITLES[question - 1]!, { exact: true })).toBeVisible();
    if (question === 12) {
      profileResponse = page.waitForResponse(
        (response) =>
          response.request().method() === "POST" &&
          response.url().endsWith("/v1/preference-profiles"),
      );
    }
    await page
      .getByRole("radio", {
        name: QUESTIONNAIRE.questions[question - 1]!.options[0]!.text_ko,
        exact: true,
      })
      .click();
  }
  if (profileResponse === null) throw new Error("profile submission was not observed");
  expect((await profileResponse).status()).toBe(201);
  await page
    .getByRole("button", { name: PROFILE_RECOMMENDATION_CTA })
    .waitFor({ state: "visible", timeout: 15_000 });
}

async function openPhotoPanel(page: Page) {
  const consentHeading = page.getByRole("heading", { name: CONSENT_HEADING });
  if (!(await consentHeading.isVisible())) {
    await page.getByRole("button", { name: "사진 추천 페이지 열기" }).click();
    await expect(page).toHaveURL(/\/photo$/);
    await expect(consentHeading).toBeVisible();
  }
}

async function startPhotoPath(page: Page) {
  await openPhotoPanel(page);
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();
}

async function enterPhotoPathWithConsent(
  page: Page,
  fileCount: number,
  verifyStoredReference = true,
) {
  await startPhotoPath(page);
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await expect(page.getByRole("heading", { name: PICKER_HEADING })).toBeVisible();

  const picker = page.locator('input[type="file"]');
  const files: Array<{ name: string; mimeType: string; buffer: Buffer }> = Array.from(
    { length: fileCount },
    (_, index) => ({
      name: `original-photo-${index + 1}.png`,
      mimeType: "image/png",
      buffer: Buffer.from(new Uint8Array(1024)),
    }),
  );
  await picker.setInputFiles(files);
  await page.getByRole("button", { name: `사진 ${fileCount}장 분석 시작하기` }).click();
  await expect(page).toHaveURL(/\/photo\/jobs\//);
  if (verifyStoredReference) {
    await expect.poll(
      () => page.evaluate((key) => sessionStorage.getItem(key), PHOTO_JOBS_KEY),
    ).not.toBeNull();
  }
}

async function continueWithoutPhoto(page: Page) {
  await page.getByRole("button", { name: NO_PHOTO_CTA }).click();
  await page.getByRole("button", { name: PROFILE_RECOMMENDATION_CTA }).click();
}

async function continueWithConfirmedPhoto(page: Page) {
  await expect(page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA })).toBeVisible();
  await page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA }).click();
}

test.beforeEach(async ({ page }, testInfo) => {
  authorityInterceptionRegistrationCount = 0;
  if (!testInfo.title.includes("@real-photo-backend")) {
    await guardLoopbackTraffic(page);
  }
});

const REAL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

test("@real-photo-backend real profile cookie and photo lifecycle", async ({ page, context }) => {
  const observed: Array<{ method: string; pathname: string; status: number }> = [];
  const draftRequests: Array<{ method: string; pathname: string }> = [];
  expect(authorityInterceptionRegistrationCount).toBe(0);
  await guardLoopbackTraffic(page);
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/v1/preference-profiles") || url.pathname.startsWith("/v1/photo-jobs")) {
      observed.push({ method: response.request().method(), pathname: url.pathname, status: response.status() });
    }
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/v1/journey-drafts")) {
      draftRequests.push({ method: request.method(), pathname: url.pathname });
    }
  });

  const profileResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && response.url().endsWith("/v1/preference-profiles"),
  );
  await createProfileJourney(page);
  const profileResponse = await profileResponsePromise;
  const setCookie = (await profileResponse.headerValue("set-cookie")) ?? "";
  expect(setCookie).toContain("HttpOnly");
  expect(setCookie).toContain("SameSite=strict");
  expect(setCookie).toContain("Path=/");
  expect(setCookie).toContain("Max-Age=1800");
  expect(setCookie).not.toContain("Domain=");
  expect(setCookie).not.toContain("Secure");
  expect(await page.evaluate(() => document.cookie.includes("itda_current_profile"))).toBe(false);
  const cookies = await context.cookies();
  expect(cookies.some((cookie) => cookie.name === "itda_current_profile" && cookie.httpOnly)).toBe(true);

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await page.locator('input[type="file"]').setInputFiles([
    { name: "real.png", mimeType: "image/png", buffer: REAL_PNG },
  ]);
  const jobResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "POST" && response.url().endsWith("/v1/photo-jobs"),
  );
  await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();
  const jobResponse = await jobResponsePromise;
  const job = (await jobResponse.json()) as { job_id: string };
  const jobPath = `/v1/photo-jobs/${job.job_id}`;
  const traitsResponsePromise = page.waitForResponse(
    (response) => response.request().method() === "GET" && new URL(response.url()).pathname === `${jobPath}/traits`,
  );
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible({ timeout: 20_000 });
  const traitsResponse = await traitsResponsePromise;
  const traits = (await traitsResponse.json()) as {
    candidates: Array<{ candidate_id: string; trait_id: string; text_ko: string }>;
  };
  expect(traits.candidates.length).toBeGreaterThan(0);
  const confirmRequestPromise = page.waitForRequest(
    (request) => request.method() === "POST" && new URL(request.url()).pathname === `${jobPath}/traits/confirm`,
  );
  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).click();
  const confirmRequest = await confirmRequestPromise;
  const confirmBody = confirmRequest.postDataJSON() as {
    confirmations: Array<{
      source_candidate_id: string | null;
      trait_id: string;
      text_ko: string;
      included: boolean;
    }>;
  };
  expect(confirmBody.confirmations.map((row) => row.source_candidate_id)).toEqual(
    traits.candidates.map((row) => row.candidate_id),
  );
  expect(confirmBody.confirmations).toEqual(
    traits.candidates.map((row) => ({
      source_candidate_id: row.candidate_id,
      trait_id: row.trait_id,
      text_ko: row.text_ko,
      included: true,
    })),
  );
  await continueWithConfirmedPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
  await expect(page.getByText(PROVENANCE_PHOTO)).toBeVisible();

  const deletion = await page.evaluate(async (jobId) => {
    const response = await fetch(`/v1/photo-jobs/${encodeURIComponent(jobId)}`, {
      method: "DELETE",
      credentials: "same-origin",
    });
    return { status: response.status, body: await response.json() as unknown };
  }, job.job_id);
  expect(deletion.status).toBe(200);
  expect(deletion.body).toMatchObject({ state: "deleted", cleanup_pending: false });

  const profileRequests = observed.filter((item) => item.pathname === "/v1/preference-profiles");
  expect(profileRequests).toEqual([
    { method: "POST", pathname: "/v1/preference-profiles", status: 201 },
  ]);
  const photoRequests = observed.filter((item) => item.pathname.startsWith("/v1/photo-jobs"));
  const allowedPairs = new Set([
    `POST /v1/photo-jobs`,
    `PUT ${jobPath}/images/1`,
    `POST ${jobPath}/submit`,
    `GET ${jobPath}`,
    `GET ${jobPath}/traits`,
    `POST ${jobPath}/traits/confirm`,
    `DELETE ${jobPath}`,
  ]);
  expect(photoRequests.every((item) => allowedPairs.has(`${item.method} ${item.pathname}`))).toBe(true);
  for (const pair of allowedPairs) {
    expect(photoRequests.some((item) => `${item.method} ${item.pathname}` === pair)).toBe(true);
  }
  expect(photoRequests.every((item) => item.status >= 200 && item.status < 300)).toBe(true);
  expect(draftRequests).toEqual([]);
  expect(authorityInterceptionRegistrationCount).toBe(0);
});

test("no-photo entry stays first-class and the photo journey stays synthetic", async ({
  page,
}) => {
  await createProfileJourney(page);

  const noPhoto = page.getByRole("button", { name: PROFILE_RECOMMENDATION_CTA });
  const photoPageButton = page.getByRole("button", { name: "사진 추천 페이지 열기" });
  await expect(noPhoto).toBeVisible();
  await expect(photoPageButton).toBeVisible();
  await expect(page.locator("details.profile-photo-panel")).toHaveCount(0);

  await installSyntheticPhotoRoutes(page);
  await photoPageButton.click();
  await expect(page).toHaveURL(/\/photo$/);
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();

  const checkbox = page.getByRole("checkbox");
  await expect(checkbox).not.toBeChecked();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await expect(page.getByText(CONSENT_ERROR)).toBeVisible();
  await expect(page.locator('input[type="file"]')).toHaveCount(0);
});

test("focused live-job no-photo starts cleanup and navigates without awaiting it", async ({
  page,
}) => {
  await createProfileJourney(page);
  let deletionRequested = false;
  await installSyntheticPhotoRoutes(page, {
    finalSnapshot: snapshot("queued"),
    onDeletion: async () => {
      deletionRequested = true;
      await new Promise(() => undefined);
    },
  });
  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: QUEUED_HEADING })).toBeVisible();

  const noPhotoResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/recommendation-runs"),
  );
  await continueWithoutPhoto(page);
  await noPhotoResponse;
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
  expect(deletionRequested).toBe(true);
  expect(await page.evaluate((key) => sessionStorage.getItem(key), PHOTO_JOBS_KEY)).toBeNull();
});

test("consent plus one, two, and three files with synthetic success", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", {
      trait_candidates: syntheticCandidates(),
      uploaded_count: 1,
      selected_count: 1,
    }),
  });

  for (const count of [1, 2, 3]) {
    await startPhotoPath(page);
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: CONSENT_CTA }).click();
    await page.locator('input[type="file"]').setInputFiles(
      Array.from({ length: count }, (_, index) => ({
        name: `original-photo-${index + 1}.png`,
        mimeType: "image/png",
        buffer: Buffer.from(new Uint8Array(1024)),
      })),
    );
    await expect(
      page.getByRole("button", { name: `사진 ${count}장 분석 시작하기` }),
    ).toBeEnabled();
    await page.getByRole("button", { name: `사진 ${count}장 분석 시작하기` }).click();
    await expect.poll(
      () => page.evaluate((key) => sessionStorage.getItem(key), PHOTO_JOBS_KEY),
    ).not.toBeNull();
    await page.evaluate((key) => sessionStorage.removeItem(key), PHOTO_JOBS_KEY);
    await page.goto("/profile");
  }
});

test("focused confirm failure keeps review and retry success navigates", async ({ page }) => {
  await createProfileJourney(page);
  let confirmationAttempts = 0;
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
    onConfirmation: async (route) => {
      confirmationAttempts += 1;
      await route.fulfill({
        status: confirmationAttempts === 1 ? 503 : 200,
        contentType: "application/json",
        body: JSON.stringify(
          confirmationAttempts === 1
            ? { detail: { code: "PHOTO_CONFIRMATION_UNAVAILABLE" } }
            : { job_id: JOB_ID, state: "succeeded", confirmed: [] },
        ),
      });
    },
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
  await page.getByRole("textbox", { name: TRAIT_TEXTS.first }).fill(TRAIT_24_CHAR);
  await page.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }).click();

  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).click();
  await expect(page.getByText(CONFIRM_ERROR)).toBeVisible();
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
  await expect(page.getByRole("textbox", { name: TRAIT_24_CHAR })).toHaveValue(TRAIT_24_CHAR);
  await expect(page.getByText("추천에 반영하지 않음")).toBeVisible();
  expect(confirmationAttempts).toBe(1);

  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).click();
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA })).toBeVisible();
  expect(confirmationAttempts).toBe(2);
});

test("queued to running to succeeded to review to confirm projects confirmed traits only", async ({
  page,
}) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: QUEUED_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { name: RUNNING_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  // Confirm all suggestions via the single batch CTA; recommendation remains an independent action.
  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).click();
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA })).toBeVisible();
  expect(
    await page.evaluate(() =>
      Object.keys(sessionStorage).some((key) => key.includes("photo")),
    ),
  ).toBe(true);
});

test("edit, remove, and restore candidates stay reversible before the batch confirm", async ({
  page,
}) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  const firstInput = page.getByRole("textbox", { name: TRAIT_TEXTS.first });
  await firstInput.fill(TRAIT_24_CHAR);
  const editedInput = page.getByRole("textbox", { name: TRAIT_24_CHAR });
  await expect(page.getByText("내가 수정함")).toBeVisible();

  await page.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }).click();
  await expect(page.getByText("추천에 반영하지 않음")).toBeVisible();
  await page.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 다시 포함하기` }).click();

  // Blur and Enter never confirm.
  await editedInput.blur();
  await expect(page.getByRole("button", { name: REVIEW_CONFIRM_CTA })).toBeEnabled();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: REVIEW_CONFIRM_CTA })).toBeEnabled();
});

test("zero included tags falls back to the original-profile continuation", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  for (const trait of Object.values(TRAIT_TEXTS)) {
    await page.getByRole("button", { name: `${trait} 제안 빼기` }).click();
  }

  await expect(page.getByRole("heading", { name: ZERO_TAG_HEADING })).toBeVisible();
  await expect(page.getByRole("button", { name: REVIEW_CONFIRM_CTA })).toHaveCount(0);
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
  await expect(page.getByText(PROVENANCE_NO_PHOTO)).toBeVisible();
});

test("focused aggregate overflow never creates a durable job", async ({ page }) => {
  await createProfileJourney(page);
  let jobCreated = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v1/photo-jobs")) {
      jobCreated += 1;
    }
  });
  await installSyntheticPhotoRoutes(page);

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await expect(page.getByRole("heading", { name: PICKER_HEADING })).toBeVisible();

  const picker = page.locator('input[type="file"]');
  await picker.setInputFiles(
    [1, 2, 3].map((ordinal) => ({
      name: `original-photo-${ordinal}.png`,
      mimeType: "image/png",
      buffer: Buffer.alloc(8 * 1024 * 1024),
    })),
  );
  await expect(
    page.getByText("선택한 사진 전체가 20MB보다 커요. 사진을 선택에서 빼거나 더 작은 사진을 골라 주세요."),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "사진 3장 분석 시작하기" })).toBeDisabled();
  expect(jobCreated).toBe(0);
});

test("validation rejection never creates a durable job", async ({ page }) => {
  await createProfileJourney(page);
  let jobCreated = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v1/photo-jobs")) {
      jobCreated += 1;
    }
  });
  await installSyntheticPhotoRoutes(page);

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await expect(page.getByRole("heading", { name: PICKER_HEADING })).toBeVisible();

  // Fourth file is rejected; first three remain.
  const picker = page.locator('input[type="file"]');
  await picker.setInputFiles(
    [1, 2, 3, 4].map((ordinal) => ({
      name: `original-photo-${ordinal}.png`,
      mimeType: "image/png",
      buffer: Buffer.from(new Uint8Array(1024)),
    })),
  );
  await expect(
    page.getByText("사진은 한 번에 최대 3장까지 고를 수 있어요."),
  ).toBeVisible();
  await expect(page.getByText("사진 4", { exact: false })).toHaveCount(0);
  expect(jobCreated).toBe(0);

  // Unsupported type is rejected by ordinal with no filename.
  await page.getByRole("button", { name: "다른 사진 고르기" }).click();
  await picker.setInputFiles([
    { name: "original-spoof.gif", mimeType: "image/gif", buffer: Buffer.from(new Uint8Array(64)) },
  ]);
  await expect(page.getByText("사진 1은 JPEG, PNG, WEBP 형식이 아니에요.")).toBeVisible();
  await expect(page.getByText("original-spoof")).toHaveCount(0);
  expect(jobCreated).toBe(0);
});

test("timeout falls back immediately without awaiting cleanup", async ({ page }) => {
  test.setTimeout(75_000);
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [],
    onSnapshot: async () => {
      await new Promise(() => undefined);
    },
  });

  await enterPhotoPathWithConsent(page, 1);
  await expect(page.getByText(TIMEOUT_COPY)).toBeVisible({ timeout: 70_000 });
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
});

test("provider failure keeps no-photo primary and cleanup truth separate", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    creationResponses: [{ error: 503 }],
  });

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await page
    .locator('input[type="file"]')
    .setInputFiles([
      { name: "original-photo-1.png", mimeType: "image/png", buffer: Buffer.from(new Uint8Array(1024)) },
    ]);
  await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();

  await expect(page.getByText(FAILED_HEADING)).toBeVisible();
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
});

test("expired jobs offer restart and immediate no-photo continuation", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued")],
    finalSnapshot: snapshot("expired"),
  });

  await enterPhotoPathWithConsent(page, 1);
  await expect(page.getByRole("heading", { name: EXPIRED_COPY })).toBeVisible();
  await expect(page.getByRole("button", { name: RESTART_CTA })).toBeVisible();
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
});

test("delete request walks pending to verified with bounded copy", async ({ page }) => {
  await createProfileJourney(page);
  await page.route("**/v1/photo-jobs/*/deletion", async (route) => {
    expect(route.request().method()).toBe("DELETE");
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({ state: "deleted", residue_verified: false, ledger_recorded: false }),
    });
  });
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued")],
    finalSnapshot: snapshot("deleted", { deletion: { residue_verified: true, ledger_recorded: true } }),
  });

  await enterPhotoPathWithConsent(page, 1);
  await page.getByRole("button", { name: DELETE_TRIGGER }).click();
  const dialog = page.getByRole("dialog", { name: DELETE_DIALOG_HEADING });
  await expect(dialog.getByRole("button", { name: DELETE_SAFE })).toBeFocused();
  await dialog.getByRole("button", { name: DELETE_DESTRUCTIVE }).click();

  await expect(page.getByRole("heading", { name: "삭제를 요청했어요." })).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
  await expect(page.getByRole("button", { name: REFRESH_DELETION_CTA })).toBeVisible();

  await page.getByRole("button", { name: REFRESH_DELETION_CTA }).click();
  await expect(page.getByText("원본 사진과 이 작업의 분석 제안을 삭제했어요.")).toBeVisible();
});

test("malformed job payloads collapse to the unknown fallback without candidates", async ({
  page,
}) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [
      { job_id: JOB_ID, state: "TELEPORTED" } as unknown as PhotoJobSnapshot,
      { job_id: JOB_ID, state: "running", trait_candidates: { broken: true } },
    ],
    finalSnapshot: { job_id: "", state: "succeeded" },
  });

  await enterPhotoPathWithConsent(page, 1);
  await expect(page.getByText(MALFORMED_FALLBACK)).toBeVisible();
  await expect(page.getByText("조용한 사찰")).toHaveCount(0);
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
});

test("storage-unavailable browsers keep the full journey with the exact notice", async ({
  page,
}) => {
  await createProfileJourney(page);
  await page.evaluate(() => {
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new DOMException("blocked", "SecurityError");
      },
    });
  });

  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 1, false);
  await expect(page.getByText(STORAGE_UNAVAILABLE_NOTICE)).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
  await expect(page.getByRole("heading", { name: RUNNING_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
});

test("reload keeps the bounded storage reference and rehydrates job state", async ({ page }) => {
  await createProfileJourney(page);
  let releaseSucceeded = false;
  await installSyntheticPhotoRoutes(page, {
    onSnapshot: async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          releaseSucceeded
            ? snapshot("succeeded", { trait_candidates: syntheticCandidates() })
            : snapshot("running"),
        ),
      });
    },
  });

  await enterPhotoPathWithConsent(page, 1);
  const raw = await page.evaluate((key) => sessionStorage.getItem(key), PHOTO_JOBS_KEY);
  expect(raw).toBeTruthy();
  expect((raw ?? "").length).toBeLessThanOrEqual(2048);
  const record = JSON.parse(raw ?? "{}") as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    expect(["schema_version", "job_id", "profile_id", "notice_version", "created_at"]).toContain(
      key,
    );
  }

  await page.reload();
  await expect(page.getByRole("heading", { name: RUNNING_HEADING })).toBeVisible();
  releaseSucceeded = true;
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
});

test("direct entry without a storage reference uses the bounded fallback", async ({ page }) => {
  await page.goto(`/photo/jobs/${JOB_ID}`);
  await expect(page.getByText(DIRECT_ENTRY_FALLBACK)).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
  await expect(page.getByText(/잔존|residue|원본이 삭제/)).toHaveCount(0);
});

test("upload uncertainty offers retry and immediate no-photo", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page);
  await page.route("**/v1/photo-jobs/*/images/*", async (route) => {
    await route.abort("connectionrefused");
  });

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await page
    .locator('input[type="file"]')
    .setInputFiles([
      { name: "original-photo-1.png", mimeType: "image/png", buffer: Buffer.from(new Uint8Array(1024)) },
    ]);
  await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();
  await expect(page.getByText(UPLOAD_UNCERTAINTY)).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
});

test("provider unavailability before send shows the proven not-sent copy", async ({ page }) => {
  await createProfileJourney(page);
  await page.route("**/v1/photo-jobs", async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ detail: { code: "PHOTO_SEND_BOUNDARY_NOT_CROSSED" } }),
    });
  });

  await startPhotoPath(page);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await page
    .locator('input[type="file"]')
    .setInputFiles([
      { name: "original-photo-1.png", mimeType: "image/png", buffer: Buffer.from(new Uint8Array(1024)) },
    ]);
  await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();
  await expect(page.getByText(PROVIDER_UNAVAILABLE)).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
});

test("poll network errors keep polling bounded and no-photo available", async ({ page }) => {
  await createProfileJourney(page);
  let pollAttempts = 0;
  await installSyntheticPhotoRoutes(page, {
    onSnapshot: async (route) => {
      pollAttempts += 1;
      await route.abort("connectionreset");
    },
  });

  await enterPhotoPathWithConsent(page, 1);
  await expect(page.getByText(POLL_ERROR_COPY)).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
  expect(pollAttempts).toBeGreaterThan(0);
});

test("UI-BS-01 long copy reflows at minimum viewport and 200 percent zoom", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto("/profile");
  await createProfileJourney(page);

  const noHorizontalScroll = async () =>
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);

  await noHorizontalScroll();

  // Consent screen holds the longest copy strings.
  await startPhotoPath(page);
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();
  await noHorizontalScroll();
  for (const factLabel of ["목적", "처리 범위", "외부 전송 가능성", "최소 보유와 삭제 시점"]) {
    await expect(page.getByText(factLabel, { exact: false })).toBeVisible();
  }
  await expect(page.getByRole("checkbox")).toBeVisible();
  await expect(page.getByRole("button", { name: CONSENT_CTA })).toBeVisible();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeVisible();

  // Error and fallback copy stays visible at 320px.
  await page.getByRole("button", { name: CONSENT_CTA }).click();
  await expect(page.getByText(CONSENT_ERROR)).toBeVisible();
  await noHorizontalScroll();

  // 200% zoom at the 1280x800 desktop baseline reflows without clipping.
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.evaluate(() => {
    document.documentElement.style.fontSize = "32px";
  });
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();
  await noHorizontalScroll();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeVisible();
  await expect(page.getByRole("button", { name: CONSENT_CTA })).toBeVisible();
});

test("UI-BS-02 Korean trait boundary preserves row controls", async ({ page }) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  const bounded = page.getByRole("textbox", { name: TRAIT_TEXTS.first });
  await bounded.fill(TRAIT_24_CHAR);
  const edited = page.getByRole("textbox", { name: TRAIT_24_CHAR });
  await expect(edited).toHaveValue(TRAIT_24_CHAR);
  await expect(edited).toHaveAttribute("maxlength", "24");

  const row = edited.locator("xpath=ancestor::li").first();
  await expect(row.getByRole("button", { name: `${TRAIT_TEXTS.first} 제안 빼기` })).toBeVisible();
  await expect(row.getByText("내가 수정함")).toBeVisible();
  await expect(page.getByRole("button", { name: REVIEW_CONFIRM_CTA })).toBeEnabled();

  await page.setViewportSize({ width: 320, height: 568 });
  await expect(row.getByRole("button", { name: `${TRAIT_TEXTS.first} 제안 빼기` })).toBeVisible();
  await expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBe(true);
});

test("UI-BS-03 sticky safe area leaves terminal controls reachable", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued")],
    finalSnapshot: snapshot("deleted", { deletion: { residue_verified: true, ledger_recorded: true } }),
  });

  await enterPhotoPathWithConsent(page, 1);

  // Terminal controls must be clickable (not covered by the sticky bar).
  for (const name of [DELETE_TRIGGER, NO_PHOTO_CTA]) {
    const control = page.getByRole("button", { name });
    await control.scrollIntoViewIfNeeded();
    await control.click({ trial: true });
  }
  await page.getByRole("button", { name: DELETE_TRIGGER }).click();
  const dialog = page.getByRole("dialog", { name: DELETE_DIALOG_HEADING });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: DELETE_SAFE }).click();
  await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeEnabled();
  await continueWithoutPhoto(page);
  await expect(page.getByRole("heading", { name: RESULTS_HEADING })).toBeFocused();
});

test("UI-BS-05 reload preserves provenance and confirmed-only projection", async ({ page }) => {
  await createProfileJourney(page);
  let confirmedBody: { confirmations?: Array<{ text_ko?: string; included?: boolean }> } = {};
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
    onConfirmation: async (route) => {
      confirmedBody = route.request().postDataJSON() as typeof confirmedBody;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ confirmation_receipt: "2".repeat(64) }),
      });
    },
  });

  await enterPhotoPathWithConsent(page, 2);
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  // Establish distinct provenance states: edited, excluded, and untouched suggested.
  const edited = page.getByLabel(TRAIT_TEXTS.first);
  await edited.fill(TRAIT_24_CHAR);
  await page.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }).click();
  await expect(page.getByText("내가 수정함")).toBeVisible();
  await expect(page.getByText("추천에 반영하지 않음")).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
  await expect(page.getByRole("textbox", { name: TRAIT_TEXTS.first })).toHaveValue("");
  await expect(page.getByText("내가 수정함")).toHaveCount(0);
  await expect(page.getByText("추천에 반영하지 않음")).toHaveCount(0);

  await page.getByRole("textbox", { name: TRAIT_TEXTS.first }).fill(TRAIT_24_CHAR);
  await page.getByRole("button", { name: `${TRAIT_TEXTS.second} 제안 빼기` }).click();

  // Only included, confirmed values are retained for the independent recommendation action.
  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).click();
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA })).toBeVisible();
  await expect(page.locator("details.profile-photo-panel")).not.toHaveAttribute("open", "");
  expect(
    confirmedBody.confirmations?.some((row) => row.text_ko === TRAIT_TEXTS.second),
  ).toBe(false);
  expect(confirmedBody.confirmations).toHaveLength(5);
  expect(confirmedBody.confirmations?.every((row) => row.included === true)).toBe(true);
});

test("UI-BS-06 keyboard and accessibility journeys cover every optional-photo state", async ({
  page,
}) => {
  await createProfileJourney(page);
  let releaseSucceeded = false;
  await installSyntheticPhotoRoutes(page, {
    onSnapshot: async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          releaseSucceeded
            ? snapshot("succeeded", { trait_candidates: syntheticCandidates() })
            : snapshot("running"),
        ),
      });
    },
  });

  // Entry: the independent recommendation CTA stays first and the photo panel is keyboard-reachable.
  await page.getByRole("button", { name: PROFILE_RECOMMENDATION_CTA }).focus();
  await page.keyboard.press("Tab");
  const panelSummary = page.locator("details.profile-photo-panel > summary");
  await expect(panelSummary).toBeFocused();

  // Consent: single h1, described checkbox, keyboard-only activation.
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: CONSENT_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
  const checkbox = page.getByRole("checkbox");
  await expect(checkbox).toBeVisible();
  expect(await checkbox.getAttribute("aria-describedby")).toBeTruthy();
  await checkbox.focus();
  await page.keyboard.press("Space");
  await expect(checkbox).toBeChecked();
  await page.getByRole("button", { name: CONSENT_CTA }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: PICKER_HEADING })).toBeFocused();

  // Picker: native input stays keyboard-reachable; submit via keyboard.
  const picker = page.locator('input[type="file"]');
  await picker.setInputFiles(
    [1, 2].map((ordinal) => ({
      name: `original-photo-${ordinal}.png`,
      mimeType: "image/png",
      buffer: Buffer.from(new Uint8Array(1024)),
    })),
  );
  await page.getByRole("button", { name: "사진 2장 분석 시작하기" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/profile$/);

  // Polling: the visible status is busy and focus is never stolen mid-poll.
  const pollingStatus = page.locator('[data-photo-status="running"]');
  await expect(pollingStatus).toBeVisible();
  await expect(pollingStatus).toHaveAttribute("aria-busy", "true");
  const focusBefore = await page.evaluate(() => document.activeElement?.textContent ?? "");
  releaseSucceeded = true;
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.activeElement?.textContent ?? "")).toBe(focusBefore);

  // Review: labelled inputs and accessible provenance badges.
  const firstInput = page.getByRole("textbox", { name: TRAIT_TEXTS.first });
  await firstInput.focus();
  await page.keyboard.press("End");
  expect(await firstInput.getAttribute("maxlength")).toBe("24");
  await expect(page.getByText("분석 제안").first()).toBeVisible();

  // Delete dialog: safe-first focus, Tab cycle, Escape while idle.
  await page.getByRole("button", { name: DELETE_TRIGGER }).focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: DELETE_DIALOG_HEADING });
  await expect(dialog.getByRole("button", { name: DELETE_SAFE })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: DELETE_DESTRUCTIVE })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("button", { name: DELETE_TRIGGER })).toBeFocused();

  // Confirm via keyboard: the panel closes and exposes the independent photo-aware CTA.
  await page.getByRole("button", { name: REVIEW_CONFIRM_CTA }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("button", { name: PHOTO_RECOMMENDATION_CTA })).toBeVisible();
});

test("reduced motion removes shimmer and pulse without removing information", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  await enterPhotoPathWithConsent(page, 1);
  await expect(page.getByRole("heading", { name: QUEUED_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { name: RUNNING_HEADING })).toBeVisible();
  await expect(page.getByRole("heading", { name: REVIEW_HEADING })).toBeVisible();

  const animatedValues = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>("[data-photo-status]")).flatMap((node) => {
      const style = getComputedStyle(node);
      return [style.animationName, style.transitionDuration];
    }),
  );
  for (const value of animatedValues) {
    expect(value === "none" || Number.parseFloat(value) <= 0.15).toBe(true);
  }
});

test("mobile and desktop viewports keep the reading column and controls usable", async ({
  page,
}) => {
  await createProfileJourney(page);
  await installSyntheticPhotoRoutes(page, {
    snapshots: [snapshot("queued"), snapshot("running")],
    finalSnapshot: snapshot("succeeded", { trait_candidates: syntheticCandidates() }),
  });

  for (const viewport of [
    { width: 320, height: 568 },
    { width: 390, height: 844 },
    { width: 768, height: 1024 },
  ]) {
    await page.setViewportSize(viewport);
    await enterPhotoPathWithConsent(page, 1);
    await expect(page.getByRole("button", { name: NO_PHOTO_CTA })).toBeVisible();
    await expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.evaluate((key) => sessionStorage.removeItem(key), PHOTO_JOBS_KEY);
    await page.goto("/profile");
  }
});
