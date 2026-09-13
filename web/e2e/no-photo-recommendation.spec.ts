import { FRONTEND_QUESTIONNAIRE as QUESTIONNAIRE } from "../src/content/questionnaire";
import { expect, type Page, type Response, type Route, test } from "@playwright/test";
import { createHash } from "node:crypto";

const SHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PENDING_RECOMMENDATION_KEY = "itda:phase5:pending-recommendation:v2";
const CURRENT_RECOMMENDATION_KEY = "itda:phase5:current-recommendation:v2";

const CANONICAL_TITLES = QUESTIONNAIRE.questions.map(({ title_ko }) => title_ko);

type PreferenceProfileObservation = {
  answers: Record<string, number>;
  profile_id: string;
  request_id: string;
  trip_conditions: Record<string, unknown>;
};

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function profileInputSha256(profile: PreferenceProfileObservation) {
  return createHash("sha256")
    .update(
      canonicalJson({
        questionnaire_version: QUESTIONNAIRE.questionnaire_version,
        scoring_version: QUESTIONNAIRE.scoring_version,
        description_template_version: QUESTIONNAIRE.description_template_version,
        config_hash: QUESTIONNAIRE.config_hash,
        trip_conditions: profile.trip_conditions,
        answers: profile.answers,
      }),
      "utf8",
    )
    .digest("hex");
}

type RecommendationRequestObservation = {
  preference_profile_id: string;
  request_id: string;
};

function recommendationEvidence(rank: number, axis: "h" | "e" | "r") {
  const context = { h: "역사", e: "분위기", r: "휴식" }[axis];
  return {
    evidence_id: `evidence-${rank}-${axis}`,
    excerpt_ko: `합성 검증 장소 ${rank}의 ${context} 맥락을 설명하는 저장 근거예요.`,
    source_label_ko: "한국관광공사 TourAPI 공식 관광정보",
    attribution_ko: "출처: 한국관광공사 TourAPI (공공데이터포털 데이터셋 15101578)",
    contest_use_scope: "noncommercial_contest_demo_evaluation",
    contest_rights_qualified: true,
    reference_date: "2026-08-10",
  };
}

function assertLoopbackUrl(rawUrl: string) {
  const url = new URL(rawUrl);
  if (
    (url.protocol === "http:" || url.protocol === "https:") &&
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
  ) {
    throw new Error(`non-loopback browser request blocked: ${url.href}`);
  }
}

async function guardLoopbackTraffic(page: Page) {
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === "fonts.googleapis.com" || url.hostname === "fonts.gstatic.com") {
      await route.abort();
      return;
    }
    assertLoopbackUrl(url.href);
    await route.fallback();
  });
}

test("browser network guard rejects external origins without issuing a request", () => {
  expect(() => assertLoopbackUrl("https://example.com/v1/recommendation-runs")).toThrow(
    "non-loopback browser request blocked",
  );
  expect(() => assertLoopbackUrl("http://127.0.0.1:4173/start")).not.toThrow();
});

async function fillTripContext(page: Page) {
  await page.getByLabel("방문 날짜 (선택)").fill("2026-10-09");
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

function waitForProfile(page: Page) {
  return page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/preference-profiles"),
  );
}

async function answerQuiz(page: Page, answerIndex: (ordinal: number) => number) {
  let responsePromise: Promise<Response> | null = null;
  for (const [index] of QUESTIONNAIRE.questions.entries()) {
    await expect(page).toHaveURL(/\/quiz$/);
    await expect(page.getByText(`${index + 1} / 12`, { exact: true })).toBeVisible();
    await expect(page.getByText(CANONICAL_TITLES[index], { exact: true })).toBeVisible();
    const option = QUESTIONNAIRE.questions[index]!.options[answerIndex(index + 1)]!;
    if (index === QUESTIONNAIRE.questions.length - 1) {
      responsePromise = waitForProfile(page);
    }
    await page.getByRole("radio", { name: option.text_ko, exact: true }).click();
  }

  if (responsePromise === null) throw new Error("profile submission was not observed");
  const response = await responsePromise;
  expect(response.status()).toBe(201);
  return (await response.json()) as PreferenceProfileObservation;
}

async function createInitialProfile(page: Page) {
  await page.goto("/start");
  await fillTripContext(page);
  await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
  return answerQuiz(page, () => 0);
}

async function confirmChangedProfile(page: Page) {
  await page.getByRole("button", { name: "답변 수정하기" }).click();
  return answerQuiz(page, (ordinal) => (ordinal === 1 ? 2 : 0));
}

function recommendationResponse(
  request: RecommendationRequestObservation,
  profileInputSha256: string,
  runId: string,
) {
  return {
    schema_version: "itda.recommendation-run-created.v1",
    recommendation_run_id: runId,
    request_id: request.request_id,
    preference_profile_id: request.preference_profile_id,
    preference_input_sha256: profileInputSha256,
  };
}

function halfUp(numerator: number, denominator: number) {
  return Math.floor((numerator + Math.floor(denominator / 2)) / denominator);
}

const CONFIG_SHA = "f94bcaa2b895f9a19e94a5f54ba6af640e9a1226fce03b942ba023e0bd2e9c19";
const RECOVERY_POLICY_SHA = "8cf0d41d64fb987b0ac3c146a5045ef34efe7f12c2a1b3268730bdac97b65300";
const HARD_DUPLICATE_SHA = "32905425be2491414797c0bdc026314de91cdd979abca7cd6d721df3370a8d22";
const CANNOT_COAPPEAR_SHA = "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70";
const ACTIVATION_SUITE_SHA = "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659";
const CONTRAST_SUITE_SHA = "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9";
const CONFIDENCE_REASON = {
  EVIDENCE_LIMITED_MISMATCH_SUPPRESSED: "확인된 근거가 제한되어 기대 차이 안내를 생략했어요.",
  EVIDENCE_LIMITED_MISMATCH_AVAILABLE: "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요.",
  EVIDENCE_SUPPORTED: "확인된 근거 범위에서 안내해요.",
} as const;

type ConfidenceState = keyof typeof CONFIDENCE_REASON;

function confidenceStateFor(confidence: number): ConfidenceState {
  if (confidence < 65) return "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED";
  if (confidence < 70) return "EVIDENCE_LIMITED_MISMATCH_AVAILABLE";
  return "EVIDENCE_SUPPORTED";
}

function currentAuthority() {
  return {
    recovery_policy_sha256: RECOVERY_POLICY_SHA,
    hard_duplicate_adjudication_sha256: HARD_DUPLICATE_SHA,
    cannot_coappear_authority_sha256: CANNOT_COAPPEAR_SHA,
    activation_suite_sha256: ACTIVATION_SUITE_SHA,
    contrast_suite_sha256: CONTRAST_SUITE_SHA,
  };
}

function recommendationResultsResponse(profileId: string, inputDigest: string) {
  const confidenceByRank = [55, 64, 65, 69, 70];
  const items = Array.from({ length: 5 }, (_, index) => {
    const rank = index + 1;
    const confidence = confidenceByRank[index]!;
    const confidenceState = confidenceStateFor(confidence);
    const referenceDate = "2026-08-10";
    const fitScore = 91 - rank; // Boundary fixtures keep fit arithmetic independent from confidence.
    const absoluteDifference = 100 - fitScore;
    const axisDefinitions = [
      ["HISTORY_TRADITION", 100, "h"],
      ["EMOTION_IMAGE", 95, "e"],
      ["REST_IMMERSION", 90, "r"],
    ] as const;
    const axisScores = axisDefinitions.map(([axis, expectedValue, suffix]) => ({
      axis,
      value: expectedValue - absoluteDifference,
      evidence_ids: [`evidence-${rank}-${suffix}`],
    }));
    const axisComponents = axisDefinitions.map(([axis, expectedValue, suffix]) => ({
      contribution_id: `contribution-${rank}-${suffix}`,
      axis,
      expected_value: expectedValue,
      place_value: expectedValue - absoluteDifference,
      absolute_difference: absoluteDifference,
      fit_score: fitScore,
    }));
    const conditionWeights = [400, 350, 350, 350, 300, 250];
    const conditionComponents = [
      "VISIT_DATE_TIME",
      "COMPANIONS",
      "TRANSPORT",
      "WALKING",
      "INDOOR_OUTDOOR",
      "CROWD",
    ].map((condition_id, conditionIndex) => ({
      contribution_id: `contribution-${rank}-condition-${conditionIndex}`,
      condition_id,
      expected_value: 50,
      place_value: 40,
      absolute_difference: 10,
      fit_score: 90,
      total_score_weight_bp: conditionWeights[conditionIndex],
      weighted_numerator: 90 * conditionWeights[conditionIndex]!,
    }));
    const experienceFitScore = fitScore;
    const travelConditionFitScore = halfUp(
      conditionComponents.reduce((total, component) => total + component.weighted_numerator, 0),
      2_000,
    );
    const relevanceNumerator = experienceFitScore * 8_000 + travelConditionFitScore * 2_000;
    const relevanceScore = halfUp(relevanceNumerator, 10_000);
    const diversityNoveltyScore = 50;
    const rerankNumerator = relevanceScore * 8_500 + diversityNoveltyScore * 1_500;
    const contribution = {
      axis_components: axisComponents,
      condition_components: conditionComponents,
      experience_fit_score: experienceFitScore,
      travel_condition_fit_score: travelConditionFitScore,
      relevance_score: relevanceScore,
      relevance_numerator: relevanceNumerator,
      diversity_novelty_score: diversityNoveltyScore,
      rerank_score: halfUp(rerankNumerator, 10_000),
      rerank_numerator: rerankNumerator,
    };
    return {
      rank,
      place_id: `synthetic-place-${rank}`,
      place_name_ko: `합성 검증 장소 ${rank}`,
      fit_score: relevanceScore,
      confidence_percent: confidence,
      evidence_confidence_state: confidenceState,
      evidence_confidence_reason_ko: CONFIDENCE_REASON[confidenceState],
      mismatch: {
        raw_score: 30,
        effective_score: 30,
        axis_distance: 30,
        trait_distance: 30,
        important_trait_floor_applied: false,
        state: confidence < 65 ? "SUPPRESSED_LOW_CONFIDENCE" : "GENTLE_DIFFERENCE",
        template_id: confidence < 65 ? null : "mismatch-gentle-v1",
        message_ko: confidence < 65 ? null : "한 가지 차이를 확인해 보세요.",
        suppression_reason: confidence < 65 ? "CONFIDENCE_BELOW_65" : null,
      },
      contribution,
      axis_scores: axisScores,
      evidence: [recommendationEvidence(rank, "h"), recommendationEvidence(rank, "e")],
      explanations: [
        {
          contribution_id: `contribution-${rank}-h`,
          place_attribute_id: "HISTORY_TRADITION",
          evidence_id: `evidence-${rank}-h`,
          reference_date: referenceDate,
          template_id: "reason-history-v1",
          message_ko: `역사 근거 ${rank}이 이번 기대와 이어져요.`,
        },
        {
          contribution_id: `contribution-${rank}-e`,
          place_attribute_id: "EMOTION_IMAGE",
          evidence_id: `evidence-${rank}-e`,
          reference_date: referenceDate,
          template_id: "reason-emotion-v1",
          message_ko: `감성 근거 ${rank}이 이번 기대와 이어져요.`,
        },
      ],
      reference_date: referenceDate,
      image_state: "ABSENT",
    };
  });
  const scoredCandidates = items.map((item) => ({
    place_id: item.place_id,
    relevance_score: item.contribution.relevance_score,
    experience_fit_score: item.contribution.experience_fit_score,
    travel_condition_fit_score: item.contribution.travel_condition_fit_score,
    contribution: item.contribution,
    mismatch: item.mismatch,
  }));
  const diversitySteps = items.map((item, index) => ({
    rank: item.rank,
    selected_place_id: item.place_id,
    relevance_score: item.contribution.relevance_score,
    novelty_score: item.contribution.diversity_novelty_score,
    combined_score: item.contribution.rerank_score,
    considered: items.slice(index).map((remaining) => ({
      place_id: remaining.place_id,
      relevance_score: remaining.contribution.relevance_score,
      novelty_score: remaining.contribution.diversity_novelty_score,
      combined_score: remaining.contribution.rerank_score,
    })),
  }));
  const deterministicRun = {
    schema_version: "recommendation-run.v1",
    input_digest: inputDigest,
    release_sha256: SHA.replaceAll("0", "2"),
    canonical_membership_sha256: SHA.replaceAll("0", "3"),
    config_sha256: CONFIG_SHA,
    kernel_version: "recommendation-kernel-v3",
    authority: currentAuthority(),
    candidate_set_digest: SHA.replaceAll("0", "4"),
    candidate_place_ids: items.map((item) => item.place_id),
    exclusions: [],
    duplicate_decisions: [],
    scored_candidates: scoredCandidates,
    diversity_steps: diversitySteps,
    items: items.map(({ confidence_percent: _confidence, ...item }) => item),
    ndcg_status: "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS",
    ndcg_denominator: 0,
  };
  const canonicalSha256 = createHash("sha256")
    .update(canonicalJson(deterministicRun), "utf8")
    .digest("hex");
  return {
    schema_version: "itda.recommendation-results.v1",
    preference_profile_id: profileId,
    analysis_origin: "DEMO_MODEL_DERIVED",
    operating_states: items.map((item) => ({
      place_id: item.place_id,
      state: "OPERATING_INFORMATION_UNVERIFIED",
    })),
    release_disclosure: {
      analysis_origin: "DEMO_MODEL_DERIVED",
      model: "glm-5v-turbo",
      prompt_schema_version: "phase5-demo-profile.v1",
      profile_schema_version: "itda.demo-model-derived-profile.v1",
      config_sha256: CONFIG_SHA,
      source_bundle_sha256: SHA.replaceAll("0", "1"),
      release_sha256: SHA.replaceAll("0", "2"),
      reference_date: "2026-08-10",
    },
    run: {
      ...deterministicRun,
      run_id: `recommendation-run:${canonicalSha256.slice(0, 32)}`,
      created_at: "2026-08-10T12:00:00Z",
      canonical_sha256: canonicalSha256,
    },
  };
}

function recommendationDetailResponse(
  results: ReturnType<typeof recommendationResultsResponse>,
  placeId: string,
) {
  const runId = results.run.run_id;
  const item = results.run.items.find((candidate) => candidate.place_id === placeId);
  if (item === undefined) throw new Error(`unknown synthetic detail place: ${placeId}`);
  const rank = item.rank;
  const confidence = [55, 64, 65, 69, 70][rank - 1]!;
  return {
    run_id: runId,
    release_sha256: results.run.release_sha256,
    confidence_percent: confidence,
    evidence_confidence_state: item.evidence_confidence_state,
    evidence_confidence_reason_ko: item.evidence_confidence_reason_ko,
    item: Object.fromEntries(
      Object.entries(item).filter(([key]) => key !== "confidence_percent"),
    ),
    mismatch_traits: [1, 2, 3, 4, 5, 6].map((value) => ({
      trait_id: `M${value}`,
      value: 40 + value,
      evidence_ids: [`evidence-${rank}-${value === 1 ? "h" : "e"}`],
    })),
    evidence: [...item.evidence, recommendationEvidence(rank, "r")],
    operating_state: "OPERATING_INFORMATION_UNVERIFIED",
    similar_place_ids: results.run.items
      .filter((candidate) => candidate.place_id !== placeId)
      .slice(0, 3)
      .map((candidate) => candidate.place_id),
  };
}

function recommendationComparisonResponse(runId: string, placeIds: string[]) {
  const complete = (row_id: string, label_ko: string, value: string) => ({
    row_id,
    label_ko,
    values_ko: placeIds.map(() => value),
    missing_reasons: placeIds.map(() => null),
  });
  const rows = [
    {
      row_id: "fit-score",
      label_ko: "추천 적합도",
      values_ko: placeIds.map((_, index) => String(90 - index)),
      missing_reasons: placeIds.map(() => null),
    },
    complete("axis-history_tradition", "역사·전통", "80점 / 100점"),
    complete("axis-emotion_image", "감성·이미지", "70점 / 100점"),
    complete("axis-rest_immersion", "휴식·몰입", "60점 / 100점"),
    complete("evidence-reason-1", "잘 맞는 이유 1", "역사 근거가 이번 기대와 이어져요."),
    complete("evidence-reason-2", "잘 맞는 이유 2", "감성 근거가 이번 기대와 이어져요."),
    complete("mismatch-guidance", "이번 여행에서 기대한 것과 다른 점", "한 가지 차이를 확인해 보세요."),
    complete("trait-m1", "공간 성격", "41점 / 100점"),
    complete("trait-m2", "방문객 성격", "42점 / 100점"),
    complete("trait-m3", "현장 밀도", "43점 / 100점"),
    complete("trait-m4", "경험 방식", "44점 / 100점"),
    complete("trait-m5", "체류 방식", "45점 / 100점"),
    complete("trait-m6", "시간 의존성", "46점 / 100점"),
    complete(
      "time-season-context",
      "시간·계절 맥락",
      "저장된 시간 의존성은 46점 / 100점이에요. 야간·계절·특정 시간의 영향 가능성을 뜻해요.",
    ),
    {
      row_id: "operating-state",
      label_ko: "운영 정보",
      values_ko: placeIds.map(() => "정보 없음"),
      missing_reasons: placeIds.map(() => "OPERATING_INFORMATION_UNVERIFIED"),
    },
    complete("media-state", "대표 이미지 상태", "대표 이미지 없음"),
    complete("reference-date", "데이터 기준일", "2026-08-10"),
  ];
  return {
    schema_version: "recommendation-comparison-v1",
    run_id: runId,
    release_sha256: SHA.replaceAll("0", "2"),
    place_ids: placeIds,
    rows,
  };
}

async function fulfillRecommendation(
  route: Route,
  profileInputSha256: string,
  runId: string,
) {
  const request = route.request().postDataJSON() as RecommendationRequestObservation;
  await route.fulfill({
    status: 201,
    contentType: "application/json",
    body: JSON.stringify(recommendationResponse(request, profileInputSha256, runId)),
  });
}

async function fulfillRecommendationResults(
  route: Route,
  results: ReturnType<typeof recommendationResultsResponse>,
) {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(results),
  });
}

function operatingInformationResponse(runId: string, placeIds: string[]) {
  return {
    schema_version: "operating-information.v1",
    run_id: runId,
    places: placeIds.map((placeId, index) => ({
      place_id: placeId,
      state: "AVAILABLE",
      snapshot: {
        provider: "TOUR_API",
        operation: "detailIntro2",
        content_type_id: "39",
        entries: [
          {
            kind: "OPENING_HOURS",
            label_ko: "영업시간",
            value_ko: `${11 + index}:00~20:00`,
            provider_field: "opentimefood",
          },
          {
            kind: "REST_DATES",
            label_ko: "휴무일",
            value_ko: "매주 월요일",
            provider_field: "restdatefood",
          },
        ],
        retrieved_at: "2026-09-05T04:30:00Z",
        provider_modifiedtime: "20260905043000",
        source_label_ko: "한국관광공사 TourAPI(KorService2 detailIntro2)",
        cached: false,
      },
      unavailable_reason: null,
    })),
  };
}

async function assertTop5Results(
  page: Page,
  expectedAnalysisOrigin:
    | "DEMO_MODEL_DERIVED"
    | "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
) {
  await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeFocused();
  const cards = page.getByRole("list", { name: "추천 5곳" }).getByRole("listitem");
  await expect(cards).toHaveCount(5);
  await expect(cards.first()).toContainText("1위");
  await expect(cards.first()).toContainText("잘 맞는 이유");
  await expect(cards.first()).toContainText("이번 여행에서 기대한 것과 다른 점");
  await expect(
    page.locator(
      `.recommendation-status-banner[data-analysis-origin="${expectedAnalysisOrigin}"]`,
    ),
  ).toBeVisible();
}

test("@real-demo real demo Top 5 results", async ({ page }) => {
  await guardLoopbackTraffic(page);
  await createInitialProfile(page);
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await assertTop5Results(page, "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED");
});

test("synthetic clean Top 5 results", async ({ page }) => {
  await guardLoopbackTraffic(page);
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/*", async (route) => {
    await fulfillRecommendationResults(route, results);
  });
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await assertTop5Results(page, "DEMO_MODEL_DERIVED");
});

test("synthetic current operating information joins results, detail, and comparison", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  await page.setViewportSize({ width: 390, height: 844 });
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/**", async (route) => {
    const url = new URL(route.request().url());
    const pathname = decodeURIComponent(url.pathname);
    if (pathname.endsWith("/operating-information")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          operatingInformationResponse(runId, url.searchParams.getAll("place_id")),
        ),
      });
      return;
    }
    if (pathname.endsWith("/comparison")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          recommendationComparisonResponse(runId, url.searchParams.getAll("place_id")),
        ),
      });
      return;
    }
    const detailMatch = pathname.match(/\/recommendation-runs\/[^/]+\/places\/([^/]+)$/);
    if (detailMatch !== null) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(recommendationDetailResponse(results, detailMatch[1]!)),
      });
      return;
    }
    await fulfillRecommendationResults(route, results);
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  const firstCard = page.locator("[data-recommendation-card]").first();
  await expect(firstCard.getByText("영업시간")).toBeVisible();
  await expect(firstCard.getByText("11:00~20:00")).toBeVisible();
  await expect(firstCard.getByText(/한국관광공사 TourAPI/)).toBeVisible();
  await expect(firstCard).not.toContainText("현재 영업 중");

  await firstCard.getByRole("link", { name: /상세 보기$/ }).click();
  await expect(page.getByRole("heading", { name: "최신 운영 정보" })).toBeVisible();
  await expect(page.getByText("매주 월요일")).toBeVisible();
  await expect(page.getByText(/2026\. 09\. 05\. 13:30 확인/)).toBeVisible();

  await page.getByRole("button", { name: "합성 검증 장소 1 비교에 추가" }).click();
  await page.getByRole("link", { name: "합성 검증 장소 2 상세 보기" }).click();
  await page.getByRole("button", { name: "합성 검증 장소 2 비교에 추가" }).click();
  await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
  const liveRow = page.locator("[data-operating-comparison-row]");
  await expect(liveRow).toContainText("11:00~20:00");
  await expect(liveRow).toContainText("12:00~20:00");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("@real-demo real demo place detail stays pinned through similar, back, forward, and refresh", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  let recommendationPosts = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/v1/recommendation-runs")
    ) {
      recommendationPosts += 1;
    }
  });

  await createInitialProfile(page);
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await assertTop5Results(page, "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED");
  const runUrl = page.url();
  await page.getByRole("link", { name: /상세 보기/ }).first().click();

  await expect(page.locator("[data-place-detail]")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
  await expect(page.getByText("잘 맞는 이유", { exact: true })).toBeVisible();
  await expect(page.getByText("이번 여행에서 기대한 것과 다른 점", { exact: true })).toBeVisible();
  await expect(page.getByText("시간·계절 맥락", { exact: true })).toBeVisible();
  await expect(page.getByText(/운영 정보 미확인/)).toBeVisible();
  await expect(page.getByText(/영업 중|현재 이용 가능/)).toHaveCount(0);
  await expect(page.getByText("GLM 공개 근거 모델 분석", { exact: true })).toBeVisible();

  const firstDetailUrl = page.url();
  await page
    .getByRole("list", { name: "같은 추천 실행의 비슷한 장소" })
    .getByRole("link")
    .first()
    .click();
  await expect(page.locator("[data-place-detail]")).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
  expect(page.url()).not.toBe(firstDetailUrl);
  expect(page.url().split("/places/")[0]).toBe(runUrl);

  await page.goBack();
  await expect(page).toHaveURL(firstDetailUrl);
  await page.goForward();
  await page.reload();
  await expect(page.locator("[data-place-detail]")).toBeVisible();
  expect(recommendationPosts).toBe(1);
});

test("@real-demo @private-real-demo private real demo complete journey", async ({ page }) => {
  await guardLoopbackTraffic(page);
  let recommendationPosts = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v1/recommendation-runs")) {
      recommendationPosts += 1;
    }
  });

  await createInitialProfile(page);
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await assertTop5Results(page, "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED");

  let cards = page.getByRole("list", { name: "추천 5곳" }).getByRole("listitem");
  await cards.nth(0).getByRole("button", { name: /비교에 추가$/ }).click();
  await cards.nth(1).getByRole("button", { name: /비교에 추가$/ }).click();
  await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
  await expect(page.getByRole("heading", { name: "선택한 장소 비교" })).toBeFocused();
  await expect(page.getByRole("region", { name: "장소 비교표" })).toBeVisible();

  await page.goBack();
  await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeFocused();
  cards = page.getByRole("list", { name: "추천 5곳" }).getByRole("listitem");
  await cards.nth(0).getByRole("button", { name: / 저장$/ }).click();
  await expect(cards.nth(0).getByRole("button", { name: / 저장됨$/ })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await cards.nth(0).getByRole("link", { name: /상세 보기$/ }).click();
  await expect(page.locator("[data-place-detail]")).toBeVisible();
  await expect(page.getByText("잘 맞는 이유", { exact: true })).toBeVisible();

  await page.goBack();
  await page.reload();
  await expect(page.getByRole("heading", { name: "저장한 장소" })).toBeVisible();
  expect(recommendationPosts).toBe(1);
});

test("synthetic clean place detail is GET-only, text-first, and mobile-safe", async ({ page }) => {
  await guardLoopbackTraffic(page);
  await page.setViewportSize({ width: 320, height: 800 });
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  let recommendationPosts = 0;
  let pinnedReads = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/v1/recommendation-runs")
    ) {
      recommendationPosts += 1;
    }
  });
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/**", async (route) => {
    expect(route.request().method()).toBe("GET");
    pinnedReads += 1;
    const pathname = decodeURIComponent(new URL(route.request().url()).pathname);
    const detailMatch = pathname.match(/\/recommendation-runs\/[^/]+\/places\/([^/]+)$/);
    if (detailMatch !== null) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(recommendationDetailResponse(results, detailMatch[1]!)),
      });
      return;
    }
    await fulfillRecommendationResults(route, results);
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await page.getByRole("link", { name: "합성 검증 장소 1 상세 보기" }).click();
  await expect(page.getByRole("heading", { name: "합성 검증 장소 1" })).toBeFocused();
  await expect(page.getByText("대표 이미지 없음", { exact: true })).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
  await expect(page.getByText(/영업 중|현재 이용 가능/)).toHaveCount(0);
  await expect(page.getByRole("list", { name: "여섯 가지 기대 차이 특성" })).toBeVisible();
  await expect(page.getByText("합성 검증 장소 1의 역사 맥락을 설명하는 저장 근거예요.")).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBe(true);

  const firstDetailUrl = page.url();
  await page.getByRole("link", { name: "합성 검증 장소 2 상세 보기" }).click();
  await expect(page.getByRole("heading", { name: "합성 검증 장소 2" })).toBeFocused();
  await page.goBack();
  await expect(page).toHaveURL(firstDetailUrl);
  await page.goForward();
  await page.reload();
  await expect(page.getByRole("heading", { name: "합성 검증 장소 2" })).toBeFocused();
  expect(recommendationPosts).toBe(1);
  expect(pinnedReads).toBeGreaterThanOrEqual(8);
});

test("compare keeps two same-run places through detail, refresh, and mobile table navigation", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  await page.setViewportSize({ width: 320, height: 800 });
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  let recommendationPosts = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v1/recommendation-runs")) {
      recommendationPosts += 1;
    }
  });
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/**", async (route) => {
    expect(route.request().method()).toBe("GET");
    const url = new URL(route.request().url());
    const pathname = decodeURIComponent(url.pathname);
    if (pathname.endsWith("/comparison")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          recommendationComparisonResponse(runId, url.searchParams.getAll("place_id")),
        ),
      });
      return;
    }
    const detailMatch = pathname.match(/\/recommendation-runs\/[^/]+\/places\/([^/]+)$/);
    if (detailMatch !== null) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(recommendationDetailResponse(results, detailMatch[1]!)),
      });
      return;
    }
    await fulfillRecommendationResults(route, results);
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await page.getByRole("button", { name: "합성 검증 장소 1 비교에 추가" }).click();
  await expect(page.getByText("1/3")).toBeVisible();
  await page.getByRole("link", { name: "합성 검증 장소 2 상세 보기" }).click();
  await page.getByRole("button", { name: "합성 검증 장소 2 비교에 추가" }).click();
  await expect(page.getByText("2/3")).toBeVisible();
  await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();

  await expect(page).toHaveURL(`/recommendations/${encodeURIComponent(runId)}/compare`);
  await expect(page.getByRole("heading", { name: "선택한 장소 비교" })).toBeFocused();
  await expect(page.locator("caption", { hasText: "선택한 장소 2~3곳 비교" })).toBeVisible();
  await expect(page.getByRole("region", { name: "장소 비교표" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "합성 검증 장소 1" })).toBeVisible();
  await expect(page.getByRole("rowheader", { name: "운영 정보" })).toBeVisible();
  await expect(
    page.getByText("정보 없음 — 운영 정보가 확인되지 않았어요.").first(),
  ).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  await page.reload();
  await expect(page.getByRole("heading", { name: "선택한 장소 비교" })).toBeFocused();
  await page.goBack();
  await expect(page.getByRole("heading", { name: "합성 검증 장소 2" })).toBeFocused();
  await page.goForward();
  await expect(page.getByRole("heading", { name: "선택한 장소 비교" })).toBeFocused();
  expect(recommendationPosts).toBe(1);
});

test("map-free journey keeps 320px overflow contained and honors reduced motion", async ({ page }) => {
  await guardLoopbackTraffic(page);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.setViewportSize({ width: 320, height: 800 });
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/comparison")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(
          recommendationComparisonResponse(runId, url.searchParams.getAll("place_id")),
        ),
      });
      return;
    }
    await fulfillRecommendationResults(route, results);
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await assertTop5Results(page, "DEMO_MODEL_DERIVED");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const cards = page.locator("[data-recommendation-card]");
  const firstBox = await cards.nth(0).boundingBox();
  const secondBox = await cards.nth(1).boundingBox();
  expect(firstBox?.x).toBe(secondBox?.x);
  await expect(cards.first().getByText("잘 맞는 이유", { exact: true })).toBeVisible();
  await expect(
    cards.first().getByText("이번 여행에서 기대한 것과 다른 점", { exact: true }),
  ).toBeVisible();

  const firstSave = page.getByRole("button", { name: "합성 검증 장소 1 저장" });
  const saveBox = await firstSave.boundingBox();
  expect(saveBox?.height).toBeGreaterThanOrEqual(44);
  await firstSave.focus();
  const focusAndMotion = await firstSave.evaluate((node) => {
    const style = getComputedStyle(node);
    return {
      outlineWidth: style.outlineWidth,
      transitionDuration: style.transitionDuration,
    };
  });
  expect(focusAndMotion.outlineWidth).toBe("3px");
  expect(Number.parseFloat(focusAndMotion.transitionDuration)).toBeLessThanOrEqual(0.00001);

  await page.getByRole("button", { name: "합성 검증 장소 1 비교에 추가" }).click();
  await page.getByRole("button", { name: "합성 검증 장소 2 비교에 추가" }).click();
  await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
  const tableRegion = page.getByRole("region", { name: "장소 비교표" });
  await expect(page.getByRole("heading", { name: "선택한 장소 비교" })).toBeFocused();
  await tableRegion.focus();
  await expect(tableRegion).toBeFocused();
  expect(
    await tableRegion.evaluate((node) => node.scrollWidth > node.clientWidth),
  ).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("save and reload keeps the exact release-bound place without another recommendation POST", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  const profile = await createInitialProfile(page);
  const inputDigest = profileInputSha256(profile);
  const results = recommendationResultsResponse(profile.profile_id, inputDigest);
  const runId = results.run.run_id;
  let recommendationPosts = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v1/recommendation-runs")) {
      recommendationPosts += 1;
    }
  });
  await page.route("**/v1/recommendation-runs", async (route) => {
    await fulfillRecommendation(route, inputDigest, runId);
  });
  await page.route("**/v1/recommendation-runs/**", async (route) => {
    expect(route.request().method()).toBe("GET");
    await fulfillRecommendationResults(route, results);
  });
  await page.route("**/v1/saved-place-references/**", async (route) => {
    expect(route.request().method()).toBe("GET");
    const parts = decodeURIComponent(new URL(route.request().url()).pathname).split("/");
    const placeId = parts.at(-1)!;
    const releaseSha256 = parts.at(-2)!;
    const rank = Number(placeId.split("-").at(-1));
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        place_id: placeId,
        place_name_ko: `합성 검증 장소 ${rank}`,
        saved_release_sha256: releaseSha256,
        resolved_release_sha256: releaseSha256,
        state: "CURRENT",
        state_reason: null,
      }),
    });
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await page.getByRole("button", { name: "합성 검증 장소 1 저장" }).click();
  await expect(page.getByRole("button", { name: "합성 검증 장소 1 저장됨" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByText("합성 검증 장소 1을 이 브라우저에 저장했어요.")).toBeVisible();

  const stored = await page.evaluate(() => {
    const raw = window.localStorage.getItem("itda.phase5.saved-places.v1");
    return raw === null ? null : JSON.parse(raw);
  });
  expect(stored).toHaveLength(1);
  expect(Object.keys(stored[0]).sort()).toEqual([
    "place_id",
    "release_sha256",
    "saved_at",
    "schema_version",
  ]);

  await page.reload();
  await expect(page.getByRole("heading", { name: "저장한 장소" })).toBeVisible();
  await expect(page.getByText("현재 저장 릴리스에서 확인했어요.")).toBeVisible();
  await expect(page.getByRole("button", { name: "합성 검증 장소 1 저장됨" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(recommendationPosts).toBe(1);
  await expect(page.getByText(/계정|동기화|공유|일정|투표/)).toHaveCount(0);
});

test("NO_ACTIVE_SCORED_RELEASE preserves the confirmed profile and offers bounded recovery", async ({
  page,
}) => {
  await guardLoopbackTraffic(page);
  await createInitialProfile(page);
  await page.route("**/v1/recommendation-runs", async (route) => {
    const request = route.request().postDataJSON() as RecommendationRequestObservation;
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        detail: {
          code: "NO_ACTIVE_SCORED_RELEASE",
          message_ko: "검증된 점수 프로필 24곳이 모두 준비된 뒤에만 추천을 보여드려요.",
          request_id: request.request_id,
          preference_profile_id: request.preference_profile_id,
          release_id: null,
        },
      }),
    });
  });

  const requests: RecommendationRequestObservation[] = [];
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/v1/recommendation-runs")
    ) {
      requests.push(request.postDataJSON() as RecommendationRequestObservation);
    }
  });

  const unavailableResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/recommendation-runs"),
  );
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  expect((await unavailableResponse).status()).toBe(503);

  const heading = page.getByRole("heading", {
    name: "추천 준비가 아직 끝나지 않았어요.",
  });
  await expect(heading).toBeFocused();
  await expect(page.locator('[data-status="NO_ACTIVE_SCORED_RELEASE"]')).toContainText(
    "검증된 점수 프로필 24곳이 모두 준비된 뒤에만 추천을 보여드려요. 잠시 후 다시 확인해 주세요.",
  );
  await expect(page.getByRole("meter", { name: "역사·전통 33점 / 100점" })).toBeVisible();
  await expect(page.locator("[data-recommendation-card]")).toHaveCount(0);

  const retryResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/v1/recommendation-runs"),
  );
  await page.getByRole("button", { name: "추천 준비 다시 확인" }).click();
  expect((await retryResponse).status()).toBe(503);
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual(requests[0]);
  await page.reload();
  await expect(page.getByRole("meter", { name: "역사·전통 33점 / 100점" })).toBeVisible();
  expect(requests).toHaveLength(2);
});

test("request identity changes with confirmed profile", async ({ page }) => {
  await guardLoopbackTraffic(page);
  const initialProfile = await createInitialProfile(page);
  const initialResults = recommendationResultsResponse(
    initialProfile.profile_id,
    profileInputSha256(initialProfile),
  );
  const requests: RecommendationRequestObservation[] = [];
  let attempt = 0;
  let changedProfile: PreferenceProfileObservation;
  let changedResults: ReturnType<typeof recommendationResultsResponse> | undefined;

  await page.route("**/v1/recommendation-runs", async (route) => {
    const request = route.request().postDataJSON() as RecommendationRequestObservation;
    requests.push(request);
    attempt += 1;
    if (attempt === 1) {
      await route.abort("failed");
      return;
    }
    const results = attempt === 2 ? initialResults : changedResults;
    if (results === undefined) throw new Error("changed recommendation fixture is unavailable");
    await fulfillRecommendation(
      route,
      results.run.input_digest,
      results.run.run_id,
    );
  });
  await page.route("**/v1/recommendation-runs/*", async (route) => {
    const runId = decodeURIComponent(new URL(route.request().url()).pathname.split("/").at(-1)!);
    const results = runId === initialResults.run.run_id
      ? initialResults
      : changedResults?.run.run_id === runId
        ? changedResults
        : undefined;
    if (results === undefined) throw new Error(`unknown canonical recommendation run: ${runId}`);
    await fulfillRecommendationResults(route, results);
  });

  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await expect(page.getByRole("heading", { name: "추천을 불러오지 못했어요." })).toBeFocused();
  const uncertainPending = await page.evaluate((key) => {
    const raw = sessionStorage.getItem(key);
    return raw === null ? null : JSON.parse(raw);
  }, PENDING_RECOMMENDATION_KEY);
  expect(uncertainPending).toMatchObject({
    preference_profile_id: initialProfile.profile_id,
    request_id: requests[0]?.request_id,
  });
  await page.getByRole("button", { name: "다시 시도하기" }).click();
  await expect(page).toHaveURL(
    `/recommendations/${encodeURIComponent(initialResults.run.run_id)}`,
  );
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual(requests[0]);
  expect(await page.evaluate((key) => sessionStorage.getItem(key), PENDING_RECOMMENDATION_KEY)).toBeNull();
  expect(
    await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? "null"), CURRENT_RECOMMENDATION_KEY),
  ).toMatchObject({ recommendation_run_id: initialResults.run.run_id });

  await page.reload();
  await page.goBack();
  await page.goForward();
  await page.goBack();
  expect(requests).toHaveLength(2);

  await page.goto("/profile");
  changedProfile = await confirmChangedProfile(page);
  changedResults = recommendationResultsResponse(
    changedProfile.profile_id,
    profileInputSha256(changedProfile),
  );
  expect(changedProfile.profile_id).not.toBe(initialProfile.profile_id);
  expect(profileInputSha256(changedProfile)).not.toBe(profileInputSha256(initialProfile));
  await expect(page.getByRole("button", { name: "바로 추천 보기" })).toBeEnabled();
  expect(await page.evaluate((key) => sessionStorage.getItem(key), PENDING_RECOMMENDATION_KEY)).toBeNull();
  expect(await page.evaluate((key) => sessionStorage.getItem(key), CURRENT_RECOMMENDATION_KEY)).toBeNull();
  await page.getByRole("button", { name: "바로 추천 보기" }).click();
  await expect(page).toHaveURL(
    `/recommendations/${encodeURIComponent(changedResults.run.run_id)}`,
  );

  expect(requests).toHaveLength(3);
  expect(requests[2].request_id).not.toBe(requests[0].request_id);
  expect(requests[2].preference_profile_id).toBe(changedProfile.profile_id);
  expect(requests[2].preference_profile_id).not.toBe(initialProfile.profile_id);
  expect(
    await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key) ?? "null"), CURRENT_RECOMMENDATION_KEY),
  ).toMatchObject({ recommendation_run_id: changedResults.run.run_id });
  await page.reload();
  await page.goBack();
  await page.goForward();
  expect(requests).toHaveLength(3);
});
