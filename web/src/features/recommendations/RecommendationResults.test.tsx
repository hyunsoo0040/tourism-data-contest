import { render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const RED_SENTINEL = "PHASE5_RED_RECOMMENDATION_RESULTS_NOT_IMPLEMENTED";
const SHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CONFIG_SHA = "f94bcaa2b895f9a19e94a5f54ba6af640e9a1226fce03b942ba023e0bd2e9c19";
const RECOVERY_POLICY_SHA = "8cf0d41d64fb987b0ac3c146a5045ef34efe7f12c2a1b3268730bdac97b65300";
const HARD_DUPLICATE_SHA = "32905425be2491414797c0bdc026314de91cdd979abca7cd6d721df3370a8d22";
const CANNOT_COAPPEAR_SHA = "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70";
const ACTIVATION_SUITE_SHA = "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659";
const CONTRAST_SUITE_SHA = "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9";
const CONFIDENCE_REASON = {
  EVIDENCE_AUDIT_ONLY: "확인된 근거가 매우 제한되어 참고 정보로만 보여드려요.",
  EVIDENCE_LIMITED_MISMATCH_SUPPRESSED: "확인된 근거가 제한되어 기대 차이 안내를 생략했어요.",
  EVIDENCE_LIMITED_MISMATCH_AVAILABLE: "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요.",
  EVIDENCE_SUPPORTED: "확인된 근거 범위에서 안내해요.",
} as const;

function currentAuthority(): JsonRecord {
  return {
    recovery_policy_sha256: RECOVERY_POLICY_SHA,
    hard_duplicate_adjudication_sha256: HARD_DUPLICATE_SHA,
    cannot_coappear_authority_sha256: CANNOT_COAPPEAR_SHA,
    activation_suite_sha256: ACTIVATION_SUITE_SHA,
    contrast_suite_sha256: CONTRAST_SUITE_SHA,
  };
}

function currentConfidenceState(confidence: number): keyof typeof CONFIDENCE_REASON {
  if (confidence < 55) return "EVIDENCE_AUDIT_ONLY";
  if (confidence < 65) return "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED";
  if (confidence < 70) return "EVIDENCE_LIMITED_MISMATCH_AVAILABLE";
  return "EVIDENCE_SUPPORTED";
}
const controlledRedOnly = (
  globalThis as typeof globalThis & {
    __vitest_worker__?: { config?: { testNamePattern?: RegExp } };
  }
).__vitest_worker__?.config?.testNamePattern?.source === "controlled RED sentinel";

type JsonRecord = Record<string, unknown>;

function resultItem(rank: number, confidence = rank < 3 ? 64 : rank < 5 ? 69 : 70): JsonRecord {
  const placeId = `place-${rank}`;
  const referenceDate = "2026-08-10";
  const evidenceConfidenceState = currentConfidenceState(confidence);
  const mismatch = confidence < 65
    ? {
        raw_score: 30,
        effective_score: 30,
        axis_distance: 30,
        trait_distance: 30,
        important_trait_floor_applied: false,
        state: "SUPPRESSED_LOW_CONFIDENCE",
        template_id: null,
        message_ko: null,
        suppression_reason: "CONFIDENCE_BELOW_65",
      }
    : {
        raw_score: 30,
        effective_score: 30,
        axis_distance: 30,
        trait_distance: 30,
        important_trait_floor_applied: false,
        state: "GENTLE_DIFFERENCE",
        template_id: "mismatch-gentle-v1",
        message_ko: "한 가지 차이를 확인해 보세요.",
        suppression_reason: null,
      };
  const mismatchForDecodedItem = mismatch;
  const axisScores = [
    { axis: "HISTORY_TRADITION", value: 70 + rank, evidence_ids: [`evidence-${rank}-h`] },
    { axis: "EMOTION_IMAGE", value: 60 + rank, evidence_ids: [`evidence-${rank}-e`] },
    { axis: "REST_IMMERSION", value: 50 + rank, evidence_ids: [`evidence-${rank}-r`] },
  ];
  const axisComponents = [
    ["HISTORY_TRADITION", 80, 70 + rank, "h"],
    ["EMOTION_IMAGE", 75, 60 + rank, "e"],
    ["REST_IMMERSION", 65, 50 + rank, "r"],
  ].map(([axis, expected, place, suffix]) => {
    const absoluteDifference = Math.abs(Number(expected) - Number(place));
    return {
      contribution_id: `contribution-${rank}-${suffix}`,
      axis,
      expected_value: expected,
      place_value: place,
      absolute_difference: absoluteDifference,
      fit_score: 100 - absoluteDifference,
    };
  });
  const experienceFitScore = Math.floor(
    (axisComponents.reduce((total, component) => total + component.fit_score, 0) + 1) / 3,
  );
  const conditionWeights = [400, 350, 350, 350, 300, 250];
  const conditionComponents = [
    "VISIT_DATE_TIME",
    "COMPANIONS",
    "TRANSPORT",
    "WALKING",
    "INDOOR_OUTDOOR",
    "CROWD",
  ].map((condition_id, index) => ({
    contribution_id: `contribution-${rank}-condition-${index}`,
    condition_id,
    expected_value: 50,
    place_value: 50,
    absolute_difference: 0,
    fit_score: 100,
    total_score_weight_bp: conditionWeights[index],
    weighted_numerator: 100 * conditionWeights[index],
  }));
  const travelConditionFitScore = Math.floor(
    (conditionComponents.reduce((total, component) => total + component.weighted_numerator, 0) +
      1_000) /
      2_000,
  );
  const relevanceNumerator = experienceFitScore * 8_000 + travelConditionFitScore * 2_000;
  const relevanceScore = Math.floor((relevanceNumerator + 5_000) / 10_000);
  const rerankNumerator = relevanceScore * 8_500 + 50 * 1_500;
  const contribution = {
    axis_components: axisComponents,
    condition_components: conditionComponents,
    experience_fit_score: experienceFitScore,
    travel_condition_fit_score: travelConditionFitScore,
    relevance_score: relevanceScore,
    relevance_numerator: relevanceNumerator,
    diversity_novelty_score: 50,
    rerank_score: Math.floor((rerankNumerator + 5_000) / 10_000),
    rerank_numerator: rerankNumerator,
  };
  return {
    rank,
    place_id: placeId,
    place_name_ko: `경주 장소 ${rank}`,
    fit_score: relevanceScore,
    evidence_confidence_state: evidenceConfidenceState,
    evidence_confidence_reason_ko: CONFIDENCE_REASON[evidenceConfidenceState],
    mismatch: mismatchForDecodedItem,
    confidence_percent: confidence,
    contribution,
    axis_scores: axisScores,
    evidence: axisScores.slice(0, 2).map((axis) => ({
      evidence_id: axis.evidence_ids[0],
      excerpt_ko: `경주 장소 ${rank}의 근거 발췌입니다.`,
      source_label_ko: "한국관광공사 TourAPI 공식 관광정보",
      attribution_ko: "출처: 한국관광공사 TourAPI",
      contest_use_scope: "noncommercial_contest_demo_evaluation",
      contest_rights_qualified: true,
      reference_date: referenceDate,
    })),
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
}

function mvpEvidence(
  evidenceId: string,
  referenceDate: string,
): JsonRecord {
  return {
    schema_version: "mvp-evidence-snippet.v1",
    evidence_id: evidenceId,
    excerpt_ko: `${evidenceId}의 엄격 공개 근거입니다.`,
    source_label_ko: "한국관광공사 TourAPI 공식 관광정보",
    attribution_ko: "출처: 한국관광공사 TourAPI",
    reference_date: referenceDate,
    provider: "TOUR_API",
    official_dataset_id: "15101578",
    official_license_url: "https://www.data.go.kr/data/15101578/openapi.do",
    license_type: "공공데이터 이용허락범위 제한 없음",
    source_response_sha256: SHA.replaceAll("0", "6"),
    permission_metadata_sha256: SHA.replaceAll("0", "7"),
    evidence_sha256: SHA.replaceAll("0", "8"),
    usage_state: "STRICT_PUBLIC_USAGE_ALLOWED",
  };
}

function mvpResultItem(rank: number): JsonRecord {
  const confidence = rank === 1 ? 54 : rank === 2 ? 64 : rank === 3 ? 69 : 70;
  const { confidence_percent: _confidence, ...item } = resultItem(rank, confidence);
  const placeId = `place-${String(rank).padStart(3, "0")}`;
  const evidence = [
    mvpEvidence(`evidence-${rank}-h`, "2026-08-09"),
    mvpEvidence(`evidence-${rank}-e`, "2026-08-10"),
  ];
  return {
    ...item,
    place_id: placeId,
    evidence,
    explanations: (item.explanations as JsonRecord[]).map((row, index) => ({
      ...row,
      reference_date: evidence[index]!.reference_date,
    })),
    reference_date: "2026-08-10",
  };
}

async function mvpRecommendationResults(): Promise<JsonRecord> {
  const items = [1, 2, 3, 4, 5].map(mvpResultItem);
  const authority = {
    release_sha256: SHA.replaceAll("0", "2"),
    membership_sha256: SHA.replaceAll("0", "3"),
    relation_sha256: SHA.replaceAll("0", "4"),
    candidate_sha256: SHA.replaceAll("0", "5"),
    config_sha256: CONFIG_SHA,
    kernel_version: "recommendation-kernel-v3",
  };
  const preference = {
    profile_id: "profile-current",
    input_sha256: SHA,
    axis_targets: ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"].map(
      (axis, index) => ({ axis, value: 70 - index * 5 }),
    ),
    condition_targets: [
      "VISIT_DATE_TIME",
      "COMPANIONS",
      "TRANSPORT",
      "WALKING",
      "INDOOR_OUTDOOR",
      "CROWD",
    ].map((condition_id) => ({ condition_id, value: 50 })),
    trait_targets: ["M1", "M2", "M3", "M4", "M5", "M6"].map(
      (trait_id, index) => ({ trait_id, value: 40 + index, important: index === 0 }),
    ),
  };
  const run: JsonRecord = {
    schema_version: "recommendation-run.v2",
    run_id: "recommendation-run:pending",
    input_digest: await sha256Canonical({ preference, authority }),
    preference,
    authority,
    candidate_place_ids: Array.from(
      { length: 80 },
      (_, index) => `place-${String(index + 1).padStart(3, "0")}`,
    ),
    items,
    created_at: "2026-08-10T12:00:00Z",
    canonical_sha256: SHA,
  };
  const payload: JsonRecord = {
    schema_version: "itda.recommendation-results.v2",
    preference_profile_id: "profile-current",
    analysis_origin: "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
    operating_states: items.map((item) => ({
      place_id: item.place_id,
      state: "OPERATING_INFORMATION_UNVERIFIED",
    })),
    release_disclosure: {
      analysis_origin: "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
      model: "glm-5.3-flash",
      prompt_schema_version: "mvp-place-scoring-request.v2",
      profile_schema_version: "mvp-scored-release.v1",
      config_sha256: CONFIG_SHA,
      source_bundle_sha256: SHA.replaceAll("0", "9"),
      release_sha256: authority.release_sha256,
      reference_date: "2026-08-10",
    },
    run,
  };
  await sealMvpRecommendationResults(payload);
  return payload;
}

async function photoRecommendationResults(): Promise<JsonRecord> {
  const payload = await mvpRecommendationResults();
  const run = payload.run as JsonRecord;
  const authority = run.authority as JsonRecord;
  Object.assign(authority, {
    photo_projection_version: "photo-projection-v1",
    photo_projection_policy_sha256: "a".repeat(64),
    photo_projection_output_sha256: "b".repeat(64),
    confirmation_draft_sha256: "c".repeat(64),
    photo_job_reference_sha256: "d".repeat(64),
    images_count: 2,
    included_count: 3,
  });
  const items = run.items as JsonRecord[];
  run.schema_version = "recommendation-run.v3";
  run.photo_scores = items.map((item, index) => {
    const baseRelevance = Number((item.contribution as JsonRecord).relevance_score);
    const traitComponents = ["M1", "M2", "M3", "M4", "M5", "M6"].map(
      (trait_id, traitIndex) => {
        const expected = 40 + traitIndex;
        const actual = 50 + index;
        return {
          trait_id,
          expected,
          actual,
          fit: 100 - Math.abs(expected - actual),
        };
      },
    );
    const photoTraitFit = Math.floor(
      (traitComponents.reduce((sum, row) => sum + row.fit, 0) * 2 + 6) / 12,
    );
    const effectiveRelevance = Math.floor(
      (2 * (baseRelevance * 6_500 + photoTraitFit * 3_500) + 10_000) / 20_000,
    );
    item.fit_score = effectiveRelevance;
    return {
      base_relevance: baseRelevance,
      trait_components: traitComponents,
      photo_trait_fit: photoTraitFit,
      effective_relevance: effectiveRelevance,
      explanation_ko: `사진에서 확인한 분위기가 경주 장소 ${index + 1}과 이어져요.`,
    };
  });
  await sealMvpRecommendationResults(payload);
  return payload;
}

async function sha256Canonical(value: unknown): Promise<string> {
  const digestBytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalJson(value)),
  );
  return Array.from(new Uint8Array(digestBytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function sealMvpRecommendationResults(payload: JsonRecord): Promise<void> {
  const run = payload.run as JsonRecord;
  run.input_digest = await sha256Canonical({
    preference: run.preference,
    authority: run.authority,
  });
  const deterministic = Object.fromEntries(
    Object.entries(run).filter(
      ([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key),
    ),
  );
  const digest = await sha256Canonical(deterministic);
  run.canonical_sha256 = digest;
  run.run_id = `recommendation-run:${digest.slice(0, 32)}`;
}

function photoDetail(payload: JsonRecord, itemIndex = 0): JsonRecord {
  const run = payload.run as JsonRecord;
  const items = run.items as JsonRecord[];
  const item = items[itemIndex]!;
  const rank = Number(item.rank);
  return {
    run_id: run.run_id,
    release_sha256: (run.authority as JsonRecord).release_sha256,
    confidence_percent: rank === 1 ? 54 : rank === 2 ? 64 : rank === 3 ? 69 : 70,
    evidence_confidence_state: item.evidence_confidence_state,
    evidence_confidence_reason_ko: item.evidence_confidence_reason_ko,
    item,
    mismatch_traits: ["M1", "M2", "M3", "M4", "M5", "M6"].map(
      (trait_id, index) => ({
        trait_id,
        value: 40 + index,
        evidence_ids: [`evidence-${rank}-${index % 2 === 0 ? "h" : "e"}`],
      }),
    ),
    evidence: [
      ...(item.evidence as JsonRecord[]),
      mvpEvidence(`evidence-${rank}-r`, "2026-08-10"),
    ],
    operating_state: "OPERATING_INFORMATION_UNVERIFIED",
    similar_place_ids: items
      .filter((candidate) => candidate.place_id !== item.place_id)
      .slice(0, 3)
      .map((candidate) => candidate.place_id),
  };
}

function photoComparison(payload: JsonRecord, placeIds: string[]): JsonRecord {
  const run = payload.run as JsonRecord;
  const row = (row_id: string, label_ko: string, value: string) => ({
    row_id,
    label_ko,
    values_ko: placeIds.map(() => value),
    missing_reasons: placeIds.map(() => null),
  });
  return {
    schema_version: "recommendation-comparison-v1",
    run_id: run.run_id,
    release_sha256: (run.authority as JsonRecord).release_sha256,
    place_ids: placeIds,
    rows: [
      row("fit-score", "추천 적합도", "88"),
      row("axis-history_tradition", "역사·전통", "80점 / 100점"),
      row("axis-emotion_image", "감성·이미지", "70점 / 100점"),
      row("axis-rest_immersion", "휴식·몰입", "60점 / 100점"),
      row("evidence-reason-1", "잘 맞는 이유 1", "역사 근거가 이번 기대와 이어져요."),
      row("evidence-reason-2", "잘 맞는 이유 2", "감성 근거가 이번 기대와 이어져요."),
      row("mismatch-guidance", "이번 여행에서 기대한 것과 다른 점", "한 가지 차이를 확인해 보세요."),
      row("trait-m1", "공간 성격", "41점 / 100점"),
      row("trait-m2", "방문객 성격", "42점 / 100점"),
      row("trait-m3", "현장 밀도", "43점 / 100점"),
      row("trait-m4", "경험 방식", "44점 / 100점"),
      row("trait-m5", "체류 방식", "45점 / 100점"),
      row("trait-m6", "시간 의존성", "46점 / 100점"),
      row("time-season-context", "시간·계절 맥락", "저장된 시간 의존성은 46점 / 100점이에요."),
      {
        row_id: "operating-state",
        label_ko: "운영 정보",
        values_ko: placeIds.map(() => "정보 없음"),
        missing_reasons: placeIds.map(() => "OPERATING_INFORMATION_UNVERIFIED"),
      },
      row("media-state", "대표 이미지 상태", "대표 이미지 없음"),
      row("reference-date", "데이터 기준일", "2026-08-10"),
    ],
  };
}

function unsealedRecommendationResults(): JsonRecord {
  const items = [1, 2, 3, 4, 5].map((rank) => resultItem(rank));
  const excludedPlaceId = "place-0";
  const scoredCandidates = items.map((item) => {
    const contribution = item.contribution as JsonRecord;
    return {
      place_id: item.place_id,
      relevance_score: contribution.relevance_score,
      experience_fit_score: contribution.experience_fit_score,
      travel_condition_fit_score: contribution.travel_condition_fit_score,
      contribution,
      mismatch: item.mismatch,
    };
  });
  const diversitySteps = items.map((item, index) => {
    const contribution = item.contribution as JsonRecord;
    return {
      rank: item.rank,
      selected_place_id: item.place_id,
      relevance_score: contribution.relevance_score,
      novelty_score: contribution.diversity_novelty_score,
      combined_score: contribution.rerank_score,
      considered: items.slice(index).map((remaining) => {
        const remainingContribution = remaining.contribution as JsonRecord;
        return {
          place_id: remaining.place_id,
          relevance_score: remainingContribution.relevance_score,
          novelty_score: remainingContribution.diversity_novelty_score,
          combined_score: remainingContribution.rerank_score,
        };
      }),
    };
  });
  return {
    schema_version: "itda.recommendation-results.v1",
    preference_profile_id: "profile-current",
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
      schema_version: "recommendation-run.v1",
      run_id: "recommendation-run:current",
      input_digest: SHA,
      release_sha256: SHA.replaceAll("0", "2"),
      canonical_membership_sha256: SHA.replaceAll("0", "3"),
      config_sha256: CONFIG_SHA,
      kernel_version: "recommendation-kernel-v3",
      authority: currentAuthority(),
      candidate_set_digest: SHA.replaceAll("0", "4"),
      candidate_place_ids: [excludedPlaceId, ...items.map((item) => item.place_id)],
      exclusions: [
        { place_id: excludedPlaceId, reason: "NOT_RECOMMENDATION_ELIGIBLE" },
      ],
      duplicate_decisions: [
        {
          duplicate_group_id: "duplicate-group-1",
          kept_place_id: "place-1",
          suppressed_place_ids: [excludedPlaceId],
        },
      ],
      scored_candidates: scoredCandidates,
      diversity_steps: diversitySteps,
      items: items.map(({ confidence_percent: _confidence, ...item }) => item),
      ndcg_status: "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS",
      ndcg_denominator: 0,
      created_at: "2026-08-10T12:00:00Z",
      canonical_sha256: SHA.replaceAll("0", "5"),
    },
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as JsonRecord;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function sealRecommendationResults(payload: JsonRecord): Promise<JsonRecord> {
  const run = payload.run as JsonRecord;
  const deterministic = Object.fromEntries(
    Object.entries(run).filter(
      ([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key),
    ),
  );
  const digestBytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalJson(deterministic)),
  );
  const digest = Array.from(new Uint8Array(digestBytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  run.canonical_sha256 = digest;
  run.run_id = `recommendation-run:${digest.slice(0, 32)}`;
  return payload;
}

const SEALED_RESULTS = await sealRecommendationResults(unsealedRecommendationResults());
const RECOMMENDATION_RUN_ID = (SEALED_RESULTS.run as JsonRecord).run_id as string;

function recommendationResults(overrides: JsonRecord = {}): JsonRecord {
  return { ...structuredClone(SEALED_RESULTS), ...overrides };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function renderResults(fetchImpl: typeof fetch, runId = RECOMMENDATION_RUN_ID) {
  vi.stubGlobal("fetch", fetchImpl);
  const modulePath = "../../journey-pages/RecommendationsJourneyPage";
  const { RecommendationsPage } = await import(/* @vite-ignore */ modulePath);
  const router = createMemoryRouter(
    [{ path: "/recommendations/:runId", element: <RecommendationsPage /> }],
    { initialEntries: [`/recommendations/${encodeURIComponent(runId)}`] },
  );
  render(<RouterProvider router={router} />);
  return router;
}

if (controlledRedOnly) {
  it("controlled RED sentinel", () => {
    process.stdout.write(`${RED_SENTINEL}\n`);
    throw new Error(RED_SENTINEL);
  });
}

if (!controlledRedOnly) {
describe("generated recommendation decoding", () => {
  it("accepts only generated exact-five DEMO_MODEL_DERIVED results", async () => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(recommendationResults()));

    const result = await api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, {
      fetchImpl,
    });

    expect(result.run.items.map((item: JsonRecord) => item.rank)).toEqual([1, 2, 3, 4, 5]);
    expect(result.analysis_origin).toBe("DEMO_MODEL_DERIVED");
    expect(fetchImpl).toHaveBeenCalledWith(
      `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}`,
      expect.objectContaining({ signal: undefined }),
    );
  });

  it("accepts an exact v2 result receipt with mixed evidence dates", async () => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = await mvpRecommendationResults();
    const runId = String((payload.run as JsonRecord).run_id);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(runId, { fetchImpl }),
    ).resolves.toMatchObject({
      schema_version: "itda.recommendation-results.v2",
      analysis_origin: "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
      run: { schema_version: "recommendation-run.v2" },
    });
  });

  it("accepts v3 and renders only server-authoritative photo provenance and explanations", async () => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = await photoRecommendationResults();
    const runId = String((payload.run as JsonRecord).run_id);
    const fetchImpl = vi.fn().mockImplementation(
      () => Promise.resolve(jsonResponse(payload)),
    );

    await expect(
      api.fetchRecommendationResults(runId, { fetchImpl }),
    ).resolves.toMatchObject({ run: { schema_version: "recommendation-run.v3" } });
    await renderResults(fetchImpl, runId);

    expect(await screen.findByText("사진 취향을 반영한 경주 여행지")).toBeTruthy();
    expect(
      screen.getByText("직접 확인한 사진 취향을 기대 프로필에 반영해 고른 경주 여행지예요."),
    ).toBeTruthy();
    expect(screen.getAllByText(/사진에서 확인한 분위기가 경주 장소/)).toHaveLength(5);
  });

  it("renders the pinned server photo explanation on the v3 detail page", async () => {
    const payload = await photoRecommendationResults();
    const run = payload.run as JsonRecord;
    const runId = String(run.run_id);
    const item = (run.items as JsonRecord[])[0]!;
    const detail = photoDetail(payload);
    const fetchImpl = vi.fn(async (request: RequestInfo | URL) =>
      String(request).includes("/places/")
        ? jsonResponse(detail)
        : jsonResponse(payload),
    );
    vi.stubGlobal("fetch", fetchImpl);
    const modulePath = "../../journey-pages/PlaceDetailJourneyPage";
    const { PlaceDetailPage } = await import(/* @vite-ignore */ modulePath);
    const router = createMemoryRouter(
      [{ path: "/recommendations/:runId/places/:placeId", element: <PlaceDetailPage /> }],
      {
        initialEntries: [
          `/recommendations/${encodeURIComponent(runId)}/places/${item.place_id}`,
        ],
      },
    );
    render(<RouterProvider router={router} />);

    expect(await screen.findByRole("heading", { name: item.place_name_ko as string })).toBeTruthy();
    expect(
      screen
        .getByText("사진에서 확인한 분위기가 경주 장소 1과 이어져요.")
        .getAttribute("data-photo-recommendation-explanation"),
    ).not.toBeNull();
  });

  it("renders each selected server photo explanation on the v3 compare page", async () => {
    window.localStorage.clear();
    const payload = await photoRecommendationResults();
    const run = payload.run as JsonRecord;
    const runId = String(run.run_id);
    const placeIds = (run.items as JsonRecord[])
      .slice(0, 2)
      .map((item) => String(item.place_id));
    const releaseSha256 = String((run.authority as JsonRecord).release_sha256);
    const storage = await import("../../app/storage");
    storage.writeCompareSelection({ runId, releaseSha256, placeIds });
    const comparison = photoComparison(payload, placeIds);
    const fetchImpl = vi.fn(async (request: RequestInfo | URL) =>
      String(request).includes("/comparison?")
        ? jsonResponse(comparison)
        : jsonResponse(payload),
    );
    vi.stubGlobal("fetch", fetchImpl);
    const modulePath = "../../journey-pages/CompareJourneyPage";
    const { ComparePage } = await import(/* @vite-ignore */ modulePath);
    const router = createMemoryRouter(
      [{ path: "/recommendations/:runId/compare", element: <ComparePage /> }],
      { initialEntries: [`/recommendations/${encodeURIComponent(runId)}/compare`] },
    );
    render(<RouterProvider router={router} />);

    expect(await screen.findByRole("heading", { name: "선택한 장소 비교" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "사진 취향 반영 이유" })).toBeTruthy();
    const explanations = document.querySelectorAll("[data-photo-recommendation-explanation]");
    expect(explanations).toHaveLength(2);
    expect(explanations[0]?.textContent).toContain("경주 장소 1");
    expect(explanations[0]?.textContent).toContain("사진에서 확인한 분위기가 경주 장소 1과 이어져요.");
    expect(explanations[1]?.textContent).toContain("경주 장소 2");
    expect(explanations[1]?.textContent).toContain("사진에서 확인한 분위기가 경주 장소 2과 이어져요.");
  });

  it.each([
    ["base relevance", (payload: JsonRecord) => {
      const score = (((payload.run as JsonRecord).photo_scores as JsonRecord[])[0]!);
      score.base_relevance = Number(score.base_relevance) - 1;
    }],
    ["effective relevance", (payload: JsonRecord) => {
      const score = (((payload.run as JsonRecord).photo_scores as JsonRecord[])[0]!);
      score.effective_relevance = Number(score.effective_relevance) - 1;
    }],
    ["trait arithmetic", (payload: JsonRecord) => {
      const score = (((payload.run as JsonRecord).photo_scores as JsonRecord[])[0]!);
      ((score.trait_components as JsonRecord[])[0]!).fit = 0;
    }],
  ])("rejects v3 %s tampering after coherent resealing", async (_label, mutate) => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = await photoRecommendationResults();
    mutate(payload);
    await sealMvpRecommendationResults(payload);
    const runId = String((payload.run as JsonRecord).run_id);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(runId, { fetchImpl }),
    ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  const mvpResultMutations: Array<[
    string,
    (payload: JsonRecord) => void,
    boolean,
  ]> = [
    ["extra result field", (payload) => {
      payload.unexpected = true;
    }, false],
    ["extra authority field", (payload) => {
      ((payload.run as JsonRecord).authority as JsonRecord).unexpected = true;
    }, true],
    ["missing preference field", (payload) => {
      delete (((payload.run as JsonRecord).preference as JsonRecord).input_sha256);
    }, true],
    ["preference axis order", (payload) => {
      const preference = (payload.run as JsonRecord).preference as JsonRecord;
      (preference.axis_targets as JsonRecord[]).reverse();
    }, true],
    ["candidate order", (payload) => {
      ((payload.run as JsonRecord).candidate_place_ids as string[]).reverse();
    }, true],
    ["duplicate candidate", (payload) => {
      const candidates = (payload.run as JsonRecord).candidate_place_ids as string[];
      candidates[1] = candidates[0]!;
    }, true],
    ["extra item field", (payload) => {
      (((payload.run as JsonRecord).items as JsonRecord[])[0]!).confidence_percent = 54;
    }, true],
    ["mismatch arithmetic", (payload) => {
      const item = ((payload.run as JsonRecord).items as JsonRecord[])[0]!;
      (item.mismatch as JsonRecord).effective_score = 31;
    }, true],
    ["contribution arithmetic", (payload) => {
      const item = ((payload.run as JsonRecord).items as JsonRecord[])[0]!;
      (item.contribution as JsonRecord).rerank_numerator = 1;
    }, true],
    ["axis order", (payload) => {
      const item = ((payload.run as JsonRecord).items as JsonRecord[])[0]!;
      (item.axis_scores as JsonRecord[]).reverse();
    }, true],
    ["explanation reference date", (payload) => {
      const item = ((payload.run as JsonRecord).items as JsonRecord[])[0]!;
      (item.explanations as JsonRecord[])[0]!.reference_date = "2026-08-10";
    }, true],
    ["disclosure authority mismatch", (payload) => {
      (payload.release_disclosure as JsonRecord).release_sha256 = "f".repeat(64);
    }, false],
    ["operating state order", (payload) => {
      (payload.operating_states as JsonRecord[]).reverse();
    }, false],
    ["stale input digest", (payload) => {
      (payload.run as JsonRecord).input_digest = "f".repeat(64);
    }, false],
    ["stale canonical digest", (payload) => {
      (payload.run as JsonRecord).canonical_sha256 = "f".repeat(64);
    }, false],
  ];

  it.each(mvpResultMutations)(
    "rejects v2 result %s tampering",
    async (_label, mutate, reseal) => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = await mvpRecommendationResults();
      mutate(payload);
      if (reseal) await sealMvpRecommendationResults(payload);
      const runId = String((payload.run as JsonRecord).run_id);
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationResults(runId, { fetchImpl }),
      ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
    },
  );

  it("accepts the current NVIDIA v4 disclosure contract", async () => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = recommendationResults({
      release_disclosure: {
        ...(recommendationResults().release_disclosure as JsonRecord),
        model: "minimaxai/minimax-m3",
        prompt_schema_version: "phase5-demo-profile-sentinel-json.v4",
        profile_schema_version: "itda.nvidia-minimax-model-derived-profile.v4",
      },
    });
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, { fetchImpl }),
    ).resolves.toMatchObject({ analysis_origin: "DEMO_MODEL_DERIVED" });
  });

  it("accepts detail-only numeric confidence with the matching bounded state and reason", async () => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const { confidence_percent: _confidence, ...detailItem } = resultItem(1, 55);
    const detailEvidence = [
      ...(detailItem.evidence as JsonRecord[]),
      {
        ...((detailItem.evidence as JsonRecord[])[0] as JsonRecord),
        evidence_id: "evidence-1-r",
      },
    ];
    const detailPayload = {
      run_id: RECOMMENDATION_RUN_ID,
      release_sha256: String((SEALED_RESULTS.run as JsonRecord).release_sha256),
      confidence_percent: 55,
      evidence_confidence_state: "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED",
      evidence_confidence_reason_ko: CONFIDENCE_REASON.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED,
      item: detailItem,
      mismatch_traits: ["M1", "M2", "M3", "M4", "M5", "M6"].map((trait_id) => ({
        trait_id,
        value: 50,
        evidence_ids: [(detailItem.evidence as JsonRecord[])[0]!.evidence_id],
      })),
      evidence: detailEvidence,
      operating_state: "OPERATING_INFORMATION_UNVERIFIED",
      similar_place_ids: [],
    };
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(detailPayload));

    await expect(
      api.fetchRecommendationDetail(RECOMMENDATION_RUN_ID, "place-1", { fetchImpl }),
    ).resolves.toMatchObject({
      confidence_percent: 55,
      evidence_confidence_state: "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED",
    });
  });

  const itemMutations: Array<[string, (item: JsonRecord) => void]> = [
    ["unknown contribution", (item: JsonRecord) => {
      const explanation = (item.explanations as JsonRecord[])[0]!;
      explanation.contribution_id = "contribution-unknown";
    }],
    ["cross-axis evidence", (item: JsonRecord) => {
      const explanation = (item.explanations as JsonRecord[])[0]!;
      explanation.evidence_id = `evidence-${item.rank}-e`;
    }],
    ["duplicate explanation binding", (item: JsonRecord) => {
      const explanations = item.explanations as JsonRecord[];
      explanations[1] = { ...explanations[0], message_ko: "중복 바인딩" };
    }],
    ["rerank arithmetic", (item: JsonRecord) => {
      const contribution = item.contribution as JsonRecord;
      contribution.rerank_numerator =
        Number(contribution.rerank_numerator) + 1;
    }],
    ["mismatch arithmetic", (item: JsonRecord) => {
      const mismatch = item.mismatch as JsonRecord;
      mismatch.effective_score = Number(mismatch.effective_score) + 1;
    }],
    ["zero-weight condition numerator", (item: JsonRecord) => {
      const contribution = item.contribution as JsonRecord;
      const conditions = contribution.condition_components as JsonRecord[];
      conditions[0]!.weighted_numerator = 1;
    }],
  ];

  it.each(itemMutations)("rejects %s in the item explanation contract", async (_label, mutate) => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = recommendationResults();
    const items = (payload.run as JsonRecord).items;
    mutate(items instanceof Array
      ? (items[0] as JsonRecord)
      : {});
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, { fetchImpl }),
    ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  const runTraceMutations: Array<[string, (run: JsonRecord) => void]> = [
    ["incomplete candidate score row", (run) => {
      const scored = run.scored_candidates as JsonRecord[];
      scored[0] = { place_id: scored[0]!.place_id };
    }],
    ["incomplete diversity step", (run) => {
      const steps = run.diversity_steps as JsonRecord[];
      steps[0] = { rank: steps[0]!.rank, selected_place_id: steps[0]!.selected_place_id };
    }],
    ["duplicate scored candidate partition", (run) => {
      const scored = run.scored_candidates as JsonRecord[];
      scored[1]!.place_id = scored[0]!.place_id;
    }],
    ["unknown exclusion reason", (run) => {
      const exclusions = run.exclusions as JsonRecord[];
      exclusions[0]!.reason = "UNKNOWN_REASON";
    }],
    ["empty duplicate suppression", (run) => {
      const decisions = run.duplicate_decisions as JsonRecord[];
      decisions[0]!.suppressed_place_ids = [];
    }],
    ["item fit score drift from candidate trace", (run) => {
      const items = run.items as JsonRecord[];
      items[0]!.fit_score = Number(items[0]!.fit_score) + 1;
    }],
    ["diversity selection order drift", (run) => {
      const steps = run.diversity_steps as JsonRecord[];
      steps[0]!.selected_place_id = "place-2";
    }],
  ];

  it.each(runTraceMutations)("rejects %s in the run receipt", async (_label, mutate) => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = recommendationResults();
    mutate((payload.run as JsonRecord));
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, { fetchImpl }),
    ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  const runIntegrityMutations: Array<[
    string,
    (run: JsonRecord) => string,
  ]> = [
    ["stale canonical digest", (run) => {
      run.canonical_sha256 = "f".repeat(64);
      return String(run.run_id);
    }],
    ["unbound run identity", (run) => {
      run.run_id = "recommendation-run:unbound";
      return String(run.run_id);
    }],
    ["non-UTC creation time", (run) => {
      run.created_at = "2026-08-10T21:00:00+09:00";
      return String(run.run_id);
    }],
  ];

  it.each(runIntegrityMutations)("rejects %s in the run integrity receipt", async (_label, mutate) => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const payload = recommendationResults();
    const expectedRunId = mutate(payload.run as JsonRecord);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(expectedRunId, { fetchImpl }),
    ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each(["2026-08-10T12:00:00z", "2026-08-10T12:00:00+0000", "2026-08-10T12:00:00-00:00"])(
    "accepts backend-valid effective UTC timestamp %s",
    async (createdAt) => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = recommendationResults();
      (payload.run as JsonRecord).created_at = createdAt;
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, { fetchImpl }),
      ).resolves.toMatchObject({ analysis_origin: "DEMO_MODEL_DERIVED" });
    },
  );

  const backendContractMutations: Array<[
    string,
    (payload: JsonRecord) => void,
  ]> = [
    ["impossible calendar date", (payload) => {
      const run = payload.run as JsonRecord;
      for (const item of run.items as JsonRecord[]) {
        item.reference_date = "2026-02-30";
        for (const evidence of item.evidence as JsonRecord[]) {
          evidence.reference_date = "2026-02-30";
        }
        for (const explanation of item.explanations as JsonRecord[]) {
          explanation.reference_date = "2026-02-30";
        }
      }
      (payload.release_disclosure as JsonRecord).reference_date = "2026-02-30";
    }],
    ["impossible UTC timestamp", (payload) => {
      (payload.run as JsonRecord).created_at = "2026-02-30T12:00:00Z";
    }],
    ["kernel version", (payload) => {
      (payload.run as JsonRecord).kernel_version = "INVALID VERSION";
    }],
    ["nine axis evidence ids", (payload) => {
      const run = payload.run as JsonRecord;
      const item = (run.items as JsonRecord[])[0]!;
      const axis = (item.axis_scores as JsonRecord[])[0]!;
      axis.evidence_ids = [
        ...(axis.evidence_ids as string[]),
        ...Array.from({ length: 8 }, (_, index) => `extra-evidence-${index + 1}`),
      ];
    }],
  ];

  it.each(backendContractMutations)(
    "rejects backend-invalid %s after coherent resealing",
    async (_label, mutate) => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = recommendationResults();
      mutate(payload);
      await sealRecommendationResults(payload);
      const expectedRunId = String((payload.run as JsonRecord).run_id);
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationResults(expectedRunId, { fetchImpl }),
      ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
    },
  );

  const backendContractBoundaryNeighbors: Array<[
    string,
    (payload: JsonRecord) => void,
  ]> = [
    ["leap-day reference date", (payload) => {
      const run = payload.run as JsonRecord;
      for (const item of run.items as JsonRecord[]) {
        item.reference_date = "2024-02-29";
        for (const evidence of item.evidence as JsonRecord[]) {
          evidence.reference_date = "2024-02-29";
        }
        for (const explanation of item.explanations as JsonRecord[]) {
          explanation.reference_date = "2024-02-29";
        }
      }
      (payload.release_disclosure as JsonRecord).reference_date = "2024-02-29";
    }],
    ["latest UTC time", (payload) => {
      (payload.run as JsonRecord).created_at = "2024-02-29T23:59:59.999999+0000";
    }],
    ["eight axis evidence ids", (payload) => {
      const run = payload.run as JsonRecord;
      const firstItem = (run.items as JsonRecord[])[0]!;
      const firstAxis = (firstItem.axis_scores as JsonRecord[])[0]!;
      const evidenceId = String((firstAxis.evidence_ids as string[])[0]);
      firstAxis.evidence_ids = Array.from({ length: 8 }, () => evidenceId);
    }],
  ];

  it.each(backendContractBoundaryNeighbors)(
    "accepts valid backend contract boundary neighbor: %s",
    async (_label, mutate) => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = recommendationResults();
      mutate(payload);
      await sealRecommendationResults(payload);
      const expectedRunId = String((payload.run as JsonRecord).run_id);
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationResults(expectedRunId, { fetchImpl }),
      ).resolves.toMatchObject({ analysis_origin: "DEMO_MODEL_DERIVED" });
    },
  );

  it.each([
    [
      "unsupported origin",
      recommendationResults({ analysis_origin: "SYNTHETIC" }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "incomplete Top 5",
      recommendationResults({
        run: {
          ...(recommendationResults().run as JsonRecord),
          items: (recommendationResults().run as JsonRecord).items instanceof Array
            ? ((recommendationResults().run as JsonRecord).items as unknown[]).slice(0, 4)
            : [],
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "cross-run response",
      recommendationResults({
        run: {
          ...(recommendationResults().run as JsonRecord),
          run_id: "recommendation-run:other",
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "cross-config disclosure",
      recommendationResults({
        release_disclosure: {
          ...(recommendationResults().release_disclosure as JsonRecord),
          config_sha256: "f".repeat(64),
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "stale disclosure date",
      recommendationResults({
        release_disclosure: {
          ...(recommendationResults().release_disclosure as JsonRecord),
          reference_date: "2026-08-09",
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "legacy NVIDIA v3 disclosure",
      recommendationResults({
        release_disclosure: {
          ...(recommendationResults().release_disclosure as JsonRecord),
          model: "minimaxai/minimax-m3",
          prompt_schema_version: "phase5-demo-profile-sentinel-json.v3",
          profile_schema_version: "itda.nvidia-minimax-model-derived-profile.v3",
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "MiniMax model crossed with GLM schemas",
      recommendationResults({
        release_disclosure: {
          ...(recommendationResults().release_disclosure as JsonRecord),
          model: "minimaxai/minimax-m3",
          prompt_schema_version: "phase5-demo-profile.v1",
          profile_schema_version: "itda.demo-model-derived-profile.v1",
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
    [
      "GLM model crossed with MiniMax schemas",
      recommendationResults({
        release_disclosure: {
          ...(recommendationResults().release_disclosure as JsonRecord),
          model: "glm-5v-turbo",
          prompt_schema_version: "phase5-demo-profile-sentinel-json.v4",
          profile_schema_version: "itda.nvidia-minimax-model-derived-profile.v4",
        },
      }),
      "INVALID_RECOMMENDATION_OUTPUT",
    ],
  ])("rejects %s without exposing cards", async (_label, payload, expectedCode) => {
    const apiPath = "../../api/api";
    const api = await import(/* @vite-ignore */ apiPath);
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

    await expect(
      api.fetchRecommendationResults(RECOMMENDATION_RUN_ID, { fetchImpl }),
    ).rejects.toMatchObject({ code: expectedCode });
  });
});

describe("results and recovery", () => {
  it("renders exactly five ordered stored cards and restores the pinned run with GET only", async () => {
    const results = recommendationResults();
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(results));
    await renderResults(fetchImpl);

    const heading = await screen.findByRole("heading", { name: "이번 경주에 맞는 5곳" });
    await waitFor(() => expect(heading).toBe(document.activeElement));
    const list = screen.getByRole("list", { name: "추천 5곳" });
    const cards = within(list).getAllByRole("listitem");
    expect(cards).toHaveLength(5);
    expect(cards.map((card) => within(card).getByRole("heading").textContent)).toEqual([
      "1위 경주 장소 1",
      "2위 경주 장소 2",
      "3위 경주 장소 3",
      "4위 경주 장소 4",
      "5위 경주 장소 5",
    ]);
    expect(within(cards[0]!).getByText("적합도 90점 / 100점")).toBeTruthy();
    expect(within(cards[0]!).getAllByRole("meter")).toHaveLength(3);
    expect(within(cards[0]!).getByText("역사 근거 1이 이번 기대와 이어져요.")).toBeTruthy();
    expect(within(cards[0]!).getByText("감성 근거 1이 이번 기대와 이어져요.")).toBeTruthy();
    expect(within(cards[0]!).getByText("대표 이미지 없음")).toBeTruthy();
    expect(within(cards[0]!).getByText(/운영 정보 미확인/)).toBeTruthy();
    expect(within(cards[0]!).getByText("2026.08.10 기준")).toBeTruthy();
    expect(screen.getByText("추천 5곳을 준비했어요.").getAttribute("role")).toBe("status");
    const resultItems = (results.run as JsonRecord).items as JsonRecord[];
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls.map((call) => String(call[0]))).toEqual([
      `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}`,
      `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}/operating-information?${resultItems
        .map((item) => `place_id=${encodeURIComponent(String(item.place_id))}`)
        .join("&")}`,
    ]);
    expect(fetchImpl.mock.calls.every((call) => (call[1]?.method ?? "GET") === "GET")).toBe(true);
  });

  it.each([
    [
      "NO_ACTIVE_SCORED_RELEASE",
      503,
      "추천 준비가 아직 끝나지 않았어요.",
      "추천 준비 다시 확인",
    ],
    [
      "INSUFFICIENT_ELIGIBLE_CANDIDATES",
      422,
      "추천 5곳을 만들지 못했어요.",
      "추천 준비 다시 확인",
    ],
    [
      "RECOMMENDATION_RUN_NOT_FOUND",
      404,
      "이 추천 결과를 다시 확인할 수 없어요.",
      "기대 프로필로 돌아가기",
    ],
  ])("renders the %s closed state with no success DOM", async (code, status, heading, action) => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse(
        {
          detail: {
            code,
            message_ko: "서버가 보낸 내부 문구를 그대로 노출하지 않아요.",
            preference_profile_id: null,
            release_id: null,
            request_id: null,
          },
        },
        status,
      ),
    );
    await renderResults(fetchImpl);

    const stateHeading = await screen.findByRole("heading", { name: heading });
    await waitFor(() => expect(stateHeading).toBe(document.activeElement));
    expect(screen.getByRole("button", { name: action })).toBeTruthy();
    expect(document.querySelectorAll("[data-recommendation-card]")).toHaveLength(0);
    expect(document.querySelector(`[data-status="${code}"]`)).toBeTruthy();
  });

  it("fails a partial success closed and keeps one bounded live sentence", async () => {
    const malformed = recommendationResults({
      run: {
        ...(recommendationResults().run as JsonRecord),
        items: ((recommendationResults().run as JsonRecord).items as unknown[]).slice(0, 4),
      },
    });
    await renderResults(vi.fn().mockResolvedValue(jsonResponse(malformed)));

    expect(
      await screen.findByRole("heading", { name: "추천을 불러오지 못했어요." }),
    ).toBe(document.activeElement);
    expect(document.querySelectorAll("[data-recommendation-card]")).toHaveLength(0);
    const live = screen.getByRole("alert");
    expect(live.textContent).toContain("기대 프로필은 이 브라우저에 남아 있어요.");
    expect(live.textContent).not.toContain("서버가 보낸 내부 문구");
  });
});

describe("demo disclosure", () => {
  it("renders the GLM public-evidence disclosure for v2 results", async () => {
    const payload = await mvpRecommendationResults();
    const runId = String((payload.run as JsonRecord).run_id);
    await renderResults(
      vi.fn().mockResolvedValue(jsonResponse(payload)),
      runId,
    );

    expect(await screen.findByText("GLM 공개 근거 모델 분석")).toBeTruthy();
    expect(
      screen.getByText(
        "권리 검수된 공개 관광 근거를 바탕으로 만든 GLM 분석이에요. 전문가 인증이나 실제 만족도 예측을 뜻하지 않아요.",
      ),
    ).toBeTruthy();
    const banner = document.querySelector(
      '[data-analysis-origin="GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED"]',
    );
    expect(banner).toBeTruthy();
    expect(banner?.textContent).toContain("glm-5.3-flash");
    expect(banner?.textContent).toContain("mvp-place-scoring-request.v2");
    expect(
      document.querySelectorAll(
        '.recommendation-status-row[data-analysis-origin="GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED"]',
      ),
    ).toHaveLength(5);
  });

  it("renders the exact safe release disclosure and no raw provider material", async () => {
    await renderResults(vi.fn().mockResolvedValue(jsonResponse(recommendationResults())));

    expect(await screen.findByText("공모전 데모용 모델 분석")).toBeTruthy();
    expect(
      screen.getByText(
        "공개 관광 설명과 Odii 근거를 바탕으로 만든 모델 분석이에요. 전문가 인증이나 실제 만족도 예측을 뜻하지 않아요.",
      ),
    ).toBeTruthy();
    const banner = document.querySelector('[data-analysis-origin="DEMO_MODEL_DERIVED"]');
    expect(banner).toBeTruthy();
    expect(banner?.textContent).toContain("glm-5v-turbo");
    expect(banner?.textContent).toContain("phase5-demo-profile.v1");
    expect(banner?.textContent).toContain(CONFIG_SHA);
    expect(banner?.textContent).not.toMatch(/raw prompt|response body|protected path|secret/i);
  });
});
}
