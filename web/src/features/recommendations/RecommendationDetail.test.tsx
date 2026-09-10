import { render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, MemoryRouter, RouterProvider } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const RED_SENTINEL = "PHASE5_RED_RECOMMENDATION_DETAIL_NOT_IMPLEMENTED";
const SHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const controlledRedOnly = (
  globalThis as typeof globalThis & {
    __vitest_worker__?: { config?: { testNamePattern?: RegExp } };
  }
).__vitest_worker__?.config?.testNamePattern?.source === "controlled RED sentinel";

type JsonRecord = Record<string, unknown>;

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

function confidenceStateFor(confidence: number): keyof typeof CONFIDENCE_REASON {
  if (confidence < 65) return "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED";
  if (confidence < 70) return "EVIDENCE_LIMITED_MISMATCH_AVAILABLE";
  return "EVIDENCE_SUPPORTED";
}

function currentAuthority(): JsonRecord {
  return {
    recovery_policy_sha256: RECOVERY_POLICY_SHA,
    hard_duplicate_adjudication_sha256: HARD_DUPLICATE_SHA,
    cannot_coappear_authority_sha256: CANNOT_COAPPEAR_SHA,
    activation_suite_sha256: ACTIVATION_SUITE_SHA,
    contrast_suite_sha256: CONTRAST_SUITE_SHA,
  };
}

function halfUp(numerator: number, denominator: number): number {
  return Math.floor((numerator + Math.floor(denominator / 2)) / denominator);
}

function resultItem(
  rank: number,
  confidence = 70,
  overrides: JsonRecord = {},
): JsonRecord {
  const placeId = `place-${rank}`;
  const referenceDate = "2026-08-10";
  const evidenceConfidenceState = confidenceStateFor(confidence);
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
  const experienceFitScore = halfUp(
    axisComponents.reduce((total, component) => total + component.fit_score, 0),
    3,
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
    place_value: 40,
    absolute_difference: 10,
    fit_score: 90,
    total_score_weight_bp: conditionWeights[index],
    weighted_numerator: 90 * conditionWeights[index],
  }));
  const travelConditionFitScore = halfUp(
    conditionComponents.reduce((total, component) => total + component.weighted_numerator, 0),
    2_000,
  );
  const relevanceNumerator = experienceFitScore * 8_000 + travelConditionFitScore * 2_000;
  const relevanceScore = halfUp(relevanceNumerator, 10_000);
  const rerankNumerator = relevanceScore * 8_500 + 50 * 1_500;
  return {
    rank,
    place_id: placeId,
    place_name_ko: `경주 장소 ${rank}`,
    fit_score: relevanceScore,
    evidence_confidence_state: evidenceConfidenceState,
    evidence_confidence_reason_ko: CONFIDENCE_REASON[evidenceConfidenceState],
    confidence_percent: confidence,
    mismatch,
    contribution: {
      axis_components: axisComponents,
      condition_components: conditionComponents,
      experience_fit_score: experienceFitScore,
      travel_condition_fit_score: travelConditionFitScore,
      relevance_score: relevanceScore,
      relevance_numerator: relevanceNumerator,
      diversity_novelty_score: 50,
      rerank_score: halfUp(rerankNumerator, 10_000),
      rerank_numerator: rerankNumerator,
    },
    axis_scores: [
      { axis: "HISTORY_TRADITION", value: 70 + rank, evidence_ids: [`evidence-${rank}-h`] },
      { axis: "EMOTION_IMAGE", value: 60 + rank, evidence_ids: [`evidence-${rank}-e`] },
      { axis: "REST_IMMERSION", value: 50 + rank, evidence_ids: [`evidence-${rank}-r`] },
    ],
    evidence: ["h", "e"].map((axis) => ({
      evidence_id: `evidence-${rank}-${axis}`,
      excerpt_ko:
        rank === 1 && axis === "h"
          ? "신라 시대 유산의 구조와 역사적 맥락을 설명하는 저장 근거예요."
          : rank === 1 && axis === "e"
            ? "해질녘 경관과 주변 분위기를 설명하는 저장 근거예요."
            : `경주 장소 ${rank}의 근거 발췌입니다.`,
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
    ...overrides,
  };
}

function mvpEvidence(
  evidenceId: string,
  excerptKo: string,
  referenceDate: string,
): JsonRecord {
  return {
    schema_version: "mvp-evidence-snippet.v1",
    evidence_id: evidenceId,
    excerpt_ko: excerptKo,
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

function mvpResultItem(overrides: JsonRecord = {}): JsonRecord {
  const { confidence_percent: _confidence, ...item } = resultItem(1, 70);
  const evidence = [
    mvpEvidence(
      "evidence-1-h",
      "신라 시대 유산의 구조와 역사적 맥락을 설명하는 저장 근거예요.",
      "2026-08-09",
    ),
    mvpEvidence(
      "evidence-1-e",
      "해질녘 경관과 주변 분위기를 설명하는 저장 근거예요.",
      "2026-08-10",
    ),
  ];
  const explanations = (item.explanations as JsonRecord[]).map((row, index) => ({
    ...row,
    reference_date: evidence[index]!.reference_date,
  }));
  return {
    ...item,
    evidence,
    explanations,
    reference_date: "2026-08-10",
    ...overrides,
  };
}

function mvpRecommendationDetail(overrides: JsonRecord = {}): JsonRecord {
  const item = mvpResultItem();
  return {
    run_id: "recommendation-run:mvp-detail",
    release_sha256: SHA.replaceAll("0", "2"),
    confidence_percent: 70,
    evidence_confidence_state: "EVIDENCE_SUPPORTED",
    evidence_confidence_reason_ko: CONFIDENCE_REASON.EVIDENCE_SUPPORTED,
    item,
    mismatch_traits: ["M1", "M2", "M3", "M4", "M5", "M6"].map(
      (trait_id, index) => ({
        trait_id,
        value: 40 + index,
        evidence_ids: [index === 5 ? "evidence-1-r" : `evidence-1-${index % 2 === 0 ? "h" : "e"}`],
      }),
    ),
    evidence: [
      ...((item.evidence as JsonRecord[]).map((row) => ({ ...row })) as JsonRecord[]),
      mvpEvidence(
        "evidence-1-r",
        "체류와 휴식 환경을 설명하는 저장 근거예요.",
        "2026-08-08",
      ),
    ],
    operating_state: "OPERATING_INFORMATION_UNVERIFIED",
    similar_place_ids: ["place-2", "place-3", "place-4"],
    ...overrides,
  };
}

function unsealedRecommendationResults(
  confidence = 70,
  itemOverrides: JsonRecord = {},
): JsonRecord {
  const items = [1, 2, 3, 4, 5].map((rank) =>
    resultItem(rank, rank === 1 ? confidence : 70, rank === 1 ? itemOverrides : {}),
  );
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
      candidate_place_ids: items.map((item) => item.place_id),
      exclusions: [],
      duplicate_decisions: [],
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

function recommendationResults(): JsonRecord {
  return structuredClone(SEALED_RESULTS);
}

async function recommendationBoundaryPayload(confidence: number): Promise<{
  results: JsonRecord;
  detail: JsonRecord;
}> {
  const results = await sealRecommendationResults(unsealedRecommendationResults(confidence));
  return { results, detail: recommendationDetailFromResults(results, confidence) };
}

function recommendationDetailFromResults(
  results: JsonRecord,
  confidence = 70,
  itemOverrides: JsonRecord = {},
): JsonRecord {
  const run = results.run as JsonRecord;
  const { confidence_percent: _confidence, ...item } = resultItem(1, confidence, itemOverrides);
  const pinnedItem = (run.items as JsonRecord[]).find((candidate) => candidate.place_id === item.place_id);
  if (pinnedItem === undefined) throw new Error("missing pinned boundary item");
  const detailItem = { ...pinnedItem, ...itemOverrides };
  const detailEvidence = detailItem.evidence as JsonRecord[];
  return {
    run_id: run.run_id,
    release_sha256: run.release_sha256,
    confidence_percent: confidence,
    evidence_confidence_state: detailItem.evidence_confidence_state,
    evidence_confidence_reason_ko: detailItem.evidence_confidence_reason_ko,
    item: item,
    mismatch_traits: [1, 2, 3, 4, 5, 6].map((value) => ({
      trait_id: `M${value}`,
      value: 35 + value,
      evidence_ids: [`evidence-1-${value === 1 ? "h" : "e"}`],
    })),
    evidence: [
      ...(detailEvidence.map((row) => ({ ...row })) as JsonRecord[]),
      {
        evidence_id: "evidence-1-r",
        excerpt_ko: "체류와 휴식 환경을 설명하는 저장 근거예요.",
        source_label_ko: "한국관광공사 TourAPI 공식 관광정보",
        attribution_ko: "출처: 한국관광공사 TourAPI (공공데이터포털 데이터셋 15101578)",
        contest_use_scope: "noncommercial_contest_demo_evaluation",
        contest_rights_qualified: true,
        reference_date: "2026-08-10",
      },
    ],
    operating_state: "OPERATING_INFORMATION_UNVERIFIED",
    similar_place_ids: ["place-2", "place-3", "place-4"],
  };
}

function recommendationDetail(itemOverrides: JsonRecord = {}): JsonRecord {
  const { confidence_percent: _confidence, ...item } = resultItem(1, 70, itemOverrides);
  const run = SEALED_RESULTS.run as JsonRecord;
  return {
    ...recommendationDetailFromResults(SEALED_RESULTS, 70, itemOverrides),
    item: {
      ...item,
      fit_score: (run.items as JsonRecord[])[0]!.fit_score,
      contribution: (run.items as JsonRecord[])[0]!.contribution,
    },
  };
}

function legacyRecommendationDetail(itemOverrides: JsonRecord = {}): JsonRecord {
  const item = resultItem(1, 70, itemOverrides);
  return {
    run_id: RECOMMENDATION_RUN_ID,
    release_sha256: SHA.replaceAll("0", "2"),
    item,
    mismatch_traits: [1, 2, 3, 4, 5, 6].map((value) => ({
      trait_id: `M${value}`,
      value: 35 + value,
      evidence_ids: [`evidence-1-${value === 1 ? "h" : "e"}`],
    })),
    evidence: [
      ...((item.evidence as JsonRecord[]).map((row) => ({ ...row })) as JsonRecord[]),
      {
        evidence_id: "evidence-1-r",
        excerpt_ko: "체류와 휴식 환경을 설명하는 저장 근거예요.",
        source_label_ko: "한국관광공사 TourAPI 공식 관광정보",
        attribution_ko: "출처: 한국관광공사 TourAPI (공공데이터포털 데이터셋 15101578)",
        contest_use_scope: "noncommercial_contest_demo_evaluation",
        contest_rights_qualified: true,
        reference_date: "2026-08-10",
      },
    ],
    operating_state: "OPERATING_INFORMATION_UNVERIFIED",
    similar_place_ids: ["place-2", "place-3", "place-4"],
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function renderDetail(
  fetchImpl: typeof fetch,
  placeId = "place-1",
  runId = RECOMMENDATION_RUN_ID,
) {
  vi.stubGlobal("fetch", fetchImpl);
  const modulePath = "../../journey-pages/PlaceDetailJourneyPage";
  const { PlaceDetailPage } = await import(/* @vite-ignore */ modulePath);
  const router = createMemoryRouter(
    [{ path: "/recommendations/:runId/places/:placeId", element: <PlaceDetailPage /> }],
    {
      initialEntries: [
        `/recommendations/${encodeURIComponent(runId)}/places/${placeId}`,
      ],
    },
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
  describe("shared detail truth", () => {
    it("links a result card to the exact opaque run and place route", async () => {
      const cardPath = "./RecommendationCard";
      const { RecommendationCard } = await import(/* @vite-ignore */ cardPath);
      render(
        <MemoryRouter>
          <RecommendationCard
            item={resultItem(1) as never}
            operatingState="OPERATING_INFORMATION_UNVERIFIED"
            runId="recommendation-run:current"
            analysisOrigin="DEMO_MODEL_DERIVED"
          />
        </MemoryRouter>,
      );

      expect(
        screen.getByRole("link", { name: "경주 장소 1 상세 보기" }).getAttribute("href"),
      ).toBe("/recommendations/recommendation-run%3Acurrent/places/place-1");
    });

    it.each([
      ["IMAGE_MISSING", "대표 이미지 없음", "확인된 대표 이미지가 없어 설명과 근거를 중심으로 안내해요."],
      ["IMAGE_RIGHTS_RESTRICTED", "이미지 표시 제한", "표시 권한을 확인할 수 없어 대표 이미지를 보여드리지 않아요."],
      ["IMAGE_ANALYSIS_FAILED", "이미지 분석 미완료", "이미지 분석을 완료하지 못해 확인된 텍스트 근거로 안내해요."],
    ])("renders the %s state without a borrowed image", async (state, label, body) => {
      const mediaPath = "./TextFirstMediaState";
      const { TextFirstMediaState } = await import(/* @vite-ignore */ mediaPath);
      render(<TextFirstMediaState state={state as never} />);

      expect(screen.getByText(label)).toBeTruthy();
      expect(screen.getByText(body)).toBeTruthy();
      expect(document.querySelector("img")).toBeNull();
      expect(document.querySelector(`[data-media-state="${state}"]`)).toBeTruthy();
    });

    it("renders only an explicitly authorized asset with required attribution", async () => {
      const mediaPath = "./TextFirstMediaState";
      const { TextFirstMediaState } = await import(/* @vite-ignore */ mediaPath);
      render(
        <TextFirstMediaState
          state="DISPLAY_ASSET_AVAILABLE"
          asset={{
            src: "/authorized/place-1.webp",
            alt: "경주 장소 1의 검증된 대표 이미지",
            attribution: "한국관광공사 제공 · 공공누리 표시",
          }}
        />,
      );

      expect(
        screen
          .getByRole("img", { name: "경주 장소 1의 검증된 대표 이미지" })
          .getAttribute("src"),
      ).toBe("/authorized/place-1.webp");
      expect(screen.getByText("한국관광공사 제공 · 공공누리 표시")).toBeTruthy();
    });

    it("keeps available media truth but makes no request when asset authority is incomplete", async () => {
      const mediaPath = "./TextFirstMediaState";
      const { TextFirstMediaState } = await import(/* @vite-ignore */ mediaPath);
      render(<TextFirstMediaState state="DISPLAY_ASSET_AVAILABLE" />);

      expect(document.querySelector('[data-media-state="DISPLAY_ASSET_AVAILABLE"]')).toBeTruthy();
      expect(screen.getByText("검증된 대표 이미지")).toBeTruthy();
      expect(screen.getByText("표시 자산 정보가 없어 이미지를 요청하지 않고 텍스트 근거로 안내해요.")).toBeTruthy();
      expect(document.querySelector("img")).toBeNull();
    });

    it.each([
      ["NO_GUIDANCE", "이번 여행의 기대와 크게 다르지 않아요."],
      ["GENTLE_DIFFERENCE", "한 가지 차이를 확인해 보세요."],
      ["MATERIAL_DIFFERENCE", "방문 전 기대를 조금 조정해 보세요."],
      ["STRONG_DIFFERENCE", "이번 여행의 우선순위와 다른 점이 있어요."],
      ["SUPPRESSED_LOW_CONFIDENCE", "근거가 충분하지 않아 기대 차이 안내를 생략했어요."],
    ])("renders stored %s mismatch guidance without recomputing", async (state, copy) => {
      const mismatchPath = "./MismatchGuidance";
      const { MismatchGuidance } = await import(/* @vite-ignore */ mismatchPath);
      const mismatch = {
        ...(resultItem(1).mismatch as JsonRecord),
        state,
        message_ko: copy,
        suppression_reason:
          state === "SUPPRESSED_LOW_CONFIDENCE" ? "LOW_CONFIDENCE" : null,
      };
      render(<MismatchGuidance mismatch={mismatch as never} />);

      expect(screen.getByText("이번 여행에서 기대한 것과 다른 점")).toBeTruthy();
      expect(screen.getByText(copy)).toBeTruthy();
      expect(document.querySelector(`[data-mismatch-state="${state}"]`)).toBeTruthy();
    });
  });

  describe("confidence boundary presentation", () => {
    const boundaries = [
      [55, "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED", "근거 제한", CONFIDENCE_REASON.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED, "SUPPRESSED_LOW_CONFIDENCE"],
      [64, "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED", "근거 제한", CONFIDENCE_REASON.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED, "SUPPRESSED_LOW_CONFIDENCE"],
      [65, "EVIDENCE_LIMITED_MISMATCH_AVAILABLE", "근거 제한", CONFIDENCE_REASON.EVIDENCE_LIMITED_MISMATCH_AVAILABLE, "GENTLE_DIFFERENCE"],
      [69, "EVIDENCE_LIMITED_MISMATCH_AVAILABLE", "근거 제한", CONFIDENCE_REASON.EVIDENCE_LIMITED_MISMATCH_AVAILABLE, "GENTLE_DIFFERENCE"],
      [70, "EVIDENCE_SUPPORTED", "근거 충분", CONFIDENCE_REASON.EVIDENCE_SUPPORTED, "GENTLE_DIFFERENCE"],
    ] as const;

    it.each(boundaries)(
      "renders a nonnumeric card status at confidence %s",
      async (confidence, state, label, reason, mismatchState) => {
        const cardPath = "./RecommendationCard";
        const { RecommendationCard } = await import(/* @vite-ignore */ cardPath);
        const { container } = render(
          <MemoryRouter>
            <RecommendationCard
              item={resultItem(1, confidence) as never}
              operatingState="OPERATING_INFORMATION_UNVERIFIED"
              runId="recommendation-run:boundary"
              analysisOrigin="DEMO_MODEL_DERIVED"
            />
          </MemoryRouter>,
        );
        const card = container.querySelector("[data-recommendation-card]");
        expect(card).toBeTruthy();
        expect(card?.getAttribute("data-evidence-confidence-state")).toBe(state);
        expect(within(card as HTMLElement).getByText(label, { exact: true })).toBeTruthy();
        expect(within(card as HTMLElement).getByText(reason, { exact: true })).toBeTruthy();
        expect(within(card as HTMLElement).getByText(
          mismatchState === "SUPPRESSED_LOW_CONFIDENCE"
            ? "근거가 충분하지 않아 기대 차이 안내를 생략했어요."
            : "한 가지 차이를 확인해 보세요.",
          { exact: true },
        )).toBeTruthy();
        expect(within(card as HTMLElement).queryByText(`분석 신뢰도 ${confidence}점 / 100점`)).toBeNull();
        expect(card?.querySelector("[data-confidence-percent]" )).toBeNull();
        const status = card?.querySelector("[data-evidence-confidence-state]");
        const mismatch = card?.querySelector(`[data-mismatch-state="${mismatchState}"]`);
        expect(status).toBeTruthy();
        expect(mismatch).toBeTruthy();
        expect(status!.compareDocumentPosition(mismatch!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      },
    );

    it.each(boundaries)(
      "renders the matching evidence state/reason without destination confidence numbers at %s",
      async (confidence, state, label, reason) => {
        const { results, detail } = await recommendationBoundaryPayload(confidence);
        const runId = String((results.run as JsonRecord).run_id);
        const fetchImpl = vi.fn(async (request: RequestInfo | URL) =>
          String(request).includes("/places/") ? jsonResponse(detail) : jsonResponse(results),
        );
        await renderDetail(fetchImpl, "place-1", runId);

        const heading = await screen.findByRole("heading", { name: "경주 장소 1" });
        await waitFor(() => expect(heading).toBe(document.activeElement));
        const confidenceSection = document.querySelector(
          `[data-evidence-confidence-state="${state}"]`,
        );
        expect(confidenceSection).toBeTruthy();
        expect(screen.queryByText(`분석 신뢰도 ${confidence}점 / 100점`, { exact: true })).toBeNull();
        expect(screen.getByRole("heading", { name: "근거 상태" })).toBeTruthy();
        expect(screen.getByText(label, { exact: true })).toBeTruthy();
        expect(screen.getByText(reason, { exact: true })).toBeTruthy();
        expect(confidenceSection?.textContent).toContain(reason);
        expect(document.querySelector(`[data-mismatch-state="${confidence < 65 ? "SUPPRESSED_LOW_CONFIDENCE" : "GENTLE_DIFFERENCE"}"]`)).toBeTruthy();
      },
    );
  });

  describe("pinned place detail page", () => {
    it("accepts an exact v2 detail with mixed evidence dates", async () => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = mvpRecommendationDetail();
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationDetail("recommendation-run:mvp-detail", "place-1", {
          fetchImpl,
        }),
      ).resolves.toMatchObject({
        run_id: "recommendation-run:mvp-detail",
        confidence_percent: 70,
        item: { reference_date: "2026-08-10" },
      });
    });

    const mvpDetailMutations: Array<[string, (payload: JsonRecord) => void]> = [
      ["extra top-level field", (payload) => {
        payload.unexpected = true;
      }],
      ["missing top-level field", (payload) => {
        delete payload.operating_state;
      }],
      ["confidence projection", (payload) => {
        payload.evidence_confidence_state = "EVIDENCE_LIMITED_MISMATCH_AVAILABLE";
      }],
      ["non-canonical trait order", (payload) => {
        (payload.mismatch_traits as JsonRecord[]).reverse();
      }],
      ["strict evidence shape", (payload) => {
        (payload.evidence as JsonRecord[])[0]!.contest_rights_qualified = true;
      }],
      ["item and inventory byte mismatch", (payload) => {
        (payload.evidence as JsonRecord[])[0]!.excerpt_ko = "같은 ID의 다른 엄격 근거";
      }],
      ["duplicate inventory evidence", (payload) => {
        const evidence = payload.evidence as JsonRecord[];
        evidence[2] = { ...evidence[0] };
      }],
      ["unresolved axis evidence", (payload) => {
        const item = payload.item as JsonRecord;
        (item.axis_scores as JsonRecord[])[0]!.evidence_ids = ["evidence-orphan"];
      }],
      ["unresolved trait evidence", (payload) => {
        (payload.mismatch_traits as JsonRecord[])[0]!.evidence_ids = ["evidence-orphan"];
      }],
      ["explanation evidence date", (payload) => {
        const item = payload.item as JsonRecord;
        (item.explanations as JsonRecord[])[0]!.reference_date = "2026-08-10";
      }],
      ["item latest evidence date", (payload) => {
        (payload.item as JsonRecord).reference_date = "2026-08-09";
      }],
      ["extra nested item field", (payload) => {
        (payload.item as JsonRecord).confidence_percent = 70;
      }],
    ];

    it.each(mvpDetailMutations)("rejects v2 detail %s tampering", async (_label, mutate) => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const payload = structuredClone(mvpRecommendationDetail());
      mutate(payload);
      const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));

      await expect(
        api.fetchRecommendationDetail("recommendation-run:mvp-detail", "place-1", {
          fetchImpl,
        }),
      ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
    });

    it("rejects orphaned, conflicting, or stale detail evidence before rendering", async () => {
      const apiPath = "../../api/api";
      const api = await import(/* @vite-ignore */ apiPath);
      const mutations = [
        (payload: JsonRecord) => {
          const item = payload.item as JsonRecord;
          const evidenceId = ((item.evidence as JsonRecord[])[0]!.evidence_id as string);
          payload.evidence = (payload.evidence as JsonRecord[]).filter(
            (row) => row.evidence_id !== evidenceId,
          );
        },
        (payload: JsonRecord) => {
          (payload.evidence as JsonRecord[])[0]!.excerpt_ko = "같은 ID의 다른 근거";
        },
        (payload: JsonRecord) => {
          (payload.evidence as JsonRecord[])[0]!.reference_date = "2026-08-09";
        },
        (payload: JsonRecord) => {
          const trait = (payload.mismatch_traits as JsonRecord[])[0]!;
          trait.evidence_ids = ["evidence-orphan"];
        },
        (payload: JsonRecord) => {
          const item = payload.item as JsonRecord;
          const axis = (item.axis_scores as JsonRecord[])[2]!;
          axis.evidence_ids = ["evidence-orphan"];
        },
        (payload: JsonRecord) => {
          const item = payload.item as JsonRecord;
          item.reference_date = "2026-02-30";
          for (const evidence of item.evidence as JsonRecord[]) {
            evidence.reference_date = "2026-02-30";
          }
          for (const explanation of item.explanations as JsonRecord[]) {
            explanation.reference_date = "2026-02-30";
          }
          for (const evidence of payload.evidence as JsonRecord[]) {
            evidence.reference_date = "2026-02-30";
          }
        },
        (payload: JsonRecord) => {
          const item = payload.item as JsonRecord;
          const axis = (item.axis_scores as JsonRecord[])[2]!;
          axis.evidence_ids = Array.from({ length: 9 }, () => "evidence-1-r");
        },
      ];

      for (const mutate of mutations) {
        const payload = JSON.parse(JSON.stringify(recommendationDetail())) as JsonRecord;
        mutate(payload);
        const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(payload));
        await expect(
          api.fetchRecommendationDetail(RECOMMENDATION_RUN_ID, "place-1", { fetchImpl }),
        ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
      }
    });

    it("repeats canonical card facts and adds stored evidence, traits, context, versions, and same-run links", async () => {
      const results = recommendationResults();
      const detail = recommendationDetail();
      const fetchImpl = vi.fn(async (request: RequestInfo | URL, init?: RequestInit) => {
        const url = String(request);
        if (url.endsWith("/places/place-1")) return jsonResponse(detail);
        if (url.endsWith(`/${encodeURIComponent(RECOMMENDATION_RUN_ID)}`)) {
          return jsonResponse(results);
        }
        return jsonResponse({}, 404);
      });
      await renderDetail(fetchImpl);

      const heading = await screen.findByRole("heading", { name: "경주 장소 1" });
      await waitFor(() => expect(heading).toBe(document.activeElement));
      expect(document.querySelector("[data-preference-similarity]")?.textContent).toBe("내 취향과 88% 유사");
      expect(screen.getByRole("meter", { name: "역사·전통 취향 유사도 91%" }).getAttribute("aria-valuenow")).toBe("91");
      expect(screen.queryByText(/\d+점 \/ 100점/)).toBeNull();
      expect(screen.getAllByRole("meter")).toHaveLength(3);
      expect(screen.getByText("역사 근거 1이 이번 기대와 이어져요.")).toBeTruthy();
      expect(screen.getByText("감성 근거 1이 이번 기대와 이어져요.")).toBeTruthy();
      expect(screen.getByText("대표 이미지 없음")).toBeTruthy();
      expect(screen.getByText("한 가지 차이를 확인해 보세요.")).toBeTruthy();
      expect(screen.queryByRole("list", { name: "여섯 가지 기대 차이 특성" })).toBeNull();
      expect(screen.queryByText("시간·계절 맥락")).toBeNull();
      expect(screen.getByText("운영 정보 미확인 — 방문 전 공식 안내를 확인해 주세요.")).toBeTruthy();
      expect(screen.getByText("신라 시대 유산의 구조와 역사적 맥락을 설명하는 저장 근거예요.")).toBeTruthy();
      expect(screen.getByText("공모전 데모용 모델 분석")).toBeTruthy();
      expect(screen.getByText("glm-5v-turbo")).toBeTruthy();
      const similar = screen.getByRole("list", { name: "같은 추천 실행의 비슷한 장소" });
      expect(
        within(similar)
          .getByRole("link", { name: "경주 장소 2 상세 보기" })
          .getAttribute("href"),
      ).toBe(
        `/recommendations/${encodeURIComponent(RECOMMENDATION_RUN_ID)}/places/place-2`,
      );
      expect(fetchImpl).toHaveBeenCalledTimes(4);
      expect(fetchImpl.mock.calls.map((call) => String(call[0]))).toEqual([
        `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}`,
        `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}/places/place-1`,
        `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}/trip-context`,
        `/v1/recommendation-runs/${encodeURIComponent(RECOMMENDATION_RUN_ID)}/operating-information?place_id=place-1`,
      ]);
      expect(fetchImpl.mock.calls.every((call) => (call[1]?.method ?? "GET") === "GET")).toBe(true);
    });

    it("fails stale or cross-pinned detail closed with focused recovery and no invented values", async () => {
      const detail = recommendationDetail();
      detail.release_sha256 = SHA.replaceAll("0", "9");
      const fetchImpl = vi.fn(async (request: RequestInfo | URL) =>
        String(request).includes("/places/")
          ? jsonResponse(detail)
          : jsonResponse(recommendationResults()),
      );
      await renderDetail(fetchImpl);

      const heading = await screen.findByRole("heading", {
        name: "이 추천 결과를 다시 확인할 수 없어요.",
      });
      await waitFor(() => expect(heading).toBe(document.activeElement));
      expect(document.querySelector("[data-place-detail]")).toBeNull();
      expect(screen.getByRole("button", { name: "기대 프로필로 돌아가기" })).toBeTruthy();
    });

    it("renders external text only as text nodes", async () => {
      const injected = "<img src=x onerror=alert('xss')>저장 근거";
      const detail = recommendationDetail();
      const results = recommendationResults();
      const evidenceId = String((detail.evidence as JsonRecord[])[0]!.evidence_id);
      for (const evidence of [
        ...(detail.evidence as JsonRecord[]),
        ...((detail.item as JsonRecord).evidence as JsonRecord[]),
        ...(((results.run as JsonRecord).items as JsonRecord[])[0]!.evidence as JsonRecord[]),
      ]) {
        if (evidence.evidence_id === evidenceId) evidence.excerpt_ko = injected;
      }
      const resultItemPayload = ((results.run as JsonRecord).items as JsonRecord[])[0]!;
      const detailItemPayload = detail.item as JsonRecord;
      resultItemPayload.evidence = (resultItemPayload.evidence as JsonRecord[]).map((evidence) => ({ ...evidence }));
      detailItemPayload.evidence = (detailItemPayload.evidence as JsonRecord[]).map((evidence) => ({ ...evidence }));
      await sealRecommendationResults(results);
      const injectedRunId = String((results.run as JsonRecord).run_id);
      detail.run_id = injectedRunId;
      detail.release_sha256 = (results.run as JsonRecord).release_sha256;
      const fetchImpl = vi.fn(async (request: RequestInfo | URL) =>
        String(request).includes("/places/")
          ? jsonResponse(detail)
          : jsonResponse(results),
      );
      await renderDetail(fetchImpl, "place-1", injectedRunId);

      expect(await screen.findByText(injected)).toBeTruthy();
      expect(document.querySelector("img[src='x']")).toBeNull();
    });
  });
}
