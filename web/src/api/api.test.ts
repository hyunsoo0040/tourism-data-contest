import previousCopyArtifact from "../../../contracts/questionnaire-v2-20260908.json";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiRequestError,
  createPreferenceProfile,
  fetchOperatingInformation,
  fetchPreferenceProfile,
  type PreferenceProfile,
  type QuestionnaireSubmission,
} from "../api/api";
import legacyChoiceArtifact from "../../../contracts/questionnaire-v2-legacy.json";
import questionnaireV2Artifact from "../../../contracts/questionnaire-v2.json";

const V2_COUPLING = {
  schema_version: "preference-profile-v2",
  questionnaire_version: "questionnaire-v2",
  scoring_version: "choice-distribution-v3",
  config_hash: questionnaireV2Artifact.config_hash,
  description_template_version: "current-trip-expectation-v1",
};

const tripConditions = {
  visit_date: null,
  visit_time: "UNDECIDED",
  companion: "SOLO",
  transport: "WALK_OR_TRANSIT",
  walking_tolerance: "ABOUT_1_HOUR",
  indoor_outdoor_preference: "NO_PREFERENCE",
  crowd_avoidance: "MEDIUM",
} as const;

const v2Answers = Object.fromEntries(
  questionnaireV2Artifact.question_order.map((ordinal) => [`q${ordinal}`, 2]),
);

function v2Profile(overrides: Record<string, unknown> = {}): PreferenceProfile {
  return {
    profile_id: "profile-v2-get",
    request_id: "request-v2-get",
    schema_version: V2_COUPLING.schema_version,
    questionnaire_version: V2_COUPLING.questionnaire_version,
    scoring_version: V2_COUPLING.scoring_version,
    description_template_version: V2_COUPLING.description_template_version,
    config_hash: V2_COUPLING.config_hash,
    created_at: "2026-07-22T12:00:00Z",
    is_current_trip_expectation: true,
    description_ko: "현재 프로필",
    trip_conditions: tripConditions,
    answers: v2Answers,
    scores: [
      { axis: "HISTORY_TRADITION", basis_points: 5_000, display_score: 50 },
      { axis: "EMOTION_IMAGE", basis_points: 2_500, display_score: 25 },
      { axis: "REST_IMMERSION", basis_points: 7_500, display_score: 75 },
    ],
    ...overrides,
  } as PreferenceProfile;
}

const legacyV1Profile = {
  profile_id: "profile-v1-get",
  request_id: "request-v1-get",
  schema_version: "preference-profile-v1",
  questionnaire_version: "questionnaire-v1",
  scoring_version: "integer-bp-v1",
  description_template_version: "current-trip-expectation-v1",
  config_hash: "bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c",
  created_at: "2026-07-22T12:00:00Z",
  is_current_trip_expectation: true,
  description_ko: "레거시 프로필",
  trip_conditions: tripConditions,
  answers: { q1: 4, q2: 5, q3: 3, q4: 2, q5: 1, q6: 5, q7: 4, q8: 3, q9: 2 },
  scores: [
    { axis: "HISTORY_TRADITION", basis_points: 5_000, display_score: 50 },
    { axis: "EMOTION_IMAGE", basis_points: 5_000, display_score: 50 },
    { axis: "REST_IMMERSION", basis_points: 5_000, display_score: 50 },
  ],
} as unknown as PreferenceProfile;

const submission: QuestionnaireSubmission = {
  request_id: "request-v2-post",
  trip_conditions: tripConditions,
  answers: v2Answers as QuestionnaireSubmission["answers"],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("operating information validator", () => {
  const runId = "recommendation-run:test";
  const placeIds = ["place:b", "place:a"] as const;
  const available = {
    place_id: placeIds[0],
    state: "AVAILABLE",
    snapshot: {
      provider: "TOUR_API",
      operation: "detailIntro2",
      content_type_id: "39",
      entries: [
        {
          kind: "OPENING_HOURS",
          label_ko: "영업시간",
          value_ko: "11:00~20:00",
          provider_field: "opentimefood",
        },
      ],
      retrieved_at: "2026-09-05T04:30:00Z",
      provider_modifiedtime: "20260905043000",
      source_label_ko: "한국관광공사 TourAPI(KorService2 detailIntro2)",
      cached: false,
    },
    unavailable_reason: null,
  };
  const unverified = {
    place_id: placeIds[1],
    state: "UNVERIFIED",
    snapshot: null,
    unavailable_reason: "PROVIDER_UNAVAILABLE",
  };

  it("accepts ordered mixed states and sends one encoded batch GET", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse({
        schema_version: "operating-information.v1",
        run_id: runId,
        places: [available, unverified],
      }),
    );

    const response = await fetchOperatingInformation(runId, placeIds, { fetchImpl });

    expect(response.places.map((place) => place.state)).toEqual(["AVAILABLE", "UNVERIFIED"]);
    expect(fetchImpl).toHaveBeenCalledWith(
      `/v1/recommendation-runs/${encodeURIComponent(runId)}/operating-information?place_id=place%3Ab&place_id=place%3Aa`,
      { signal: undefined },
    );
  });

  it.each([
    ["unknown field", { ...available, live_crowd: "LOW" }],
    ["wrong place order", { ...available, place_id: placeIds[1] }],
    ["available without snapshot", { ...available, snapshot: null }],
    ["unsupported provider field", {
      ...available,
      snapshot: {
        ...available.snapshot,
        entries: [{ ...available.snapshot.entries[0], provider_field: "parking" }],
      },
    }],
  ])("rejects %s", async (_label, malformed) => {
    const fetchImpl = vi.fn().mockResolvedValue(
      jsonResponse({
        schema_version: "operating-information.v1",
        run_id: runId,
        places: [malformed, unverified],
      }),
    );

    await expect(
      fetchOperatingInformation(runId, placeIds, { fetchImpl }),
    ).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
});

describe("version-coupled preference profile validators", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("accepts a stored legacy questionnaire-v1 profile through GET", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(legacyV1Profile)));

    const profile = await fetchPreferenceProfile("profile-v1-get");

    expect(profile.questionnaire_version).toBe("questionnaire-v1");
    expect(profile.schema_version).toBe("preference-profile-v1");
    expect(profile.scoring_version).toBe("integer-bp-v1");
  });

  it.each([legacyChoiceArtifact, previousCopyArtifact])("reads historical scores with their original version/hash ($config_hash)", async (artifact) => {
    const stored = v2Profile({
      scoring_version: artifact.scoring_version,
      config_hash: artifact.config_hash,
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(stored)));
    expect(await fetchPreferenceProfile(stored.profile_id)).toEqual(stored);
  });

  it("rejects historical scoring paired with a new calibration hash", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(v2Profile({
      scoring_version: legacyChoiceArtifact.scoring_version,
    }))));
    await expect(fetchPreferenceProfile("profile-v2-get")).rejects.toBeInstanceOf(ApiRequestError);
  });

  it("accepts a current questionnaire-v2 profile through GET", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(v2Profile())));

    const profile = await fetchPreferenceProfile("profile-v2-get");

    expect(profile.questionnaire_version).toBe("questionnaire-v2");
  });

  it("rejects a mixed-coupling GET payload (v1 profile wearing v2 scoring)", async () => {
    const mixed = {
      ...legacyV1Profile,
      scoring_version: "choice-distribution-v3",
      config_hash: V2_COUPLING.config_hash,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(mixed)));

    await expect(fetchPreferenceProfile("profile-v1-get")).rejects.toMatchObject({
      status: 200,
    });
  });

  it.each([
    ["schema_version", { schema_version: "preference-profile-v9" }],
    ["questionnaire_version", { questionnaire_version: "questionnaire-v7" }],
    ["scoring_version", { scoring_version: "integer-bp-v1" }],
    ["config_hash", { config_hash: "a".repeat(64) }],
    ["description_template_version", { description_template_version: "template-v9" }],
  ])("rejects a GET v2 profile with a mismatched %s", async (_field, overrides) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(v2Profile(overrides))));

    await expect(fetchPreferenceProfile("profile-v2-get")).rejects.toBeInstanceOf(ApiRequestError);
  });

  it("rejects a GET v1 profile whose nine answers fall outside the 1..5 Likert range", async () => {
    const v1WithOutOfRangeValues = {
      ...legacyV1Profile,
      answers: { ...legacyV1Profile.answers, q9: 0 },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(v1WithOutOfRangeValues)),
    );

    await expect(fetchPreferenceProfile("profile-v1-get")).rejects.toBeInstanceOf(ApiRequestError);
  });

  it("rejects a GET v1 profile missing any of the exact nine answer keys", async () => {
    const { q9: _dropped, ...eightAnswers } = legacyV1Profile.answers as Record<string, number>;
    const v1WithEightAnswers = { ...legacyV1Profile, answers: eightAnswers };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(v1WithEightAnswers)),
    );

    await expect(fetchPreferenceProfile("profile-v1-get")).rejects.toBeInstanceOf(ApiRequestError);
  });

  it("keeps POST create responses v2-only and bound to the submission", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(legacyV1Profile));
    vi.stubGlobal("fetch", fetchMock);

    await expect(createPreferenceProfile(submission)).rejects.toBeInstanceOf(ApiRequestError);
    expect(fetchMock).toHaveBeenCalledWith("/v1/preference-profiles", expect.any(Object));
  });

  it("rejects a POST create response whose answers differ from the submission", async () => {
    const mismatched = v2Profile({
      request_id: submission.request_id,
      answers: { ...v2Answers, q12: 3 },
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(mismatched)));

    await expect(createPreferenceProfile(submission)).rejects.toBeInstanceOf(ApiRequestError);
  });

  it("accepts a POST create response that echoes the v2 submission exactly", async () => {
    const echoed = v2Profile({ request_id: submission.request_id });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(echoed)));

    const profile = await createPreferenceProfile(submission);

    expect(profile.profile_id).toBe(echoed.profile_id);
  });
});
