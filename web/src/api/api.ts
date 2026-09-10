import previousCopyArtifact from "../../../contracts/questionnaire-v2-20260908.json";
import legacyChoiceArtifact from "../../../contracts/questionnaire-v2-legacy.json";
import questionnaireArtifact from "../../../contracts/questionnaire-v2.json";
import type { components } from "../contracts/generated/api";
import { FRONTEND_QUESTIONNAIRE } from "../content/questionnaire";
import {
  groundedTripForRecommendation,
  parseGroundedTripInput,
  type GroundedTripInput,
} from "../features/journey/groundedTrip";
import {
  DESCRIPTION_TEMPLATE_VERSION,
  LEGACY_CONFIG_HASH,
  LEGACY_PROFILE_SCHEMA_VERSION,
  LEGACY_QUESTIONNAIRE_VERSION,
  LEGACY_SCORING_VERSION,
  PROFILE_SCHEMA_VERSION,
  SCORING_VERSION,
  questionnaireAnswersSchema,
  legacyQuestionnaireAnswersSchema,
  tripConditionsSchema,
  type QuestionnaireAnswers,
  type TripConditions,
} from "../app/schemas";

export type QuestionnaireDefinition = components["schemas"]["QuestionnaireDefinitionV2"];
export type QuestionnaireSubmission = components["schemas"]["QuestionnaireSubmission"];
export type PreferenceProfile = components["schemas"]["PreferenceProfile"];
export type RecommendationRequest = components["schemas"]["RecommendationRequest"] & {
  grounded_input?: GroundedTripInput | null;
};
export type RecommendationRunCreated = components["schemas"]["RecommendationRunCreated"];
export type RecommendationRun = components["schemas"]["RecommendationRun"];
export type RecommendationResultsResponse =
  | components["schemas"]["RecommendationResultsResponse"]
  | components["schemas"]["MvpRecommendationResultsResponse"];
export type RecommendationDetail =
  | components["schemas"]["RecommendationDetail"]
  | components["schemas"]["MvpRecommendationDetail"];
export type ComparisonRow = components["schemas"]["ComparisonRow"];
export type RecommendationComparisonResponse =
  components["schemas"]["RecommendationComparisonResponse"];
export type SavedPlaceProjection = components["schemas"]["SavedPlaceProjection"];
export type OperatingInformationResponse =
  components["schemas"]["OperatingInformationResponse"];
export type PlaceOperatingInformation =
  components["schemas"]["PlaceOperatingInformation"];
export type RecommendationErrorResponse = components["schemas"]["RecommendationErrorResponse"];

const canonicalQuestionnaire = questionnaireArtifact;

export class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly body: unknown = null,
  ) {
    super(message);
    this.name = "ApiRequestError";
  }
}

export class QuestionnaireContractError extends Error {
  constructor() {
    super("served questionnaire does not match the expected scoring contract");
    this.name = "QuestionnaireContractError";
  }
}

export class RecommendationContractError extends Error {
  constructor(
    readonly code: "NO_ACTIVE_SCORED_RELEASE" | "INVALID_RECOMMENDATION_OUTPUT",
  ) {
    super(code);
    this.name = "RecommendationContractError";
  }
}

type RequestOptions = {
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonEquals(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => jsonEquals(value, right[index]))
    );
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && jsonEquals(left[key], right[key]),
    )
  );
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function canonicalSha256(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalJson(value)),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isAxisScore(value: unknown, expectedAxis: string): boolean {
  if (!isRecord(value) || !hasExactKeys(value, ["axis", "basis_points", "display_score"])) {
    return false;
  }
  const basisPoints = value.basis_points;
  const displayScore = value.display_score;
  return (
    value.axis === expectedAxis &&
    typeof basisPoints === "number" &&
    Number.isInteger(basisPoints) &&
    basisPoints >= 0 &&
    basisPoints <= 10_000 &&
    typeof displayScore === "number" &&
    Number.isInteger(displayScore) &&
    displayScore >= 0 &&
    displayScore <= 100 &&
    displayScore === Math.floor((basisPoints + 50) / 100)
  );
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return (await response.json()) as unknown;
  } catch {
    throw new ApiRequestError("응답 형식을 확인하지 못했어요.", response.status);
  }
}

/** Display copy is frontend-owned; only fields that bind answers to scoring are checked. */
function questionnaireScoringContract(value: unknown): unknown {
  if (!isRecord(value) || !Array.isArray(value.questions)) return null;
  return {
    questionnaire_version: value.questionnaire_version,
    scoring_version: value.scoring_version,
    description_template_version: value.description_template_version,
    config_hash: value.config_hash,
    question_order: value.question_order,
    axis_tie_break: value.axis_tie_break,
    scoring_matrix: value.scoring_matrix,
    questions: value.questions.map((question: unknown) => {
      if (!isRecord(question) || !Array.isArray(question.options)) return null;
      return {
        question_id: question.question_id,
        ordinal: question.ordinal,
        options: question.options.map((option: unknown) => {
          if (!isRecord(option)) return null;
          return { choice_id: option.choice_id, value: option.value, axis: option.axis };
        }),
      };
    }),
  };
}

export async function fetchCurrentQuestionnaire(
  options: RequestOptions = {},
): Promise<QuestionnaireDefinition> {
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl("/v1/questionnaires/current", { signal: options.signal });
  } catch {
    throw new ApiRequestError("질문을 불러오지 못했어요.", null);
  }
  if (!response.ok) {
    throw new ApiRequestError("질문을 불러오지 못했어요.", response.status);
  }
  const payload = await readJson(response);
  if (!jsonEquals(questionnaireScoringContract(payload), questionnaireScoringContract(canonicalQuestionnaire))) {
    throw new QuestionnaireContractError();
  }
  return FRONTEND_QUESTIONNAIRE;
}

type VersionCoupling = {
  schema_version: string;
  questionnaire_version: string;
  scoring_version: string;
  config_hash: string;
  description_template_version: string;
};

const V2_COUPLING: VersionCoupling = {
  schema_version: PROFILE_SCHEMA_VERSION,
  questionnaire_version: canonicalQuestionnaire.questionnaire_version,
  scoring_version: SCORING_VERSION,
  config_hash: canonicalQuestionnaire.config_hash,
  description_template_version: DESCRIPTION_TEMPLATE_VERSION,
};

const LEGACY_V2_COUPLING: VersionCoupling = {
  ...V2_COUPLING,
  scoring_version: legacyChoiceArtifact.scoring_version,
  config_hash: legacyChoiceArtifact.config_hash,
};

const PREVIOUS_COPY_V2_COUPLING: VersionCoupling = {
  ...V2_COUPLING,
  scoring_version: previousCopyArtifact.scoring_version,
  config_hash: previousCopyArtifact.config_hash,
};

const V1_COUPLING: VersionCoupling = {
  schema_version: LEGACY_PROFILE_SCHEMA_VERSION,
  questionnaire_version: LEGACY_QUESTIONNAIRE_VERSION,
  scoring_version: LEGACY_SCORING_VERSION,
  config_hash: LEGACY_CONFIG_HASH,
  description_template_version: DESCRIPTION_TEMPLATE_VERSION,
};

function matchesVersionCoupling(payload: Record<string, unknown>, coupling: VersionCoupling): boolean {
  return (
    payload.schema_version === coupling.schema_version &&
    payload.questionnaire_version === coupling.questionnaire_version &&
    payload.scoring_version === coupling.scoring_version &&
    payload.config_hash === coupling.config_hash &&
    payload.description_template_version === coupling.description_template_version
  );
}

function isPreferenceProfileShape(payload: unknown): payload is PreferenceProfile {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "answers",
      "config_hash",
      "created_at",
      "description_ko",
      "description_template_version",
      "is_current_trip_expectation",
      "profile_id",
      "questionnaire_version",
      "request_id",
      "schema_version",
      "scores",
      "scoring_version",
      "trip_conditions",
    ]) &&
    typeof payload.profile_id === "string" &&
    payload.profile_id.trim().length > 0 &&
    payload.profile_id.length <= 160 &&
    typeof payload.request_id === "string" &&
    payload.request_id.trim().length > 0 &&
    payload.request_id.length <= 160 &&
    payload.is_current_trip_expectation === true &&
    typeof payload.created_at === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(payload.created_at) &&
    Number.isFinite(Date.parse(payload.created_at)) &&
    typeof payload.description_ko === "string" &&
    payload.description_ko.trim().length > 0 &&
    payload.description_ko.length <= 500 &&
    Array.isArray(payload.scores) &&
    payload.scores.length === canonicalQuestionnaire.axis_tie_break.length &&
    payload.scores.every((score, index) =>
      isAxisScore(score, canonicalQuestionnaire.axis_tie_break[index] ?? ""),
    ) &&
    tripConditionsSchema.safeParse(payload.trip_conditions).success
  );
}

function isPreferenceProfileV2(
  payload: unknown,
  submission?: QuestionnaireSubmission,
): payload is PreferenceProfile {
  return (
    isPreferenceProfileShape(payload) &&
    (matchesVersionCoupling(payload, V2_COUPLING) ||
      matchesVersionCoupling(payload, LEGACY_V2_COUPLING) ||
      matchesVersionCoupling(payload, PREVIOUS_COPY_V2_COUPLING)) &&
    questionnaireAnswersSchema.safeParse(payload.answers).success &&
    (submission === undefined ||
      (payload.request_id === submission.request_id &&
        jsonEquals(payload.answers, submission.answers) &&
        jsonEquals(payload.trip_conditions, submission.trip_conditions)))
  );
}

function isPreferenceProfileV1(payload: unknown): payload is PreferenceProfile {
  return (
    isPreferenceProfileShape(payload) &&
    matchesVersionCoupling(payload, V1_COUPLING) &&
    legacyQuestionnaireAnswersSchema.safeParse(payload.answers).success
  );
}

/**
 * GET-served stored profiles: current questionnaire-v2 profiles and legacy
 * questionnaire-v1 profiles, each validated strictly against its own
 * generation. POST create responses stay v2-only (see createPreferenceProfile).
 */
function isStoredPreferenceProfile(payload: unknown): payload is PreferenceProfile {
  return isPreferenceProfileV2(payload) || isPreferenceProfileV1(payload);
}

export async function profileSubmissionFingerprint(
  tripConditions: TripConditions,
  answers: QuestionnaireAnswers,
): Promise<string>;
/**
 * Legacy overload: fingerprints a stored questionnaire-v1 profile with its own
 * generation's version tuple so pending/current recommendation records keyed
 * to that profile keep matching byte-for-byte. Never submits v1 answers.
 */
export async function profileSubmissionFingerprint(
  tripConditions: TripConditions,
  profile: PreferenceProfile,
): Promise<string>;
export async function profileSubmissionFingerprint(
  tripConditions: TripConditions,
  answersOrProfile: QuestionnaireAnswers | PreferenceProfile,
): Promise<string> {
  const isProfile = (
    value: QuestionnaireAnswers | PreferenceProfile,
  ): value is PreferenceProfile =>
    isRecord(value) && "questionnaire_version" in value && "config_hash" in value;
  if (isProfile(answersOrProfile)) {
    const profile = answersOrProfile;
    const material = {
      questionnaire_version: profile.questionnaire_version,
      scoring_version: profile.scoring_version,
      description_template_version: profile.description_template_version,
      config_hash: profile.config_hash,
      trip_conditions: tripConditions,
      answers: profile.answers,
    };
    return canonicalSha256(material);
  }
  const material = {
    questionnaire_version: canonicalQuestionnaire.questionnaire_version,
    scoring_version: canonicalQuestionnaire.scoring_version,
    description_template_version: canonicalQuestionnaire.description_template_version,
    config_hash: canonicalQuestionnaire.config_hash,
    trip_conditions: tripConditions,
    answers: answersOrProfile,
  };
  return canonicalSha256(material);
}

export async function createPreferenceProfile(
  submission: QuestionnaireSubmission,
  options: RequestOptions = {},
): Promise<PreferenceProfile> {
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl("/v1/preference-profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(submission),
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch {
    throw new ApiRequestError("프로필을 만들지 못했어요.", null);
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = (await response.json()) as unknown;
    } catch {
      // Preserve a null body for non-JSON failures without hiding the HTTP status.
    }
    throw new ApiRequestError("프로필을 만들지 못했어요.", response.status, body);
  }
  const payload = await readJson(response);
  if (!isPreferenceProfileV2(payload, submission)) {
    throw new ApiRequestError("프로필 형식을 확인하지 못했어요.", response.status);
  }
  return payload;
}

export async function fetchPreferenceProfile(
  profileId: string,
  options: RequestOptions = {},
): Promise<PreferenceProfile> {
  const normalizedId = profileId.trim();
  if (normalizedId.length === 0 || normalizedId.length > 160) {
    throw new ApiRequestError("프로필 형식을 확인하지 못했어요.", null);
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(`/v1/preference-profiles/${encodeURIComponent(normalizedId)}`, {
      credentials: "same-origin",
      signal: options.signal,
    });
  } catch {
    throw new ApiRequestError("프로필을 만들지 못했어요.", null);
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = (await response.json()) as unknown;
    } catch {
      // Preserve status when an upstream failure has no JSON response body.
    }
    throw new ApiRequestError("프로필을 만들지 못했어요.", response.status, body);
  }
  const payload = await readJson(response);
  if (!isStoredPreferenceProfile(payload) || payload.profile_id !== normalizedId) {
    throw new ApiRequestError("프로필 형식을 확인하지 못했어요.", response.status);
  }
  return payload;
}

function isStableId(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 160;
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isScore(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100;
}

function isIsoDate(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1 || month < 1 || month > 12 || day < 1) return false;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= daysInMonth[month - 1]!;
}

function isUtcDateTime(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-]00:?00)$/.exec(
    value,
  );
  return (
    match !== null &&
    isIsoDate(match[1]) &&
    Number(match[2]) <= 23 &&
    Number(match[3]) <= 59 &&
    Number(match[4]) <= 59
  );
}

function isVersion(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    /^[a-z0-9][a-z0-9._-]*$/.test(value)
  );
}

type JsonObject = Record<string, unknown>;
type ScoreContributionPayload = JsonObject & {
  axis_components: JsonObject[];
  condition_components: JsonObject[];
  experience_fit_score: number;
  travel_condition_fit_score: number;
  relevance_score: number;
  relevance_numerator: number;
  diversity_novelty_score: number;
  rerank_score: number;
  rerank_numerator: number;
};

const CONFIDENCE_REASON = {
  EVIDENCE_AUDIT_ONLY: "확인된 근거가 매우 제한되어 참고 정보로만 보여드려요.",
  EVIDENCE_LIMITED_MISMATCH_SUPPRESSED: "확인된 근거가 제한되어 기대 차이 안내를 생략했어요.",
  EVIDENCE_LIMITED_MISMATCH_AVAILABLE: "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요.",
  EVIDENCE_SUPPORTED: "확인된 근거 범위에서 안내해요.",
} as const;

type EvidenceConfidenceState = keyof typeof CONFIDENCE_REASON;

function confidenceStateFor(confidence: number): EvidenceConfidenceState | null {
  if (!isScore(confidence)) return null;
  if (confidence < 55) return "EVIDENCE_AUDIT_ONLY";
  if (confidence < 65) return "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED";
  if (confidence < 70) return "EVIDENCE_LIMITED_MISMATCH_AVAILABLE";
  return "EVIDENCE_SUPPORTED";
}

function isConfidenceProjection(
  payload: JsonObject,
  confidence: number | null,
): boolean {
  const state = confidenceStateFor(confidence ?? -1);
  return (
    state !== null &&
    payload.evidence_confidence_state === state &&
    payload.evidence_confidence_reason_ko === CONFIDENCE_REASON[state]
  );
}

function isCurrentAuthority(payload: unknown): payload is JsonObject {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "activation_suite_sha256",
      "cannot_coappear_authority_sha256",
      "contrast_suite_sha256",
      "hard_duplicate_adjudication_sha256",
      "recovery_policy_sha256",
    ]) &&
    payload.activation_suite_sha256 ===
      "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659" &&
    payload.cannot_coappear_authority_sha256 ===
      "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70" &&
    payload.contrast_suite_sha256 ===
      "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9" &&
    payload.hard_duplicate_adjudication_sha256 ===
      "32905425be2491414797c0bdc026314de91cdd979abca7cd6d721df3370a8d22" &&
    payload.recovery_policy_sha256 ===
      "8cf0d41d64fb987b0ac3c146a5045ef34efe7f12c2a1b3268730bdac97b65300"
  );
}

const recommendationAxes = [
  "HISTORY_TRADITION",
  "EMOTION_IMAGE",
  "REST_IMMERSION",
] as const;
const recommendationConditions = [
  "VISIT_DATE_TIME",
  "COMPANIONS",
  "TRANSPORT",
  "WALKING",
  "INDOOR_OUTDOOR",
  "CROWD",
] as const;

function isPlaceAxisSnapshot(payload: unknown, expectedAxis: string): boolean {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, ["axis", "evidence_ids", "value"]) &&
    payload.axis === expectedAxis &&
    isScore(payload.value) &&
    Array.isArray(payload.evidence_ids) &&
    payload.evidence_ids.length >= 1 &&
    payload.evidence_ids.length <= 8 &&
    payload.evidence_ids.every(isStableId)
  );
}

function isIntegerInRange(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function halfUp(numerator: number, denominator: number): number {
  return Math.floor((numerator + Math.floor(denominator / 2)) / denominator);
}

function observedConditionWeights(components: JsonObject[]): number[] {
  const base = [400, 350, 350, 350, 300, 250];
  const active = components.map((row) => row.expected_value !== null && row.place_value !== null);
  const total = base.reduce((sum, weight, index) => sum + (active[index] ? weight : 0), 0);
  if (total === 0) return base.map(() => 0);
  const weights = base.map((weight, index) => active[index] ? Math.floor(weight * 2_000 / total) : 0);
  const order = base.map((weight, index) => ({ index, remainder: active[index] ? weight * 2_000 % total : -1 }))
    .sort((left, right) => right.remainder - left.remainder || left.index - right.index);
  const remaining = 2_000 - weights.reduce((sum, weight) => sum + weight, 0);
  for (const { index } of order.slice(0, remaining)) weights[index]! += 1;
  return weights;
}

function isScoreContribution(payload: unknown, quality = false): payload is ScoreContributionPayload {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "axis_components",
      "condition_components",
      "experience_fit_score",
      "travel_condition_fit_score",
      "relevance_score",
      "relevance_numerator",
      "diversity_novelty_score",
      "rerank_score",
      "rerank_numerator",
    ]) ||
    !Array.isArray(payload.axis_components) ||
    payload.axis_components.length !== recommendationAxes.length ||
    !Array.isArray(payload.condition_components) ||
    payload.condition_components.length !== recommendationConditions.length ||
    !isScore(payload.experience_fit_score) ||
    !isScore(payload.travel_condition_fit_score) ||
    !isScore(payload.relevance_score) ||
    !isIntegerInRange(payload.relevance_numerator, 0, Number.MAX_SAFE_INTEGER) ||
    !isScore(payload.diversity_novelty_score) ||
    !isScore(payload.rerank_score) ||
    !isIntegerInRange(payload.rerank_numerator, 0, Number.MAX_SAFE_INTEGER)
  ) {
    return false;
  }

  const axisComponents = payload.axis_components;
  const conditionComponents = payload.condition_components;
  if (!conditionComponents.every(isRecord)) return false;
  const conditionWeights = quality
    ? observedConditionWeights(conditionComponents)
    : [400, 350, 350, 350, 300, 250];
  if (
    !axisComponents.every(
      (component, index) =>
        isRecord(component) &&
        hasExactKeys(component, [
          "contribution_id",
          "axis",
          "expected_value",
          "place_value",
          "absolute_difference",
          "fit_score",
        ]) &&
        isStableId(component.contribution_id) &&
        component.axis === recommendationAxes[index] &&
        isScore(component.expected_value) &&
        isScore(component.place_value) &&
        isScore(component.absolute_difference) &&
        isScore(component.fit_score) &&
        component.absolute_difference ===
          Math.abs(Number(component.expected_value) - Number(component.place_value)) &&
        component.fit_score === 100 - Number(component.absolute_difference),
    ) ||
    !conditionComponents.every(
      (component, index) =>
        isRecord(component) &&
        hasExactKeys(component, [
          "contribution_id",
          "condition_id",
          "expected_value",
          "place_value",
          "absolute_difference",
          "fit_score",
          "total_score_weight_bp",
          "weighted_numerator",
        ]) &&
        isStableId(component.contribution_id) &&
        component.condition_id === recommendationConditions[index] &&
        (isScore(component.expected_value) || (quality && component.expected_value === null)) &&
        (isScore(component.place_value) || (quality && component.place_value === null)) &&
        component.total_score_weight_bp === conditionWeights[index] &&
        isIntegerInRange(component.weighted_numerator, 0, Number.MAX_SAFE_INTEGER) &&
        (quality && (component.expected_value === null || component.place_value === null)
          ? component.absolute_difference === null && component.fit_score === null &&
            component.total_score_weight_bp === 0 && component.weighted_numerator === 0
          : isScore(component.absolute_difference) && isScore(component.fit_score) && component.absolute_difference ===
          Math.abs(Number(component.expected_value) - Number(component.place_value)) &&
        component.fit_score === 100 - Number(component.absolute_difference) &&
        component.weighted_numerator ===
          Number(component.fit_score) * Number(component.total_score_weight_bp)),
    )
  ) {
    return false;
  }

  const contributionIds = [
    ...axisComponents.map((component) => component.contribution_id),
    ...conditionComponents.map((component) => component.contribution_id),
  ];
  if (new Set(contributionIds).size !== contributionIds.length) return false;
  const axisFit = axisComponents.reduce(
    (total, component) => total + Number(component.fit_score),
    0,
  );
  const expectedConditionNumerator = conditionComponents.reduce(
    (total, component) => total + Number(component.weighted_numerator),
    0,
  );
  const expectedTravelConditionFit = halfUp(expectedConditionNumerator, 2_000);
  const conditionWeight = conditionWeights.some((weight) => weight > 0) ? 2_000 : 0;
  const expectedRelevanceNumerator =
    Number(payload.experience_fit_score) * 8_000 + expectedTravelConditionFit * conditionWeight;
  if (
    payload.experience_fit_score !== halfUp(axisFit, recommendationAxes.length) ||
    payload.travel_condition_fit_score !== expectedTravelConditionFit ||
    payload.relevance_numerator !== expectedRelevanceNumerator ||
    payload.relevance_score !== halfUp(expectedRelevanceNumerator, 8_000 + conditionWeight) ||
    payload.rerank_numerator !==
      payload.relevance_score * 8_500 + payload.diversity_novelty_score * 1_500 ||
    payload.rerank_score !== halfUp(payload.rerank_numerator, 10_000)
  ) {
    return false;
  }
  return true;
}

function isMismatchGuidance(payload: unknown): payload is JsonObject {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "axis_distance",
      "effective_score",
      "important_trait_floor_applied",
      "message_ko",
      "raw_score",
      "state",
      "suppression_reason",
      "template_id",
      "trait_distance",
    ]) ||
    !isScore(payload.raw_score) ||
    !isScore(payload.effective_score) ||
    !isScore(payload.axis_distance) ||
    !isScore(payload.trait_distance) ||
    typeof payload.important_trait_floor_applied !== "boolean"
  ) {
    return false;
  }
  const state = payload.state;
  if (
    state !== "NO_GUIDANCE" &&
    state !== "GENTLE_DIFFERENCE" &&
    state !== "MATERIAL_DIFFERENCE" &&
    state !== "STRONG_DIFFERENCE" &&
    state !== "SUPPRESSED_LOW_CONFIDENCE"
  ) {
    return false;
  }
  const effectiveScore = Number(payload.effective_score);
  const expectedEffective = payload.important_trait_floor_applied
    ? Math.max(Number(payload.raw_score), 50)
    : Number(payload.raw_score);
  if (
    payload.raw_score !==
      halfUp(
        Number(payload.axis_distance) * 6_500 + Number(payload.trait_distance) * 3_500,
        10_000,
      ) ||
    payload.effective_score !== expectedEffective
  ) {
    return false;
  }
  if (
    state !== "SUPPRESSED_LOW_CONFIDENCE" &&
    ((effectiveScore < 30 && state !== "NO_GUIDANCE") ||
      (effectiveScore >= 30 && state === "NO_GUIDANCE"))
  ) {
    return false;
  }
  const templateId = payload.template_id;
  const message = payload.message_ko;
  const suppressionReason = payload.suppression_reason;
  const validMessage =
    message === null ||
    (typeof message === "string" && message.trim().length > 0 && message.length <= 200);
  if (
    (templateId !== null && !isStableId(templateId)) ||
    !validMessage ||
    (suppressionReason !== null && suppressionReason !== "CONFIDENCE_BELOW_65")
  ) {
    return false;
  }
  if (state === "SUPPRESSED_LOW_CONFIDENCE") {
    return suppressionReason === "CONFIDENCE_BELOW_65" && templateId === null && message === null;
  }
  if (suppressionReason !== null) return false;
  if (state === "NO_GUIDANCE") return templateId === null && message === null;
  if (templateId === null || typeof message !== "string" || message.trim().length === 0) {
    return false;
  }
  const expectedRange =
    state === "GENTLE_DIFFERENCE"
      ? [30, 45]
      : state === "MATERIAL_DIFFERENCE"
        ? [45, 60]
        : [60, 101];
  return effectiveScore >= expectedRange[0] && effectiveScore < expectedRange[1];
}

function isRecommendationItem(payload: unknown, rank: number): boolean {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "axis_scores",
      "contribution",
      "evidence",
      "evidence_confidence_reason_ko",
      "evidence_confidence_state",
      "explanations",
      "fit_score",
      "image_state",
      "mismatch",
      "place_id",
      "place_name_ko",
      "rank",
      "reference_date",
    ]) ||
    payload.rank !== rank ||
    !isStableId(payload.place_id) ||
    typeof payload.place_name_ko !== "string" ||
    payload.place_name_ko.trim().length === 0 ||
    payload.place_name_ko.length > 120 ||
    !isScore(payload.fit_score) ||
    ![...Object.keys(CONFIDENCE_REASON)].includes(String(payload.evidence_confidence_state)) ||
    typeof payload.evidence_confidence_reason_ko !== "string" ||
    payload.evidence_confidence_reason_ko !==
      CONFIDENCE_REASON[payload.evidence_confidence_state as EvidenceConfidenceState] ||
    !isIsoDate(payload.reference_date) ||
    !["ABSENT", "RIGHTS_RESTRICTED", "DISPLAY_ASSET_AVAILABLE"].includes(
      String(payload.image_state),
    ) ||
    !Array.isArray(payload.axis_scores) ||
    payload.axis_scores.length !== 3 ||
    !Array.isArray(payload.explanations) ||
    payload.explanations.length < 2 ||
    payload.explanations.length > 6 ||
    !Array.isArray(payload.evidence) ||
    payload.evidence.length < 1 ||
    payload.evidence.length > 6 ||
    !isRecord(payload.mismatch) ||
    !isRecord(payload.contribution)
  ) {
    return false;
  }

  const axes = ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"];
  if (
    !payload.axis_scores.every(
      (axis, index) =>
        isRecord(axis) &&
        hasExactKeys(axis, ["axis", "evidence_ids", "value"]) &&
        axis.axis === axes[index] &&
        isScore(axis.value) &&
        Array.isArray(axis.evidence_ids) &&
        axis.evidence_ids.length >= 1 &&
        axis.evidence_ids.length <= 8 &&
        axis.evidence_ids.every(isStableId),
    )
  ) {
    return false;
  }

  if (
    !payload.evidence.every(
      (evidence) =>
        isRecord(evidence) &&
        hasExactKeys(evidence, [
          "attribution_ko",
          "contest_rights_qualified",
          "contest_use_scope",
          "evidence_id",
          "excerpt_ko",
          "reference_date",
          "source_label_ko",
        ]) &&
        isStableId(evidence.evidence_id) &&
        typeof evidence.excerpt_ko === "string" &&
        evidence.excerpt_ko.trim().length > 0 &&
        evidence.excerpt_ko.length <= 240 &&
        typeof evidence.source_label_ko === "string" &&
        evidence.source_label_ko.trim().length > 0 &&
        evidence.source_label_ko.length <= 100 &&
        typeof evidence.attribution_ko === "string" &&
        evidence.attribution_ko.trim().length > 0 &&
        evidence.attribution_ko.length <= 180 &&
        evidence.contest_use_scope === "noncommercial_contest_demo_evaluation" &&
        evidence.contest_rights_qualified === true &&
        evidence.reference_date === payload.reference_date,
    ) ||
    new Set(
      payload.evidence.map(
        (evidence) => (evidence as Record<string, unknown>).evidence_id,
      ),
    ).size !==
      payload.evidence.length ||
    !payload.explanations.every(
      (reason) =>
        isRecord(reason) &&
        hasExactKeys(reason, [
          "contribution_id",
          "evidence_id",
          "message_ko",
          "place_attribute_id",
          "reference_date",
          "template_id",
        ]) &&
        isStableId(reason.contribution_id) &&
        isStableId(reason.evidence_id) &&
        isStableId(reason.place_attribute_id) &&
        isStableId(reason.template_id) &&
        reason.reference_date === payload.reference_date &&
        typeof reason.message_ko === "string" &&
        reason.message_ko.trim().length > 0 &&
        reason.message_ko.length <= 200,
    )
  ) {
    return false;
  }

  const itemEvidenceIds = new Set(
    payload.evidence.map(
      (evidence) => (evidence as Record<string, unknown>).evidence_id,
    ),
  );
  if (
    !payload.explanations.every(
      (reason) =>
        itemEvidenceIds.has((reason as Record<string, unknown>).evidence_id),
    ) ||
    itemEvidenceIds.size !==
      new Set(
        payload.explanations.map(
          (reason) => (reason as Record<string, unknown>).evidence_id,
        ),
      ).size
  ) {
    return false;
  }

  const explanationPairKeys = new Set(
    payload.explanations.map((reason) => {
      const explanation = reason as JsonObject;
      return JSON.stringify([explanation.contribution_id, explanation.evidence_id]);
    }),
  );
  if (explanationPairKeys.size !== payload.explanations.length) return false;

  if (!isScoreContribution(payload.contribution)) return false;
  const contributionIds = new Set([
    ...payload.contribution.axis_components.map(
      (component) => (component as JsonObject).contribution_id,
    ),
    ...payload.contribution.condition_components.map(
      (component) => (component as JsonObject).contribution_id,
    ),
  ]);
  const axisById = new Map(
    payload.axis_scores.map((axis) => {
      const record = axis as JsonObject;
      return [record.axis, record] as const;
    }),
  );
  if (
    !payload.explanations.every((reason) => {
      const explanation = reason as JsonObject;
      const axis = axisById.get(explanation.place_attribute_id);
      return (
        contributionIds.has(explanation.contribution_id) &&
        axis !== undefined &&
        Array.isArray(axis.evidence_ids) &&
        axis.evidence_ids.includes(explanation.evidence_id)
      );
    })
  ) {
    return false;
  }

  return isMismatchGuidance(payload.mismatch);
}

const candidateExclusionReasons = new Set([
  "NOT_DEV",
  "NOT_EXACT_RELEASE_MEMBER",
  "NOT_LOCAL_PROFILE_SCORES",
  "NOT_DEMO_MODEL_DERIVED",
  "NOT_PUBLISHABLE",
  "NOT_RECOMMENDATION_ELIGIBLE",
  "HARD_DUPLICATE",
]);

function isCandidateExclusion(payload: unknown): payload is JsonObject {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, ["place_id", "reason"]) &&
    isStableId(payload.place_id) &&
    candidateExclusionReasons.has(String(payload.reason))
  );
}

function isDuplicateDecision(payload: unknown): payload is JsonObject {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "duplicate_group_id",
      "kept_place_id",
      "suppressed_place_ids",
    ]) &&
    isStableId(payload.duplicate_group_id) &&
    isStableId(payload.kept_place_id) &&
    Array.isArray(payload.suppressed_place_ids) &&
    payload.suppressed_place_ids.length >= 1 &&
    payload.suppressed_place_ids.every(isStableId) &&
    new Set(payload.suppressed_place_ids).size === payload.suppressed_place_ids.length
  );
}

function isCandidateScoreTrace(payload: unknown): payload is JsonObject {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "contribution",
      "experience_fit_score",
      "mismatch",
      "place_id",
      "relevance_score",
      "travel_condition_fit_score",
    ]) ||
    !isStableId(payload.place_id) ||
    !isScore(payload.relevance_score) ||
    !isScore(payload.experience_fit_score) ||
    !isScore(payload.travel_condition_fit_score) ||
    !isScoreContribution(payload.contribution) ||
    !isMismatchGuidance(payload.mismatch)
  ) {
    return false;
  }
  return (
    payload.relevance_score === payload.contribution.relevance_score &&
    payload.experience_fit_score === payload.contribution.experience_fit_score &&
    payload.travel_condition_fit_score === payload.contribution.travel_condition_fit_score
  );
}

function isDiversityCandidateScore(payload: unknown): payload is JsonObject {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "combined_score",
      "novelty_score",
      "place_id",
      "relevance_score",
    ]) &&
    isStableId(payload.place_id) &&
    isScore(payload.relevance_score) &&
    isScore(payload.novelty_score) &&
    isScore(payload.combined_score) &&
    payload.combined_score ===
      halfUp(Number(payload.relevance_score) * 8_500 + Number(payload.novelty_score) * 1_500, 10_000)
  );
}

function isDiversityStep(payload: unknown): payload is JsonObject {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "combined_score",
      "considered",
      "novelty_score",
      "rank",
      "relevance_score",
      "selected_place_id",
    ]) ||
    !isIntegerInRange(payload.rank, 1, 5) ||
    !isStableId(payload.selected_place_id) ||
    !isScore(payload.relevance_score) ||
    !isScore(payload.novelty_score) ||
    !isScore(payload.combined_score) ||
    !Array.isArray(payload.considered) ||
    payload.considered.length < 1 ||
    !payload.considered.every(isDiversityCandidateScore)
  ) {
    return false;
  }
  const considered = payload.considered as JsonObject[];
  const selected = considered.filter((row) => row.place_id === payload.selected_place_id);
  return (
    new Set(considered.map((row) => row.place_id)).size === considered.length &&
    selected.length === 1 &&
    selected[0]!.relevance_score === payload.relevance_score &&
    selected[0]!.novelty_score === payload.novelty_score &&
    selected[0]!.combined_score === payload.combined_score
  );
}

function isMvpEvidenceSnippet(payload: unknown): boolean {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "attribution_ko", "evidence_id", "evidence_sha256", "excerpt_ko",
      "license_type", "official_dataset_id", "official_license_url",
      "permission_metadata_sha256", "provider", "reference_date", "schema_version",
      "source_label_ko", "source_response_sha256", "usage_state",
    ]) &&
    payload.schema_version === "mvp-evidence-snippet.v1" &&
    isStableId(payload.evidence_id) && isSha256(payload.evidence_sha256) &&
    isSha256(payload.permission_metadata_sha256) && isSha256(payload.source_response_sha256) &&
    typeof payload.excerpt_ko === "string" && payload.excerpt_ko.trim().length >= 1 && payload.excerpt_ko.length <= 4000 &&
    typeof payload.attribution_ko === "string" && payload.attribution_ko.trim().length >= 1 && payload.attribution_ko.length <= 500 &&
    typeof payload.source_label_ko === "string" && payload.source_label_ko.trim().length >= 1 && payload.source_label_ko.length <= 100 &&
    ["TOUR_API", "ODII"].includes(String(payload.provider)) &&
    ["15101578", "15101971"].includes(String(payload.official_dataset_id)) &&
    typeof payload.official_license_url === "string" &&
    payload.official_license_url.trim().length >= 1 &&
    payload.official_license_url.length <= 500 &&
    typeof payload.license_type === "string" &&
    payload.license_type.trim().length >= 1 &&
    payload.license_type.length <= 120 &&
    isIsoDate(payload.reference_date) && payload.usage_state === "STRICT_PUBLIC_USAGE_ALLOWED"
  );
}

function isMvpRecommendationItem(
  payload: unknown,
  rank: number,
  requireBaseFit = true,
  quality = false,
): boolean {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "axis_scores",
      "contribution",
      "evidence",
      "evidence_confidence_reason_ko",
      "evidence_confidence_state",
      "explanations",
      "fit_score",
      "image_state",
      "mismatch",
      "place_id",
      "place_name_ko",
      "rank",
      "reference_date",
    ]) ||
    payload.rank !== rank ||
    !isStableId(payload.place_id) ||
    typeof payload.place_name_ko !== "string" ||
    payload.place_name_ko.trim().length === 0 ||
    payload.place_name_ko.length > 240 ||
    !isScore(payload.fit_score) ||
    !isIsoDate(payload.reference_date) ||
    payload.image_state !== "ABSENT" ||
    !Object.keys(CONFIDENCE_REASON).includes(String(payload.evidence_confidence_state)) ||
    payload.evidence_confidence_reason_ko !==
      CONFIDENCE_REASON[payload.evidence_confidence_state as EvidenceConfidenceState] ||
    !isMismatchGuidance(payload.mismatch) ||
    !isScoreContribution(payload.contribution, quality) ||
    (requireBaseFit && payload.fit_score !== payload.contribution.relevance_score) ||
    !Array.isArray(payload.axis_scores) ||
    payload.axis_scores.length !== recommendationAxes.length ||
    !payload.axis_scores.every((row, index) =>
      isPlaceAxisSnapshot(row, recommendationAxes[index]!),
    ) ||
    !Array.isArray(payload.evidence) ||
    payload.evidence.length < 1 ||
    payload.evidence.length > 6 ||
    !payload.evidence.every(isMvpEvidenceSnippet) ||
    !Array.isArray(payload.explanations) ||
    payload.explanations.length < 2 ||
    payload.explanations.length > 6
  ) {
    return false;
  }
  const evidenceRows = payload.evidence as JsonObject[];
  const evidence = new Map(evidenceRows.map((row) => [String(row.evidence_id), row]));
  const axes = new Map(
    (payload.axis_scores as JsonObject[]).map((row) => [String(row.axis), row]),
  );
  const contributionIds = new Set([
    ...(payload.contribution.axis_components as JsonObject[]).map((row) => row.contribution_id),
    ...(payload.contribution.condition_components as JsonObject[]).map(
      (row) => row.contribution_id,
    ),
  ]);
  const explanationsValid = payload.explanations.every(
    (row) =>
      isRecord(row) &&
      hasExactKeys(row, [
        "contribution_id",
        "evidence_id",
        "message_ko",
        "place_attribute_id",
        "reference_date",
        "template_id",
      ]) &&
      isStableId(row.contribution_id) &&
      contributionIds.has(row.contribution_id) &&
      recommendationAxes.includes(row.place_attribute_id as (typeof recommendationAxes)[number]) &&
      isStableId(row.evidence_id) &&
      isIsoDate(row.reference_date) &&
      evidence.get(String(row.evidence_id))?.reference_date === row.reference_date &&
      ((axes.get(String(row.place_attribute_id))?.evidence_ids as unknown[]) ?? []).includes(
        row.evidence_id,
      ) &&
      isStableId(row.template_id) &&
      typeof row.message_ko === "string" &&
      row.message_ko.trim().length > 0 &&
      row.message_ko.length <= 200,
  );
  return (
    explanationsValid &&
    new Set(evidenceRows.map((row) => row.evidence_id)).size === evidenceRows.length &&
    new Set((payload.explanations as JsonObject[]).map((row) => row.evidence_id)).size ===
      evidenceRows.length &&
    payload.reference_date ===
      evidenceRows.map((row) => String(row.reference_date)).sort().at(-1)
  );
}

function isGroundedInputAuthority(payload: unknown): boolean {
  if (!isRecord(payload) || !hasExactKeys(payload, ["schema_version", "trip_input_sha256",
    "source_release_sha256", "source_snapshot_sha256", "assessment_bundle_sha256"]) ||
    payload.schema_version !== "grounded-input-authority.v1" ||
    !isSha256(payload.trip_input_sha256) || !isSha256(payload.source_release_sha256)) return false;
  return [payload.source_snapshot_sha256, payload.assessment_bundle_sha256].every((hashes) =>
    Array.isArray(hashes) && hashes.every(isSha256) &&
    hashes.every((hash, index) => index === 0 || hashes[index - 1]! < hash));
}

function isQualityContext(payload: unknown): payload is JsonObject {
  return isRecord(payload) &&
    hasExactKeys(payload, ["companion", "transport", "purpose", "eligible_place_ids",
      ...("grounding" in payload ? ["grounding"] : [])]) &&
    (!("grounding" in payload) || isGroundedInputAuthority(payload.grounding)) &&
    ["SOLO", "FRIEND_OR_PARTNER", "FAMILY_WITH_CHILDREN", "WITH_SENIORS", "GROUP"].includes(String(payload.companion)) &&
    ["WALK_OR_TRANSIT", "CAR_OR_TAXI", "MIXED"].includes(String(payload.transport)) &&
    ["SIGHTSEEING", "FOOD", "LODGING", "MIXED"].includes(String(payload.purpose)) &&
    Array.isArray(payload.eligible_place_ids) && payload.eligible_place_ids.length <= 100 &&
    payload.eligible_place_ids.every(isStableId) &&
    new Set(payload.eligible_place_ids).size === payload.eligible_place_ids.length &&
    payload.eligible_place_ids.every((id, index) => index === 0 || (payload.eligible_place_ids as string[])[index - 1]! < id);
}

function isMvpPreference(payload: unknown, quality = false): boolean {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "axis_targets",
      "condition_targets",
      "input_sha256",
      "profile_id",
      "trait_targets",
      ...(quality ? ["quality_context"] : []),
    ]) ||
    (quality && !isQualityContext(payload.quality_context)) ||
    !isStableId(payload.profile_id) ||
    !isSha256(payload.input_sha256) ||
    !Array.isArray(payload.axis_targets) ||
    payload.axis_targets.length !== 3 ||
    !Array.isArray(payload.condition_targets) ||
    payload.condition_targets.length !== 6 ||
    !Array.isArray(payload.trait_targets) ||
    payload.trait_targets.length !== 6
  ) {
    return false;
  }
  return (
    payload.axis_targets.every(
      (row, index) =>
        isRecord(row) &&
        hasExactKeys(row, ["axis", "value"]) &&
        row.axis === recommendationAxes[index] &&
        isScore(row.value),
    ) &&
    payload.condition_targets.every(
      (row, index) =>
        isRecord(row) &&
        hasExactKeys(row, ["condition_id", "value"]) &&
        row.condition_id === recommendationConditions[index] &&
        (isScore(row.value) || (quality && row.value === null)),
    ) &&
    payload.trait_targets.every(
      (row, index) =>
        isRecord(row) &&
        hasExactKeys(row, ["important", "trait_id", "value"]) &&
        row.trait_id === `M${index + 1}` &&
        typeof row.important === "boolean" &&
        isScore(row.value),
    )
  );
}

function isPhotoScoreTrace(
  payload: unknown,
  expectedBaseRelevance: unknown,
  expectedEffectiveRelevance: unknown,
  semantic = false,
): boolean {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "base_relevance",
      "effective_relevance",
      "explanation_ko",
      "photo_trait_fit",
      "trait_components",
      ...(semantic ? ["observed_traits"] : []),
    ]) ||
    (semantic && (
      !Array.isArray(payload.observed_traits) ||
      payload.observed_traits.length < 1 || payload.observed_traits.length > 6 ||
      !payload.observed_traits.every((trait, index) =>
        typeof trait === "string" && /^M[1-6]$/.test(trait) &&
        (index === 0 || (payload.observed_traits as string[])[index - 1]! < trait))
    )) ||
    !isScore(payload.base_relevance) ||
    payload.base_relevance !== expectedBaseRelevance ||
    !isScore(payload.photo_trait_fit) ||
    !isScore(payload.effective_relevance) ||
    payload.effective_relevance !== expectedEffectiveRelevance ||
    typeof payload.explanation_ko !== "string" ||
    payload.explanation_ko.trim().length === 0 ||
    payload.explanation_ko.length > 160 ||
    !Array.isArray(payload.trait_components) ||
    payload.trait_components.length !== 6
  ) {
    return false;
  }
  const componentsValid = payload.trait_components.every(
    (row, index) =>
      isRecord(row) &&
      hasExactKeys(row, ["actual", "expected", "fit", "trait_id"]) &&
      row.trait_id === `M${index + 1}` &&
      isScore(row.actual) &&
      isScore(row.expected) &&
      isScore(row.fit) &&
      row.fit === 100 - Math.abs(Number(row.expected) - Number(row.actual)),
  );
  if (!componentsValid) return false;
  const observed = (payload.trait_components as JsonObject[]).filter(
    (row) => !semantic || (payload.observed_traits as string[]).includes(String(row.trait_id)),
  );
  const photoFit = halfUp(
    observed.reduce(
      (sum, row) => sum + Number(row.fit),
      0,
    ), observed.length,
  );
  const effective = Math.floor(
    (2 * (Number(payload.base_relevance) * 6_500 + photoFit * 3_500) + 10_000) /
      20_000,
  );
  return payload.photo_trait_fit === photoFit && payload.effective_relevance === effective;
}

function qualityRunBindings(payload: JsonObject): boolean {
  const preference = payload.preference as JsonObject;
  const context = preference.quality_context as JsonObject;
  const eligible = context.eligible_place_ids as string[];
  const candidates = payload.candidate_place_ids as string[];
  return eligible.every((id) => candidates.includes(id)) &&
    (payload.items as JsonObject[]).every((item) => {
      const contribution = item.contribution as ScoreContributionPayload;
      return eligible.includes(String(item.place_id)) &&
        contribution.axis_components.every((row, index) =>
          row.expected_value === (preference.axis_targets as JsonObject[])[index]!.value) &&
        contribution.condition_components.every((row, index) =>
          row.expected_value === (preference.condition_targets as JsonObject[])[index]!.value);
    });
}

const MVP_KERNEL_CONFIGS = {
  "recommendation-kernel-v3": "f94bcaa2b895f9a19e94a5f54ba6af640e9a1226fce03b942ba023e0bd2e9c19",
  "recommendation-kernel-v4": "397373e43782b44242dfd094312978a664f290b8b57ad127412b30589f88926e",
} as const;

function sharedSemanticPhotoInputs(scores: JsonObject[]): boolean {
  const first = scores[0]!;
  const observed = first.observed_traits as string[];
  const firstTraits = first.trait_components as JsonObject[];
  return scores.every((score) =>
    jsonEquals(score.observed_traits, observed) &&
    (score.trait_components as JsonObject[]).every((trait, index) =>
      !observed.includes(String(trait.trait_id)) || trait.expected === firstTraits[index]!.expected),
  );
}

async function isMvpRecommendationRun(payload: unknown): Promise<boolean> {
  const quality = isRecord(payload) && isRecord(payload.authority) &&
    payload.authority.kernel_version === "recommendation-kernel-v4";
  const semanticPhoto = isRecord(payload) && isRecord(payload.authority) &&
    payload.authority.photo_projection_version === "photo-projection-v2";
  if (
    isRecord(payload) &&
    payload.schema_version === "recommendation-run.v3"
  ) {
    if (
      !hasExactKeys(payload, [
        "authority",
        "candidate_place_ids",
        "canonical_sha256",
        "created_at",
        "input_digest",
        "items",
        "photo_scores",
        "preference",
        "run_id",
        "schema_version",
      ]) ||
      !isStableId(payload.run_id) ||
      !isSha256(payload.input_digest) ||
      !isSha256(payload.canonical_sha256) ||
      !isUtcDateTime(payload.created_at) ||
      !Array.isArray(payload.candidate_place_ids) ||
      payload.candidate_place_ids.length < 80 ||
      payload.candidate_place_ids.length > 100 ||
      !payload.candidate_place_ids.every(isStableId) ||
      !Array.isArray(payload.items) ||
      payload.items.length !== 5 ||
      !payload.items.every((item, index) => isMvpRecommendationItem(item, index + 1, false, quality)) ||
      !Array.isArray(payload.photo_scores) ||
      payload.photo_scores.length !== 5 ||
      !payload.photo_scores.every((row, index) => {
        const item = (payload.items as JsonObject[])[index];
        const contribution = item?.contribution;
        return (
          isRecord(contribution) &&
          isPhotoScoreTrace(
            row,
            contribution.relevance_score,
            item?.fit_score,
            semanticPhoto,
          )
        );
      }) ||
      !isMvpPreference(payload.preference, quality) ||
      !isRecord(payload.authority) ||
      !hasExactKeys(payload.authority, [
        "candidate_sha256",
        "config_sha256",
        "confirmation_draft_sha256",
        "images_count",
        "included_count",
        "kernel_version",
        "membership_sha256",
        "photo_job_reference_sha256",
        "photo_projection_output_sha256",
        "photo_projection_policy_sha256",
        "photo_projection_version",
        "relation_sha256",
        "release_sha256",
      ])
    ) {
      return false;
    }
    const authority = payload.authority;
    const digestFields = [
      "release_sha256", "membership_sha256", "relation_sha256", "candidate_sha256",
      "config_sha256", "confirmation_draft_sha256", "photo_job_reference_sha256",
      "photo_projection_output_sha256", "photo_projection_policy_sha256",
    ];
    const candidatePlaceIds = payload.candidate_place_ids as string[];
    const itemIds = (payload.items as JsonObject[]).map((row) => String(row.place_id));
    if (
      !digestFields.every((key) => isSha256(authority[key])) ||
      authority.kernel_version !== (quality ? "recommendation-kernel-v4" : "recommendation-kernel-v3") ||
      authority.config_sha256 !== MVP_KERNEL_CONFIGS[quality ? "recommendation-kernel-v4" : "recommendation-kernel-v3"] ||
      authority.photo_projection_version !== (semanticPhoto ? "photo-projection-v2" : "photo-projection-v1") ||
      (quality && !semanticPhoto) ||
      (semanticPhoto && !sharedSemanticPhotoInputs(payload.photo_scores as JsonObject[])) ||
      !isIntegerInRange(authority.images_count, 1, 3) ||
      !isIntegerInRange(authority.included_count, 1, 6) ||
      new Set(candidatePlaceIds).size !== candidatePlaceIds.length ||
      [...candidatePlaceIds].sort().some((value, index) => value !== candidatePlaceIds[index]) ||
      new Set(itemIds).size !== 5 ||
      !itemIds.every((placeId) => candidatePlaceIds.includes(placeId)) ||
      (quality && !qualityRunBindings(payload))
    ) {
      return false;
    }
    try {
      const expectedInputDigest = await canonicalSha256({
        preference: payload.preference,
        authority,
      });
      const deterministicPayload = Object.fromEntries(
        Object.entries(payload).filter(
          ([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key),
        ),
      );
      const expectedCanonicalSha256 = await canonicalSha256(deterministicPayload);
      return payload.input_digest === expectedInputDigest &&
        payload.canonical_sha256 === expectedCanonicalSha256 &&
        payload.run_id === `recommendation-run:${expectedCanonicalSha256.slice(0, 32)}`;
    } catch {
      return false;
    }
  }
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "authority",
      "candidate_place_ids",
      "canonical_sha256",
      "created_at",
      "input_digest",
      "items",
      "preference",
      "run_id",
      "schema_version",
    ]) ||
    payload.schema_version !== "recommendation-run.v2" ||
    !isStableId(payload.run_id) ||
    !isSha256(payload.input_digest) ||
    !isSha256(payload.canonical_sha256) ||
    !isUtcDateTime(payload.created_at) ||
    !Array.isArray(payload.candidate_place_ids) ||
    payload.candidate_place_ids.length < 80 ||
    payload.candidate_place_ids.length > 100 ||
    !payload.candidate_place_ids.every(isStableId) ||
    !Array.isArray(payload.items) ||
    payload.items.length !== 5 ||
    !payload.items.every((item, index) => isMvpRecommendationItem(item, index + 1, true, quality)) ||
    !isMvpPreference(payload.preference, quality) ||
    !isRecord(payload.authority) ||
    !hasExactKeys(payload.authority, [
      "candidate_sha256",
      "config_sha256",
      "kernel_version",
      "membership_sha256",
      "relation_sha256",
      "release_sha256",
    ])
  ) {
    return false;
  }
  const authority = payload.authority;
  const candidatePlaceIds = payload.candidate_place_ids as string[];
  const itemIds = (payload.items as JsonObject[]).map((row) => String(row.place_id));
  if (
    new Set(candidatePlaceIds).size !== candidatePlaceIds.length ||
    [...candidatePlaceIds].sort().some(
      (value, index) => value !== candidatePlaceIds[index],
    ) ||
    ![
      "release_sha256",
      "membership_sha256",
      "relation_sha256",
      "candidate_sha256",
      "config_sha256",
    ].every((key) => isSha256(authority[key])) ||
    authority.kernel_version !== (quality ? "recommendation-kernel-v4" : "recommendation-kernel-v3") ||
    authority.config_sha256 !== MVP_KERNEL_CONFIGS[quality ? "recommendation-kernel-v4" : "recommendation-kernel-v3"] ||
    new Set(itemIds).size !== 5 ||
    !itemIds.every((placeId) => candidatePlaceIds.includes(placeId)) ||
    (quality && !qualityRunBindings(payload))
  ) {
    return false;
  }
  try {
    const expectedInputDigest = await canonicalSha256({
      preference: payload.preference,
      authority,
    });
    const deterministicPayload = Object.fromEntries(
      Object.entries(payload).filter(
        ([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key),
      ),
    );
    const expectedCanonicalSha256 = await canonicalSha256(deterministicPayload);
    return (
      payload.input_digest === expectedInputDigest &&
      payload.canonical_sha256 === expectedCanonicalSha256 &&
      payload.run_id === `recommendation-run:${expectedCanonicalSha256.slice(0, 32)}`
    );
  } catch {
    return false;
  }
}

async function isRecommendationRun(
  payload: unknown,
): Promise<boolean> {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "authority",
      "candidate_place_ids",
      "candidate_set_digest",
      "canonical_membership_sha256",
      "canonical_sha256",
      "config_sha256",
      "created_at",
      "diversity_steps",
      "duplicate_decisions",
      "exclusions",
      "input_digest",
      "items",
      "kernel_version",
      "ndcg_denominator",
      "ndcg_status",
      "release_sha256",
      "run_id",
      "schema_version",
      "scored_candidates",
    ]) ||
    payload.schema_version !== "recommendation-run.v1" ||
    !isStableId(payload.run_id) ||
    !isSha256(payload.input_digest) ||
    !isSha256(payload.release_sha256) ||
    !isSha256(payload.canonical_membership_sha256) ||
    !isSha256(payload.config_sha256) ||
    !isSha256(payload.candidate_set_digest) ||
    !isSha256(payload.canonical_sha256) ||
    payload.kernel_version !== "recommendation-kernel-v3" ||
    !isUtcDateTime(payload.created_at) ||
    payload.ndcg_status !== "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS" ||
    payload.ndcg_denominator !== 0 ||
    !isCurrentAuthority(payload.authority) ||
    !Array.isArray(payload.candidate_place_ids) ||
    payload.candidate_place_ids.length < 5 ||
    payload.candidate_place_ids.length > 36 ||
    !payload.candidate_place_ids.every(isStableId) ||
    !Array.isArray(payload.exclusions) ||
    !payload.exclusions.every(isCandidateExclusion) ||
    !Array.isArray(payload.duplicate_decisions) ||
    !payload.duplicate_decisions.every(isDuplicateDecision) ||
    !Array.isArray(payload.scored_candidates) ||
    payload.scored_candidates.length < 5 ||
    !payload.scored_candidates.every(isCandidateScoreTrace) ||
    !Array.isArray(payload.diversity_steps) ||
    payload.diversity_steps.length !== 5 ||
    !payload.diversity_steps.every(isDiversityStep) ||
    !Array.isArray(payload.items) ||
    payload.items.length !== 5 ||
    !payload.items.every((item, index) => isRecommendationItem(item, index + 1))
  ) {
    return false;
  }

  const candidateIds = payload.candidate_place_ids as string[];
  const exclusions = payload.exclusions as JsonObject[];
  const scored = payload.scored_candidates as JsonObject[];
  const steps = payload.diversity_steps as JsonObject[];
  const items = payload.items as JsonObject[];
  const itemIds = items.map((item) => String(item.place_id));
  const scoredIds = scored.map((row) => String(row.place_id));
  const excludedIds = exclusions.map((row) => String(row.place_id));
  if (
    new Set(candidateIds).size !== candidateIds.length ||
    candidateIds.some((placeId, index) => index > 0 && candidateIds[index - 1]! > placeId) ||
    new Set(itemIds).size !== 5 ||
    new Set(scoredIds).size !== scoredIds.length ||
    new Set(excludedIds).size !== excludedIds.length ||
    scoredIds.some((placeId) => excludedIds.includes(placeId)) ||
    new Set([...scoredIds, ...excludedIds]).size !== candidateIds.length ||
    candidateIds.some((placeId) => !scoredIds.includes(placeId) && !excludedIds.includes(placeId)) ||
    steps.some((step, index) => step.rank !== index + 1 || step.selected_place_id !== itemIds[index])
  ) {
    return false;
  }

  const remaining = new Set(scoredIds);
  for (const step of steps) {
    const considered = step.considered as JsonObject[];
    const consideredIds = new Set(considered.map((row) => String(row.place_id)));
    if (
      consideredIds.size !== remaining.size ||
      [...remaining].some((placeId) => !consideredIds.has(placeId)) ||
      !remaining.delete(String(step.selected_place_id))
    ) {
      return false;
    }
  }

  const scoreById = new Map(scored.map((row) => [String(row.place_id), row] as const));
  if (
    items.some((item) => {
      const trace = scoreById.get(String(item.place_id));
      const itemContribution = item.contribution as JsonObject;
      const traceContribution = trace?.contribution as JsonObject | undefined;
      return (
        trace === undefined ||
        item.fit_score !== trace.relevance_score ||
        !jsonEquals(item.mismatch, trace.mismatch) ||
        traceContribution === undefined ||
        !jsonEquals(itemContribution.axis_components, traceContribution.axis_components) ||
        !jsonEquals(itemContribution.condition_components, traceContribution.condition_components)
      );
    })
  ) {
    return false;
  }

  const diversityById = new Map(
    steps.map((step) => [String(step.selected_place_id), step] as const),
  );
  if (!items.every((item) => {
    const step = diversityById.get(String(item.place_id));
    const contribution = item.contribution as JsonObject;
    return (
      step !== undefined &&
      contribution.diversity_novelty_score === step.novelty_score &&
      contribution.rerank_score === step.combined_score &&
      contribution.rerank_numerator ===
        Number(step.relevance_score) * 8_500 + Number(step.novelty_score) * 1_500
    );
  })) {
    return false;
  }

  const deterministicPayload = Object.fromEntries(
    Object.entries(payload).filter(
      ([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key),
    ),
  );
  try {
    const digest = await canonicalSha256(deterministicPayload);
    return (
      payload.canonical_sha256 === digest &&
      payload.run_id === `recommendation-run:${digest.slice(0, 32)}`
    );
  } catch {
    return false;
  }
}

function isRecommendationRunCreated(
  payload: unknown,
  request: RecommendationRequest,
): payload is RecommendationRunCreated {
  return (
    isRecord(payload) &&
    hasExactKeys(payload, [
      "preference_input_sha256",
      "preference_profile_id",
      "recommendation_run_id",
      "request_id",
      "schema_version",
    ]) &&
    payload.schema_version === "itda.recommendation-run-created.v1" &&
    isStableId(payload.recommendation_run_id) &&
    payload.request_id === request.request_id &&
    payload.preference_profile_id === request.preference_profile_id &&
    isSha256(payload.preference_input_sha256)
  );
}

async function isRecommendationResults(
  payload: unknown,
  expectedRunId: string,
): Promise<boolean> {
  if (isRecord(payload) && payload.schema_version === "itda.recommendation-results.v2") {
    const run = payload.run;
    if (
      !hasExactKeys(payload, [
        "analysis_origin",
        "operating_states",
        "preference_profile_id",
        "release_disclosure",
        "run",
        "schema_version",
      ]) ||
      payload.analysis_origin !== "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED" ||
      !isStableId(payload.preference_profile_id) ||
      !isRecord(run) ||
      !(await isMvpRecommendationRun(run)) ||
      run.run_id !== expectedRunId ||
      !Array.isArray(payload.operating_states) ||
      payload.operating_states.length !== 5 ||
      !payload.operating_states.every(
        (row, index) =>
          isRecord(row) &&
          hasExactKeys(row, ["place_id", "state"]) &&
          row.place_id === (run.items as JsonObject[])[index]?.place_id &&
          row.state === "OPERATING_INFORMATION_UNVERIFIED",
      ) ||
      !isRecord(payload.release_disclosure) ||
      !hasExactKeys(payload.release_disclosure, [
        "analysis_origin",
        "config_sha256",
        "model",
        "profile_schema_version",
        "prompt_schema_version",
        "reference_date",
        "release_sha256",
        "source_bundle_sha256",
      ])
    ) {
      return false;
    }
    const authority = run.authority as JsonObject;
    const disclosure = payload.release_disclosure;
    const runItems = run.items as JsonObject[];
    return (
      disclosure.analysis_origin === payload.analysis_origin &&
      disclosure.model === "glm-5.3-flash" &&
      disclosure.prompt_schema_version === "mvp-place-scoring-request.v2" &&
      disclosure.profile_schema_version === "mvp-scored-release.v1" &&
      disclosure.release_sha256 === authority.release_sha256 &&
      disclosure.config_sha256 === authority.config_sha256 &&
      isSha256(disclosure.source_bundle_sha256) &&
      isIsoDate(disclosure.reference_date) &&
      disclosure.reference_date ===
        runItems.map((item) => String(item.reference_date)).sort().at(-1)
    );
  }
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "analysis_origin",
      "operating_states",
      "preference_profile_id",
      "release_disclosure",
      "run",
      "schema_version",
    ]) ||
    payload.schema_version !== "itda.recommendation-results.v1" ||
    payload.analysis_origin !== "DEMO_MODEL_DERIVED" ||
    !isStableId(payload.preference_profile_id) ||
    !Array.isArray(payload.operating_states) ||
    payload.operating_states.length !== 5 ||
    !isRecord(payload.release_disclosure)
  ) {
    return false;
  }
  if (!(await isRecommendationRun(payload.run))) return false;
  const run = payload.run as RecommendationRun;
  if (run.run_id !== expectedRunId) return false;
  const itemIds = run.items.map((item) => item.place_id);
  if (
    !payload.operating_states.every(
      (row, index) =>
        isRecord(row) &&
        hasExactKeys(row, ["place_id", "state"]) &&
        row.place_id === itemIds[index] &&
        row.state === "OPERATING_INFORMATION_UNVERIFIED",
    )
  ) {
    return false;
  }
  const disclosure = payload.release_disclosure;
  const lineage = [
    disclosure.model,
    disclosure.prompt_schema_version,
    disclosure.profile_schema_version,
  ].join("\u0000");
  const allowedLineages = new Set([
    ["glm-5v-turbo", "phase5-demo-profile.v1", "itda.demo-model-derived-profile.v1"].join(
      "\u0000",
    ),
    [
      "glm-5v-turbo",
      "phase5-demo-profile-json.v2",
      "itda.demo-model-derived-profile.v1",
    ].join("\u0000"),
    [
      "minimaxai/minimax-m3",
      "phase5-demo-profile-sentinel-json.v4",
      "itda.nvidia-minimax-model-derived-profile.v4",
    ].join("\u0000"),
    [
      "minimaxai/minimax-m3",
      "phase5-demo-profile-sentinel-json.v5",
      "itda.nvidia-minimax-model-derived-profile.v5",
    ].join("\u0000"),
  ]);
  return (
    hasExactKeys(disclosure, [
      "analysis_origin",
      "config_sha256",
      "model",
      "profile_schema_version",
      "prompt_schema_version",
      "reference_date",
      "release_sha256",
      "source_bundle_sha256",
    ]) &&
    disclosure.analysis_origin === "DEMO_MODEL_DERIVED" &&
    allowedLineages.has(lineage) &&
    disclosure.config_sha256 === run.config_sha256 &&
    isSha256(disclosure.source_bundle_sha256) &&
    disclosure.release_sha256 === run.release_sha256 &&
    isIsoDate(disclosure.reference_date) &&
    disclosure.reference_date ===
      run.items.map((item) => item.reference_date).sort().at(-1)
  );
}

export function recommendationErrorCode(
  body: unknown,
): RecommendationErrorResponse["detail"]["code"] | null {
  if (!isRecord(body) || !hasExactKeys(body, ["detail"]) || !isRecord(body.detail)) {
    return null;
  }
  const detail = body.detail;
  if (
    !hasExactKeys(detail, [
      "code",
      "message_ko",
      "preference_profile_id",
      "release_id",
      "request_id",
    ])
  ) {
    return null;
  }
  const codes = [
    "NO_ACTIVE_SCORED_RELEASE",
    "INSUFFICIENT_ELIGIBLE_CANDIDATES",
    "RECOMMENDATION_REQUEST_CONFLICT",
    "INVALID_RECOMMENDATION_OUTPUT",
    "PREFERENCE_PROFILE_UNAVAILABLE",
    "RECOMMENDATION_RUN_NOT_FOUND",
    "RECOMMENDATION_PIN_INVALID",
    "RECOMMENDATION_PLACE_UNAVAILABLE",
    "INVALID_RECOMMENDATION_REQUEST",
  ] as const;
  return codes.find((code) => detail.code === code) ?? null;
}

export async function createRecommendationRun(
  request: RecommendationRequest,
  options: RequestOptions = {},
): Promise<RecommendationRunCreated> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const groundedInput = request.grounded_input === undefined ? groundedTripForRecommendation()
    : request.grounded_input === null ? null : parseGroundedTripInput(request.grounded_input);
  if (request.grounded_input != null && groundedInput === null) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const { grounded_input: _explicitGrounding, ...baseRequest } = request;
  const submitted = groundedInput === null ? baseRequest : { ...baseRequest, grounded_input: groundedInput };
  let response: Response;
  try {
    response = await fetchImpl("/v1/recommendation-runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(submitted),
      signal: options.signal,
    });
  } catch {
    throw new ApiRequestError("추천을 불러오지 못했어요.", null);
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = (await response.json()) as unknown;
    } catch {
      // Preserve status while keeping non-JSON failure bytes out of browser state.
    }
    throw new ApiRequestError("추천을 불러오지 못했어요.", response.status, body);
  }
  const payload = await readJson(response);
  if (!isRecommendationRunCreated(payload, request)) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return payload;
}

async function getRecommendationJson(
  url: string,
  message: string,
  options: RequestOptions,
): Promise<unknown> {
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(url, { signal: options.signal });
  } catch {
    throw new ApiRequestError(message, null);
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = (await response.json()) as unknown;
    } catch {
      // Preserve the status while keeping non-JSON response bytes out of state.
    }
    throw new ApiRequestError(message, response.status, body);
  }
  return readJson(response);
}

export async function fetchRecommendationResults(
  runId: string,
  options: RequestOptions = {},
): Promise<RecommendationResultsResponse> {
  if (!isStableId(runId)) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const payload = await getRecommendationJson(
    `/v1/recommendation-runs/${encodeURIComponent(runId)}`,
    "추천을 불러오지 못했어요.",
    options,
  );
  if (!(await isRecommendationResults(payload, runId))) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return payload as RecommendationResultsResponse;
}

function isMvpRecommendationDetail(
  payload: unknown,
  runId: string,
  placeId: string,
  expectedItem?: RecommendationResultsResponse["run"]["items"][number],
): boolean {
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "confidence_percent",
      "evidence",
      "evidence_confidence_reason_ko",
      "evidence_confidence_state",
      "item",
      "mismatch_traits",
      "operating_state",
      "release_sha256",
      "run_id",
      "similar_place_ids",
    ]) ||
    payload.run_id !== runId ||
    !isSha256(payload.release_sha256) ||
    !isScore(payload.confidence_percent) ||
    !isConfidenceProjection(payload, payload.confidence_percent) ||
    !isRecord(payload.item) ||
    !isMvpRecommendationItem(
      payload.item,
      Number(payload.item.rank),
      expectedItem === undefined,
      expectedItem !== undefined,
    ) ||
    (expectedItem !== undefined && !jsonEquals(payload.item, expectedItem)) ||
    !isConfidenceProjection(payload.item, payload.confidence_percent) ||
    payload.item.place_id !== placeId ||
    !Array.isArray(payload.evidence) ||
    payload.evidence.length < 1 ||
    payload.evidence.length > 64 ||
    !payload.evidence.every(isMvpEvidenceSnippet) ||
    !Array.isArray(payload.mismatch_traits) ||
    payload.mismatch_traits.length !== 6 ||
    !payload.mismatch_traits.every(
      (trait, index) =>
        isRecord(trait) &&
        hasExactKeys(trait, ["evidence_ids", "trait_id", "value"]) &&
        trait.trait_id === `M${index + 1}` &&
        isScore(trait.value) &&
        Array.isArray(trait.evidence_ids) &&
        trait.evidence_ids.length >= 1 &&
        trait.evidence_ids.length <= 8 &&
        trait.evidence_ids.every(isStableId),
    ) ||
    payload.operating_state !== "OPERATING_INFORMATION_UNVERIFIED" ||
    !Array.isArray(payload.similar_place_ids) ||
    payload.similar_place_ids.length > 4 ||
    !payload.similar_place_ids.every(isStableId) ||
    payload.similar_place_ids.includes(placeId) ||
    new Set(payload.similar_place_ids).size !== payload.similar_place_ids.length
  ) {
    return false;
  }
  const inventoryRows = payload.evidence as JsonObject[];
  const inventory = new Map(
    inventoryRows.map((row) => [String(row.evidence_id), row] as const),
  );
  if (inventory.size !== inventoryRows.length) return false;
  const item = payload.item;
  const itemEvidenceBound = (item.evidence as JsonObject[]).every((row) => {
    const inventoryRow = inventory.get(String(row.evidence_id));
    return inventoryRow !== undefined && jsonEquals(row, inventoryRow);
  });
  const references = [
    ...(item.axis_scores as JsonObject[]).flatMap((row) => row.evidence_ids as string[]),
    ...(item.explanations as JsonObject[]).map((row) => String(row.evidence_id)),
    ...(payload.mismatch_traits as JsonObject[]).flatMap(
      (row) => row.evidence_ids as string[],
    ),
  ];
  return itemEvidenceBound && references.every((evidenceId) => inventory.has(evidenceId));
}

export async function fetchRecommendationDetail(
  runId: string,
  placeId: string,
  options: RequestOptions = {},
  expectedItem?: RecommendationResultsResponse["run"]["items"][number],
): Promise<RecommendationDetail> {
  if (!isStableId(runId) || !isStableId(placeId)) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const payload = await getRecommendationJson(
    `/v1/recommendation-runs/${encodeURIComponent(runId)}/places/${encodeURIComponent(placeId)}`,
    "장소 정보를 불러오지 못했어요.",
    options,
  );
  if (
    isRecord(payload) &&
    Array.isArray(payload.evidence) &&
    payload.evidence.every(isMvpEvidenceSnippet)
  ) {
    if (!isMvpRecommendationDetail(payload, runId, placeId, expectedItem)) {
      throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
    }
    return payload as RecommendationDetail;
  }
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "confidence_percent",
      "evidence",
      "evidence_confidence_reason_ko",
      "evidence_confidence_state",
      "item",
      "mismatch_traits",
      "operating_state",
      "release_sha256",
      "run_id",
      "similar_place_ids",
    ]) ||
    payload.run_id !== runId ||
    !isSha256(payload.release_sha256) ||
    !isScore(payload.confidence_percent) ||
    !isConfidenceProjection(payload as JsonObject, payload.confidence_percent) ||
    !isRecord(payload.item) ||
    !isConfidenceProjection(payload.item, payload.confidence_percent) ||
    !isRecommendationItem(payload.item, Number(payload.item.rank)) ||
    payload.item.place_id !== placeId ||
    !Array.isArray(payload.evidence) ||
    payload.evidence.length < 1 ||
    payload.evidence.length > 64 ||
    !payload.evidence.every(
      (evidence) =>
        isRecord(evidence) &&
        hasExactKeys(evidence, [
          "attribution_ko",
          "contest_rights_qualified",
          "contest_use_scope",
          "evidence_id",
          "excerpt_ko",
          "reference_date",
          "source_label_ko",
        ]) &&
        isStableId(evidence.evidence_id) &&
        typeof evidence.excerpt_ko === "string" &&
        evidence.excerpt_ko.trim().length > 0 &&
        evidence.excerpt_ko.length <= 240 &&
        typeof evidence.source_label_ko === "string" &&
        evidence.source_label_ko.trim().length > 0 &&
        evidence.source_label_ko.length <= 100 &&
        typeof evidence.attribution_ko === "string" &&
        evidence.attribution_ko.trim().length > 0 &&
        evidence.attribution_ko.length <= 180 &&
        evidence.contest_use_scope === "noncommercial_contest_demo_evaluation" &&
        evidence.contest_rights_qualified === true &&
        isIsoDate(evidence.reference_date),
    ) ||
    new Set(payload.evidence.map((evidence) => (evidence as JsonObject).evidence_id)).size !==
      payload.evidence.length ||
    !Array.isArray(payload.mismatch_traits) ||
    payload.mismatch_traits.length !== 6 ||
    !payload.mismatch_traits.every(
      (trait, index) =>
        isRecord(trait) &&
        hasExactKeys(trait, ["evidence_ids", "trait_id", "value"]) &&
        trait.trait_id === `M${index + 1}` &&
        isScore(trait.value) &&
        Array.isArray(trait.evidence_ids) &&
        trait.evidence_ids.length >= 1 &&
        trait.evidence_ids.length <= 8 &&
        trait.evidence_ids.every(isStableId),
    ) ||
    payload.operating_state !== "OPERATING_INFORMATION_UNVERIFIED" ||
    !Array.isArray(payload.similar_place_ids) ||
    payload.similar_place_ids.length > 4 ||
    !payload.similar_place_ids.every(isStableId) ||
    payload.similar_place_ids.includes(placeId) ||
    new Set(payload.similar_place_ids).size !== payload.similar_place_ids.length
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const item = payload.item as JsonObject;
  const inventoryRows = payload.evidence as JsonObject[];
  const inventory = new Map(
    inventoryRows.map((row) => [String(row.evidence_id), row] as const),
  );
  const evidenceFields = [
    "attribution_ko",
    "contest_rights_qualified",
    "contest_use_scope",
    "evidence_id",
    "excerpt_ko",
    "reference_date",
    "source_label_ko",
  ] as const;
  const itemEvidence = item.evidence as JsonObject[];
  const sameEvidence = (left: JsonObject, right: JsonObject) =>
    evidenceFields.every((field) => left[field] === right[field]);
  const itemEvidenceBound = itemEvidence.every((row) => {
    const inventoryRow = inventory.get(String(row.evidence_id));
    return inventoryRow !== undefined && sameEvidence(row, inventoryRow);
  });
  const axisReferences = (item.axis_scores as JsonObject[]).flatMap(
    (row) => row.evidence_ids as string[],
  );
  const explanationReferences = (item.explanations as JsonObject[]).map(
    (row) => String(row.evidence_id),
  );
  const traitReferences = (payload.mismatch_traits as JsonObject[]).flatMap(
    (row) => row.evidence_ids as string[],
  );
  if (
    !inventoryRows.every((row) => row.reference_date === item.reference_date) ||
    !itemEvidenceBound ||
    ![...axisReferences, ...explanationReferences, ...traitReferences].every((evidenceId) =>
      inventory.has(evidenceId),
    )
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return payload as RecommendationDetail;
}

const COMPARISON_ROW_SCHEMA = [
  ["fit-score", "추천 적합도"],
  ["axis-history_tradition", "역사·전통"],
  ["axis-emotion_image", "감성·이미지"],
  ["axis-rest_immersion", "휴식·몰입"],
  ["evidence-reason-1", "잘 맞는 이유 1"],
  ["evidence-reason-2", "잘 맞는 이유 2"],
  ["mismatch-guidance", "이번 여행에서 기대한 것과 다른 점"],
  ["trait-m1", "공간 성격"],
  ["trait-m2", "방문객 성격"],
  ["trait-m3", "현장 밀도"],
  ["trait-m4", "경험 방식"],
  ["trait-m5", "체류 방식"],
  ["trait-m6", "시간 의존성"],
  ["time-season-context", "시간·계절 맥락"],
  ["operating-state", "운영 정보"],
  ["media-state", "대표 이미지 상태"],
  ["reference-date", "데이터 기준일"],
] as const;

const OPERATING_KINDS = new Set([
  "OPENING_HOURS",
  "REST_DATES",
  "USE_SEASON",
  "EVENT_DATES",
  "CHECK_IN_OUT",
]);
const OPERATING_PROVIDER_FIELDS = new Set([
  "opendate",
  "restdate",
  "usetime",
  "useseason",
  "restdateculture",
  "usetimeculture",
  "eventstartdate",
  "eventenddate",
  "playtime",
  "openperiod",
  "restdateleports",
  "usetimeleports",
  "checkintime",
  "checkouttime",
  "roomofftime",
  "opendateshopping",
  "opentime",
  "restdateshopping",
  "opendatefood",
  "opentimefood",
  "restdatefood",
]);
const OPERATING_UNAVAILABLE_REASONS = new Set([
  "ENRICHMENT_DISABLED",
  "NOT_IN_PROVIDER_SCOPE",
  "NO_OPERATING_FIELDS",
  "PROVIDER_UNAVAILABLE",
]);

function isOperatingEntry(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, ["kind", "label_ko", "provider_field", "value_ko"]) &&
    OPERATING_KINDS.has(String(value.kind)) &&
    typeof value.label_ko === "string" &&
    value.label_ko.trim().length > 0 &&
    value.label_ko.length <= 40 &&
    typeof value.value_ko === "string" &&
    value.value_ko.trim().length > 0 &&
    value.value_ko.length <= 240 &&
    OPERATING_PROVIDER_FIELDS.has(String(value.provider_field))
  );
}

function isOperatingSnapshot(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      "cached",
      "content_type_id",
      "entries",
      "operation",
      "provider",
      "provider_modifiedtime",
      "retrieved_at",
      "source_label_ko",
    ]) &&
    value.provider === "TOUR_API" &&
    value.operation === "detailIntro2" &&
    typeof value.content_type_id === "string" &&
    /^[0-9]{1,2}$/.test(value.content_type_id) &&
    Array.isArray(value.entries) &&
    value.entries.length >= 1 &&
    value.entries.length <= 8 &&
    value.entries.every(isOperatingEntry) &&
    isUtcDateTime(value.retrieved_at) &&
    (value.provider_modifiedtime === null ||
      (typeof value.provider_modifiedtime === "string" &&
        value.provider_modifiedtime.trim().length > 0 &&
        value.provider_modifiedtime.length <= 40)) &&
    value.source_label_ko === "한국관광공사 TourAPI(KorService2 detailIntro2)" &&
    typeof value.cached === "boolean"
  );
}

function isPlaceOperatingInformation(value: unknown, placeId: string): boolean {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["place_id", "snapshot", "state", "unavailable_reason"]) ||
    value.place_id !== placeId
  ) {
    return false;
  }
  if (value.state === "AVAILABLE") {
    return isOperatingSnapshot(value.snapshot) && value.unavailable_reason === null;
  }
  return (
    value.state === "UNVERIFIED" &&
    value.snapshot === null &&
    OPERATING_UNAVAILABLE_REASONS.has(String(value.unavailable_reason))
  );
}

export async function fetchOperatingInformation(
  runId: string,
  placeIds: readonly string[],
  options: RequestOptions = {},
): Promise<OperatingInformationResponse> {
  if (
    !isStableId(runId) ||
    placeIds.length < 1 ||
    placeIds.length > 5 ||
    new Set(placeIds).size !== placeIds.length ||
    !placeIds.every(isStableId)
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const query = placeIds.map((placeId) => `place_id=${encodeURIComponent(placeId)}`).join("&");
  const payload = await getRecommendationJson(
    `/v1/recommendation-runs/${encodeURIComponent(runId)}/operating-information?${query}`,
    "운영 정보를 불러오지 못했어요.",
    options,
  );
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, ["places", "run_id", "schema_version"]) ||
    payload.schema_version !== "operating-information.v1" ||
    payload.run_id !== runId ||
    !Array.isArray(payload.places) ||
    payload.places.length !== placeIds.length ||
    !payload.places.every((row, index) =>
      isPlaceOperatingInformation(row, placeIds[index]!),
    )
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return payload as OperatingInformationResponse;
}

export async function fetchRecommendationComparison(
  runId: string,
  releaseSha256: string,
  placeIds: readonly string[],
  options: RequestOptions = {},
): Promise<ComparisonRow[]> {
  if (
    !isStableId(runId) ||
    !isSha256(releaseSha256) ||
    placeIds.length < 2 ||
    placeIds.length > 3 ||
    new Set(placeIds).size !== placeIds.length ||
    !placeIds.every(isStableId)
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const query = placeIds.map((placeId) => `place_id=${encodeURIComponent(placeId)}`).join("&");
  const payload = await getRecommendationJson(
    `/v1/recommendation-runs/${encodeURIComponent(runId)}/comparison?${query}`,
    "비교 정보를 불러오지 못했어요.",
    options,
  );
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, ["place_ids", "release_sha256", "rows", "run_id", "schema_version"]) ||
    payload.schema_version !== "recommendation-comparison-v1" ||
    payload.run_id !== runId ||
    payload.release_sha256 !== releaseSha256 ||
    !Array.isArray(payload.place_ids) ||
    payload.place_ids.length !== placeIds.length ||
    !payload.place_ids.every((placeId, index) => placeId === placeIds[index]) ||
    !Array.isArray(payload.rows) ||
    payload.rows.length !== COMPARISON_ROW_SCHEMA.length ||
    !payload.rows.every(
      (row, index) => {
        const expected = COMPARISON_ROW_SCHEMA[index];
        const operatingRow = expected?.[0] === "operating-state";
        return (
        isRecord(row) &&
        hasExactKeys(row, ["label_ko", "missing_reasons", "row_id", "values_ko"]) &&
        row.row_id === expected?.[0] &&
        row.label_ko === expected?.[1] &&
        Array.isArray(row.values_ko) &&
        row.values_ko.length === placeIds.length &&
        row.values_ko.every(
          (value) => typeof value === "string" && value.trim().length > 0 && value.length <= 500,
        ) &&
        Array.isArray(row.missing_reasons) &&
        row.missing_reasons.length === placeIds.length &&
        (operatingRow
          ? row.values_ko.every((value) => value === "정보 없음") &&
            row.missing_reasons.every(
              (reason) => reason === "OPERATING_INFORMATION_UNVERIFIED",
            )
          : row.missing_reasons.every((reason) => reason === null))
        );
      },
    )
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return (payload as RecommendationComparisonResponse).rows;
}

export async function resolveSavedPlaceReference(
  releaseSha256: string,
  placeId: string,
  options: RequestOptions = {},
): Promise<SavedPlaceProjection> {
  if (!isSha256(releaseSha256) || !isStableId(placeId)) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  const payload = await getRecommendationJson(
    `/v1/saved-place-references/${releaseSha256}/${encodeURIComponent(placeId)}`,
    "저장한 장소를 불러오지 못했어요.",
    options,
  );
  if (
    !isRecord(payload) ||
    !hasExactKeys(payload, [
      "place_id",
      "place_name_ko",
      "resolved_release_sha256",
      "saved_release_sha256",
      "state",
      "state_reason",
      ...["region_code", "region_name", "address_ko"].filter((key) => Object.hasOwn(payload, key)),
    ]) ||
    payload.place_id !== placeId ||
    payload.saved_release_sha256 !== releaseSha256 ||
    typeof payload.place_name_ko !== "string" ||
    payload.place_name_ko.trim().length === 0 ||
    payload.place_name_ko.length > 120 ||
    (payload.region_code != null && (typeof payload.region_code !== "string" || !/^\d{5}$/.test(payload.region_code))) ||
    (payload.region_name != null && (typeof payload.region_name !== "string" || payload.region_name.trim().length === 0 || payload.region_name.length > 160)) ||
    (payload.address_ko != null && (typeof payload.address_ko !== "string" || payload.address_ko.trim().length === 0 || payload.address_ko.length > 500)) ||
    !["CURRENT", "STALE", "UNAVAILABLE"].includes(String(payload.state)) ||
    (payload.resolved_release_sha256 !== null && !isSha256(payload.resolved_release_sha256)) ||
    (payload.state === "CURRENT" &&
      (payload.resolved_release_sha256 !== releaseSha256 || payload.state_reason !== null)) ||
    (payload.state === "STALE" &&
      (payload.resolved_release_sha256 !== releaseSha256 || !isStableId(payload.state_reason))) ||
    (payload.state === "UNAVAILABLE" &&
      (payload.resolved_release_sha256 !== null || !isStableId(payload.state_reason)))
  ) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return payload as SavedPlaceProjection;
}
