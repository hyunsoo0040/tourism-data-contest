import { z } from "zod";

import { RecommendationContractError, ApiRequestError, fetchRecommendationResults, type RecommendationResultsResponse } from "./api";
import { digest, isoDate, sourceEvidence, stableId, utcDateTime } from "./trip-context";
import { parseGroundedTripInput, type GroundedTripInput } from "../features/journey/groundedTrip";
import { canonicalHash, combine, halfUp, MOOD_KEYS, nonnegative, nullableScore, ordered, same, score, without } from "./grounded-core";

export const AXIS_KEYS = ["H", "E", "R"] as const;
export const TRAIT_KEYS = ["M1", "M2", "M3", "M4", "M5", "M6"] as const;
export const CONDITION_KEYS = ["VISIT_DATE_TIME", "COMPANIONS", "TRANSPORT", "WALKING", "INDOOR_OUTDOOR", "CROWD"] as const;
const POLICY_SHA = "eceab437ed2867fa0bfe8ba7058f5648c3bbaa5c9b3891d081be1ecbcf189688";
const ids = z.array(stableId).refine(ordered);
const hashes = z.array(digest).refine(ordered);
const targets = (keys: readonly string[], nullable: boolean) => z.record(z.string(), nullable ? nullableScore : score)
  .refine((row) => same(Object.keys(row).sort(), [...keys].sort()));

const preferenceSchema = z.strictObject({
  profile_id: stableId, input_sha256: digest, projection_version: z.literal("grounded-preference-v1"),
  trip_input: z.custom<GroundedTripInput>((v) => parseGroundedTripInput(v) !== null),
  purpose: z.enum(["SIGHTSEEING", "FOOD", "LODGING", "MIXED"]),
  axis_targets: targets(AXIS_KEYS, false), trait_targets: targets(TRAIT_KEYS, true), important_traits: ids,
  condition_targets: targets(CONDITION_KEYS, true), mood_targets: targets(MOOD_KEYS, true), photo_input_sha256: digest.nullable(),
}).refine((row) => row.important_traits.every((key) => TRAIT_KEYS.includes(key as typeof TRAIT_KEYS[number])) &&
  (row.photo_input_sha256 !== null || Object.values(row.mood_targets).every((value) => value === null)));

const fitComponent = z.strictObject({
  key: stableId, expected: nullableScore, actual: nullableScore, compared: z.boolean(), difference: nullableScore,
  fit: nullableScore, weight: z.number().int().min(0).max(10_000), evidence_ids: ids,
  exclusion_reason: z.enum(["USER_UNSPECIFIED", "PLACE_UNSUPPORTED"]).nullable(),
}).refine((row) => {
  const compared = row.expected !== null && row.actual !== null;
  if (row.compared !== compared) return false;
  return compared ? row.difference === Math.abs(row.expected! - row.actual!) && row.fit === 100 - row.difference &&
    row.weight > 0 && row.evidence_ids.length > 0 && row.exclusion_reason === null
    : row.difference === null && row.fit === null && row.weight === 0 &&
      row.exclusion_reason === (row.expected === null ? "USER_UNSPECIFIED" : "PLACE_UNSUPPORTED");
});

export const fitTraceSchema = z.strictObject({
  components: z.array(fitComponent), numerator: nonnegative, denominator: nonnegative,
  score: nullableScore, compared_keys: ids,
}).refine((row) => {
  const numerator = row.components.reduce((sum, component) => sum + (component.fit ?? 0) * component.weight, 0);
  const denominator = row.components.reduce((sum, component) => sum + component.weight, 0);
  return ordered(row.components.map((component) => component.key)) && numerator === row.numerator && denominator === row.denominator &&
    row.score === (denominator ? halfUp(numerator, denominator) : null) &&
    same(row.compared_keys, row.components.filter((component) => component.compared).map((component) => component.key));
});

const dimensionSchema = z.strictObject({
  key: stableId, value: nullableScore, state: z.enum(["SUPPORTED_FACT", "SUPPORTED_INFERENCE", "UNKNOWN"]),
  evidence_ids: ids, reference_date: isoDate.nullable(), reason: z.string().min(1).max(1000),
}).refine((row) => row.state === "UNKNOWN" ? row.value === null
  : row.value !== null && row.evidence_ids.length > 0 && row.reference_date !== null);
const mismatchSchema = z.strictObject({
  axis_distance: nullableScore, trait_distance: nullableScore, raw_score: nullableScore, effective_score: nullableScore,
  compared_traits: ids, important_floor_applied: z.boolean(), state: z.enum(["INSUFFICIENT_EVIDENCE", "SUPPRESSED_LOW_CONFIDENCE",
    "NO_GUIDANCE", "GENTLE_DIFFERENCE", "MATERIAL_DIFFERENCE", "STRONG_DIFFERENCE"]), message_ko: z.string().nullable(),
});
const noveltyPair = z.strictObject({ place_id: stableId, shared_axes: z.array(z.enum(AXIS_KEYS)), shared_traits: z.array(z.enum(TRAIT_KEYS)), score });
const contributionSchema = z.strictObject({
  experience: fitTraceSchema, conditions: fitTraceSchema, traits: fitTraceSchema, mood: fitTraceSchema,
  base_relevance: score, effective_relevance: score, mood_weight: z.number().int().min(0).max(1500),
  novelty_pairs: z.array(noveltyPair), novelty_score: score, rerank_numerator: nonnegative, rerank_score: score,
}).refine((row) => {
  const base = combine([[row.experience.score, 8000], [row.conditions.score, 2000]]);
  const moodWeight = row.mood.score === null ? 0 : 1500;
  const effective = combine([[base, 10000 - moodWeight], [row.mood.score, moodWeight]]);
  const novelty = row.novelty_pairs.length ? Math.min(...row.novelty_pairs.map((pair) => pair.score)) : 0;
  const numerator = row.effective_relevance * 8500 + novelty * 1500;
  return base === row.base_relevance && moodWeight === row.mood_weight && effective === row.effective_relevance &&
    novelty === row.novelty_score && numerator === row.rerank_numerator && halfUp(numerator, 10000) === row.rerank_score;
});

export const groundedItemSchema = z.strictObject({
  rank: z.number().int().min(1).max(5), place_id: stableId, place_name_ko: z.string().min(1).max(240),
  region_code: z.string().regex(/^\d{5}$/).nullable().optional(),
  region_name: z.string().min(1).max(160).nullable().optional(),
  address_ko: z.string().min(1).max(500).nullable().optional(),
  raw_profile_sha256: digest, assessment_bundle_sha256: digest, fit_score: score, overall_confidence: nullableScore,
  axis_scores: z.array(dimensionSchema).length(3), mismatch_traits: z.array(dimensionSchema).length(6),
  contribution: contributionSchema, mismatch: mismatchSchema,
  explanations: z.array(z.strictObject({ dimension: z.enum(AXIS_KEYS), message_ko: z.string().min(1).max(200), evidence_ids: ids, reference_date: isoDate })),
  evidence: z.array(sourceEvidence), supported_axes: z.number().int().min(2).max(3), information_state: z.enum(["SUPPORTED", "LIMITED"]),
  reference_date: isoDate.nullable(), image_state: z.literal("ABSENT"),
}).refine((row) => {
  if (!same(row.axis_scores.map((axis) => axis.key), AXIS_KEYS) || !same(row.mismatch_traits.map((trait) => trait.key), TRAIT_KEYS)) return false;
  const count = row.axis_scores.filter((axis) => axis.value !== null).length;
  if (row.supported_axes !== count || row.information_state !== (count === 3 ? "SUPPORTED" : "LIMITED") || row.fit_score !== row.contribution.effective_relevance) return false;
  if (!same(Object.fromEntries(row.axis_scores.map((axis) => [axis.key, axis.value])), Object.fromEntries(row.contribution.experience.components.map((c) => [c.key, c.actual]))) ||
    !same(Object.fromEntries(row.mismatch_traits.map((trait) => [trait.key, trait.value])), Object.fromEntries(row.contribution.traits.components.map((c) => [c.key, c.actual])))) return false;
  const evidence = new Map(row.evidence.map((entry) => [entry.evidence_id, entry]));
  if (evidence.size !== row.evidence.length || row.evidence.some((entry) => entry.place_match !== null && entry.place_match.place_id !== row.place_id)) return false;
  return row.explanations.every((explanation) => {
    const axis = row.axis_scores.find((axis) => axis.key === explanation.dimension)!;
    return axis.value !== null && explanation.evidence_ids.length > 0 && explanation.evidence_ids.every((id) => axis.evidence_ids.includes(id) && evidence.has(id));
  });
});

const candidateBinding = z.strictObject({ place_id: stableId, raw_profile_sha256: digest, assessment_bundle_sha256: digest });
const authoritySchema = z.strictObject({
  kernel_version: z.literal("recommendation-kernel-v5"), config_sha256: z.literal(POLICY_SHA), release_sha256: digest,
  source_release_sha256: digest, assessment_manifest_sha256: digest, membership_sha256: digest, relation_sha256: digest,
  candidate_sha256: digest,
  candidate_assessment_sha256: digest, contextual_snapshot_sha256: hashes, photo_input_sha256: digest.nullable(),
});
const runSchema = z.strictObject({
  schema_version: z.literal("itda.grounded-recommendation-run.v1"), run_id: stableId, input_digest: digest,
  preference: preferenceSchema, authority: authoritySchema, candidate_bindings: z.array(candidateBinding), eligible_place_ids: ids,
  exclusions: z.array(z.strictObject({ place_id: stableId, reason: z.enum(["PURPOSE", "REGION", "INSUFFICIENT_SUPPORTED_AXES", "EXPLICIT_FACILITY_ABSENT", "SUPPORT_GATE"]) })),
  items: z.array(groundedItemSchema).length(5), created_at: utcDateTime, canonical_sha256: digest,
});
const resultSchema = z.strictObject({
  schema_version: z.literal("itda.grounded-recommendation-results.v1"), preference_profile_id: stableId, run: runSchema,
  release_disclosure: z.strictObject({ model: z.literal("glm-5.3-flash"), raw_release_sha256: digest, source_release_sha256: digest,
    assessment_manifest_sha256: digest, candidate_sha256: digest, config_sha256: z.literal(POLICY_SHA),
    scoring_policy: z.literal("SUPPORTED_SUBORDINATE_AGGREGATION"), image_policy: z.literal("VISUAL_MOOD_ONLY") }),
});

export type GroundedItem = z.infer<typeof groundedItemSchema>;
export type GroundedRun = z.infer<typeof runSchema>;
export type GroundedResults = z.infer<typeof resultSchema>;
export type RecommendationEnvelope = RecommendationResultsResponse | GroundedResults;
export type GroundedFitTrace = z.infer<typeof fitTraceSchema>;

function invalid(): never { throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT"); }

function validateMismatch(item: GroundedItem, preference: GroundedRun["preference"]): boolean {
  const trace = item.contribution, actual = item.mismatch;
  const axes = trace.experience.score === null ? null : 100 - trace.experience.score;
  const traits = trace.traits.score === null ? null : 100 - trace.traits.score;
  const raw = combine([[axes, 6500], [traits, 3500]]);
  const floor = trace.traits.components.some((c) => preference.important_traits.includes(c.key) && c.compared && c.difference !== null && c.difference >= 70);
  const effective = raw !== null && floor ? Math.max(raw, 50) : raw;
  const state = effective === null ? "INSUFFICIENT_EVIDENCE" : (item.overall_confidence ?? 0) < 65 ? "SUPPRESSED_LOW_CONFIDENCE" : effective < 30 ? "NO_GUIDANCE"
    : effective < 45 ? "GENTLE_DIFFERENCE" : effective < 60 ? "MATERIAL_DIFFERENCE" : "STRONG_DIFFERENCE";
  const message = { GENTLE_DIFFERENCE: "확인된 특성 중 기대와 조금 다른 부분이 있어요.", MATERIAL_DIFFERENCE: "확인된 특성 중 기대와 다른 부분이 있어요.", STRONG_DIFFERENCE: "기대와 다른 특성을 방문 전에 확인해 주세요." }[state as "GENTLE_DIFFERENCE"] ?? null;
  return same(actual, { axis_distance: axes, trait_distance: traits, raw_score: raw, effective_score: effective,
    compared_traits: trace.traits.compared_keys, important_floor_applied: floor, state, message_ko: message });
}

function validateNovelty(item: GroundedItem, prior: GroundedItem[]): boolean {
  if (!same(item.contribution.novelty_pairs.map((pair) => pair.place_id), prior.map((item) => item.place_id))) return false;
  const left = Object.fromEntries([...item.axis_scores, ...item.mismatch_traits].map((d) => [d.key, d.value]));
  return prior.every((other, index) => {
    const right = Object.fromEntries([...other.axis_scores, ...other.mismatch_traits].map((d) => [d.key, d.value]));
    const axes = AXIS_KEYS.filter((key) => left[key] !== null && right[key] !== null);
    const traits = TRAIT_KEYS.filter((key) => left[key] !== null && right[key] !== null);
    const distance = (keys: string[]) => keys.length ? halfUp(keys.reduce((sum, key) => sum + Math.abs(left[key]! - right[key]!), 0), keys.length) : null;
    return same(item.contribution.novelty_pairs[index], { place_id: other.place_id, shared_axes: axes, shared_traits: traits,
      score: combine([[distance(axes), 6500], [distance(traits), 3500]]) ?? 0 });
  });
}

export async function parseGroundedResults(payload: unknown, expectedRunId?: string): Promise<GroundedResults> {
  const parsed = resultSchema.safeParse(payload);
  if (!parsed.success) invalid();
  const result = parsed.data, run = result.run, authority = run.authority, disclosure = result.release_disclosure;
  if ((expectedRunId !== undefined && run.run_id !== expectedRunId) || result.preference_profile_id !== run.preference.profile_id ||
    disclosure.raw_release_sha256 !== authority.release_sha256 || disclosure.source_release_sha256 !== authority.source_release_sha256 ||
    disclosure.assessment_manifest_sha256 !== authority.assessment_manifest_sha256 || disclosure.config_sha256 !== authority.config_sha256 ||
    disclosure.candidate_sha256 !== authority.candidate_sha256 ||
    authority.photo_input_sha256 !== run.preference.photo_input_sha256) invalid();
  const bindings = new Map(run.candidate_bindings.map((row) => [row.place_id, row]));
  if (!ordered([...bindings.keys()]) || bindings.size !== run.candidate_bindings.length || !run.eligible_place_ids.every((id) => bindings.has(id)) ||
    new Set(run.items.map((item) => item.place_id)).size !== 5 ||
    new Set(run.exclusions.map((row) => row.place_id)).size !== run.exclusions.length ||
    run.exclusions.some((row) => !bindings.has(row.place_id) || run.eligible_place_ids.includes(row.place_id))) invalid();
  for (const [index, item] of run.items.entries()) {
    const binding = bindings.get(item.place_id);
    if (item.rank !== index + 1 || !run.eligible_place_ids.includes(item.place_id) || !binding ||
      (run.preference.trip_input.region_code != null && !item.region_code?.startsWith(run.preference.trip_input.region_code)) ||
      item.raw_profile_sha256 !== binding.raw_profile_sha256 || item.assessment_bundle_sha256 !== binding.assessment_bundle_sha256 ||
      !validateMismatch(item, run.preference) || !validateNovelty(item, run.items.slice(0, index))) invalid();
    for (const [trace, targets] of [[item.contribution.experience, run.preference.axis_targets], [item.contribution.traits, run.preference.trait_targets],
      [item.contribution.conditions, run.preference.condition_targets], [item.contribution.mood, run.preference.mood_targets]] as const) {
      if (!same(Object.fromEntries(trace.components.map((c) => [c.key, c.expected])), targets) ||
        trace.components.some((component) => component.weight !== (component.compared ? 1 : 0))) invalid();
    }
  }
  if (authority.candidate_assessment_sha256 !== await canonicalHash(run.candidate_bindings) ||
    run.input_digest !== await canonicalHash({ preference: run.preference, authority }) ||
    run.canonical_sha256 !== await canonicalHash(without(run, ["run_id", "created_at", "canonical_sha256"])) ||
    run.run_id !== `recommendation-run:${run.canonical_sha256.slice(0, 32)}`) invalid();
  return result;
}

export async function getGroundedJson(path: string, options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {}): Promise<unknown> {
  let response: Response;
  try { response = await (options.fetchImpl ?? fetch)(path, { signal: options.signal, credentials: "same-origin" }); }
  catch { throw new ApiRequestError("추천 정보를 불러오지 못했어요.", null); }
  let payload: unknown;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new ApiRequestError("추천 정보를 불러오지 못했어요.", response.status, payload);
  return payload;
}

export async function fetchRecommendationEnvelope(runId: string, options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {}): Promise<RecommendationEnvelope> {
  if (!stableId.safeParse(runId).success) invalid();
  const payload = await getGroundedJson(`/v1/recommendation-runs/${encodeURIComponent(runId)}`, options);
  if (typeof payload === "object" && payload !== null && "schema_version" in payload && payload.schema_version === "itda.grounded-recommendation-results.v1")
    return parseGroundedResults(payload, runId);
  // Reuse the frozen old decoders against the already fetched body. No second HTTP request.
  return fetchRecommendationResults(runId, { ...options, fetchImpl: async () => new Response(JSON.stringify(payload), { status: 200 }) });
}
