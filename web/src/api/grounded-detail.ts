import { z } from "zod";
import { RecommendationContractError } from "./api";
import { digest, isoDate, placeMatch, sourceEvidence, sourceObservationSchema, sourceReceipt, stableId, utcDateTime } from "./trip-context";
import { aggregateMoodBatches, moodCandidateSetSchema, projectedMoodSchema, validateMoodBatch } from "./visual-mood";
import { canonicalHash, MOOD_KEYS, MOOD_POLICY_SHA, ordered, same, without } from "./grounded-core";
import { AXIS_KEYS, getGroundedJson, groundedItemSchema, type GroundedItem, type GroundedResults } from "./grounded-recommendation";

const season = z.enum(["SPRING", "SUMMER", "AUTUMN", "WINTER", "UNKNOWN"]), light = z.enum(["DAY", "NIGHT", "UNKNOWN"]);
const capture = { capture_date: isoDate.nullable(), capture_month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/).nullable(), season, light_context: light };
const decisionSchema = z.strictObject({ asset_id: stableId, original_sha256: digest, license: z.enum(["KOGL_TYPE_1", "KOGL_TYPE_3", "UNKNOWN"]),
  receipt: sourceReceipt, match: placeMatch, ...capture,
  decision: z.enum(["ANALYZED", "RIGHTS_EXCLUDED", "SOURCE_UNAVAILABLE", "MATCH_REJECTED", "TEMPORARY_EVENT_EXCLUDED", "PREPROCESSING_FAILED",
    "LOW_QUALITY", "EXACT_DUPLICATE", "PERCEPTUAL_DUPLICATE", "SCENE_ALTERNATE", "CAPACITY_EXCLUDED", "MODEL_UNAVAILABLE", "MODEL_REJECTED"]),
  reason: z.string().min(1).max(500), duplicate_of_asset_id: stableId.nullable(), sanitized_sha256: digest.nullable(),
  perceptual_hash: z.string().regex(/^[0-9a-f]{16}$/).nullable(), quality_score_milli: z.number().int().min(0).max(1000).nullable() });
const imageSchema = z.strictObject({ asset_id: stableId, original_sha256: digest, sanitized_sha256: digest,
  preprocessing_policy_sha256: digest, preprocessing_audit_sha256: digest, ...capture,
  scene_group: z.string().min(1).max(200), attribution_ko: z.string().min(1).max(500), evidence: sourceEvidence, candidate_set: moodCandidateSetSchema })
  .refine((row) => row.evidence.modality === "IMAGE_PIXELS" && row.evidence.image_sha256 === row.original_sha256 &&
    row.candidate_set.payload_sha256 === row.sanitized_sha256 && (!row.capture_date || !row.capture_month || row.capture_date.slice(0, 7) === row.capture_month));
export const destinationMoodSchema = z.strictObject({
  schema_version: z.literal("destination-mood.v1"), authority_scope: z.literal("VISUAL_MOOD_ONLY"), place_id: stableId,
  raw_profile_sha256: digest, source_release_sha256: digest, assessed_at: utcDateTime, mood_policy_sha256: z.literal(MOOD_POLICY_SHA),
  selection_policy_sha256: digest, images: z.array(imageSchema).max(3), decisions: z.array(decisionSchema),
  strata: z.array(z.strictObject({ season, light_context: light, asset_ids: z.array(stableId).min(1).refine(ordered), moods: z.array(projectedMoodSchema).length(8) })
    .refine((row) => same(row.moods.map((mood) => mood.dimension), MOOD_KEYS))),
  limit_ko: z.string().min(1).max(600), bundle_sha256: digest,
});
const dimensions = [...AXIS_KEYS, ...["H", "E", "R"].flatMap((axis) => [1, 2, 3, 4].map((number) => axis + number)), ...[1, 2, 3, 4, 5, 6].map((number) => `M${number}`)];
const assessmentSchema = z.strictObject({ schema_version: z.literal("place-assessment.v1"), policy_version: z.literal("source-assessment-v1"),
  place_id: stableId, raw_profile_sha256: digest, source_release_sha256: digest, assessed_at: utcDateTime,
  dimensions: z.record(z.string(), sourceObservationSchema), facts: z.record(z.string(), sourceObservationSchema), bundle_sha256: digest })
  .refine((row) => same(Object.keys(row.dimensions).sort(), [...dimensions].sort()) &&
    Object.entries({ ...row.dimensions, ...row.facts }).every(([key, observation]) => key === observation.key &&
      observation.evidence.every((source) => source.place_match === null || source.place_match.place_id === row.place_id)) &&
    Object.keys(row.facts).every((key) => !(key in row.dimensions)) &&
    Object.entries(row.dimensions).every(([key, observation]) => observation.claim !== "VISUAL_MOOD" && (key !== "M3" || observation.claim === "CROWD") &&
      (observation.value === null || (typeof observation.value === "number" && Number.isInteger(observation.value) && observation.value >= 0 &&
        observation.value <= (/^[HER][1-4]$/.test(key) ? 4 : 100)))));
const detailSchema = z.strictObject({ schema_version: z.literal("itda.grounded-recommendation-detail.v1"), recommendation_run_id: stableId,
  release_sha256: digest, item: groundedItemSchema, assessment: assessmentSchema, mood: destinationMoodSchema });
const comparisonSchema = z.strictObject({ schema_version: z.literal("itda.grounded-recommendation-comparison.v1"), recommendation_run_id: stableId,
  release_sha256: digest, places: z.array(detailSchema).min(2).max(3) });
export type GroundedDetail = z.infer<typeof detailSchema>;
export type DestinationMood = z.infer<typeof destinationMoodSchema>;

async function validateDestinationMood(bundle: DestinationMood): Promise<boolean> {
  if (bundle.bundle_sha256 !== await canonicalHash(without(bundle, ["bundle_sha256"])) ||
    !ordered(bundle.images.map((image) => image.asset_id)) || !ordered(bundle.decisions.map((decision) => decision.asset_id)) ||
    new Set(bundle.images.map((image) => image.original_sha256)).size !== bundle.images.length ||
    new Set(bundle.images.map((image) => image.scene_group)).size !== bundle.images.length ||
    !same(bundle.images.map((image) => image.asset_id), bundle.decisions.filter((decision) => decision.decision === "ANALYZED").map((decision) => decision.asset_id))) return false;
  const expectedJob = await canonicalHash({ scope: "destination-mood.v1", place_id: bundle.place_id, raw_profile_sha256: bundle.raw_profile_sha256,
    source_release_sha256: bundle.source_release_sha256, selection_policy_sha256: bundle.selection_policy_sha256 });
  for (const image of bundle.images) {
    const decision = bundle.decisions.find((decision) => decision.asset_id === image.asset_id)!;
    if (image.evidence.place_match?.place_id !== bundle.place_id || image.candidate_set.job_id !== expectedJob || !await validateMoodBatch(image.candidate_set) ||
      decision.original_sha256 !== image.original_sha256 || decision.sanitized_sha256 !== image.sanitized_sha256 || !same(decision.receipt, image.evidence.receipt) ||
      !same(decision.match, image.evidence.place_match) || decision.season !== image.season || decision.light_context !== image.light_context) return false;
  }
  const contexts = bundle.strata.map((row) => `${row.season}|${row.light_context}`);
  if (!ordered(contexts) || !same(contexts, [...new Set(bundle.images.map((image) => `${image.season}|${image.light_context}`))].sort())) return false;
  return bundle.strata.every((stratum) => {
    const images = bundle.images.filter((image) => image.season === stratum.season && image.light_context === stratum.light_context);
    return same(stratum.asset_ids, images.map((image) => image.asset_id).sort()) && same(stratum.moods, aggregateMoodBatches(images.map((image) => image.candidate_set)));
  });
}

export async function parseGroundedDetail(payload: unknown, results: GroundedResults, placeId: string): Promise<GroundedDetail> {
  const parsed = detailSchema.safeParse(payload);
  const expected = results.run.items.find((item) => item.place_id === placeId);
  if (!parsed.success || !expected) throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  const row = parsed.data;
  // The public grounded release pins raw scores plus their source/mood sidecars.
  if (row.recommendation_run_id !== results.run.run_id || row.release_sha256 !== results.run.authority.candidate_sha256 || !same(row.item, expected) ||
    row.assessment.place_id !== placeId || row.mood.place_id !== placeId || row.item.assessment_bundle_sha256 !== row.assessment.bundle_sha256 ||
    row.item.raw_profile_sha256 !== row.assessment.raw_profile_sha256 || row.item.raw_profile_sha256 !== row.mood.raw_profile_sha256 ||
    row.assessment.source_release_sha256 !== row.mood.source_release_sha256 || row.assessment.source_release_sha256 !== results.run.authority.source_release_sha256 ||
    row.assessment.bundle_sha256 !== await canonicalHash(without(row.assessment, ["bundle_sha256"])) || !await validateDestinationMood(row.mood))
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  return row;
}

export async function fetchGroundedDetail(results: GroundedResults, placeId: string, options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {}): Promise<GroundedDetail> {
  const payload = await getGroundedJson(`/v1/recommendation-runs/${encodeURIComponent(results.run.run_id)}/places/${encodeURIComponent(placeId)}`, options);
  return parseGroundedDetail(payload, results, placeId);
}
export async function fetchGroundedComparison(results: GroundedResults, placeIds: string[], options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {}): Promise<GroundedDetail[]> {
  if (placeIds.length < 2 || placeIds.length > 3 || new Set(placeIds).size !== placeIds.length || placeIds.some((id) => !results.run.items.some((item: GroundedItem) => item.place_id === id)))
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  const query = new URLSearchParams();
  placeIds.forEach((id) => query.append("place_id", id));
  const payload = await getGroundedJson(`/v1/recommendation-runs/${encodeURIComponent(results.run.run_id)}/comparison?${query}`, options);
  const parsed = comparisonSchema.safeParse(payload);
  if (!parsed.success || parsed.data.recommendation_run_id !== results.run.run_id || parsed.data.release_sha256 !== results.run.authority.candidate_sha256 ||
    !same(parsed.data.places.map((place) => place.item.place_id), placeIds)) throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  return Promise.all(parsed.data.places.map((place, index) => parseGroundedDetail(place, results, placeIds[index]!)));
}
