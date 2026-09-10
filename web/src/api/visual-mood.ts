import { z } from "zod";
import { digest, stableId } from "./trip-context";
import { canonicalHash, halfUp, MOOD_KEYS, MOOD_POLICY_SHA, ordered, same, without, nullableScore } from "./grounded-core";

export const moodObservationSchema = z.strictObject({ dimension: z.enum(MOOD_KEYS), state: z.enum(["OBSERVED", "UNKNOWN"]),
  level: z.number().int().min(0).max(4).nullable(), certainty: z.enum(["HIGH", "LOW"]) })
  .refine((row) => row.state === "UNKNOWN" ? row.level === null && row.certainty === "LOW" : row.level !== null && row.certainty === "HIGH");
export const moodCandidateSetSchema = z.strictObject({
  schema_version: z.literal("photo-mood-candidates.v1"), family: z.literal("photo-mood-v1"), mood_version: z.literal("visual-mood-v1"),
  authority_scope: z.literal("VISUAL_MOOD_ONLY"), job_id: digest, image_index: z.number().int().min(1).max(3), payload_sha256: digest,
  policy_sha256: z.literal(MOOD_POLICY_SHA), provider_id: z.string().min(1).max(100), analysis_kind: z.enum(["MODEL", "SYNTHETIC"]),
  model: z.literal("glm-5.3-flash").nullable(), candidates: z.array(z.strictObject({ candidate_id: digest, observation: moodObservationSchema })).length(8),
  candidate_set_sha256: digest,
}).refine((row) => same(row.candidates.map((candidate) => candidate.observation.dimension), MOOD_KEYS) &&
  (row.analysis_kind === "SYNTHETIC" ? row.model === null && row.candidates.every((candidate) => candidate.observation.state === "UNKNOWN")
    : row.model === "glm-5.3-flash" && !row.provider_id.toLowerCase().includes("synthetic")));
export const projectedMoodSchema = z.strictObject({ dimension: z.enum(MOOD_KEYS), value: nullableScore,
  distinct_images: z.number().int().min(0).max(3), candidate_ids: z.array(digest).refine(ordered) })
  .refine((row) => (row.value === null) === (row.distinct_images === 0) && row.candidate_ids.length === row.distinct_images);
export const moodChoiceSchema = z.strictObject({ candidate_id: digest, included: z.boolean() });
export const confirmedMoodSchema = z.strictObject({
  schema_version: z.literal("photo-mood-projection.v1"), family: z.literal("photo-mood-v1"), job_id: digest,
  preference_profile_id: stableId, policy_sha256: z.literal(MOOD_POLICY_SHA), draft_sha256: digest,
  candidate_set_sha256: z.array(digest).refine(ordered), choices: z.array(moodChoiceSchema).max(24),
  moods: z.array(projectedMoodSchema).length(8), receipt_id: digest,
}).refine((row) => same(row.moods.map((mood) => mood.dimension), MOOD_KEYS) && ordered(row.choices.map((choice) => choice.candidate_id)));
export const moodReviewSchema = z.strictObject({
  schema_version: z.literal("photo-mood-review.v1"), family: z.literal("photo-mood-v1"), job_id: digest,
  preference_profile_id: stableId, draft_sha256: digest, batches: z.array(moodCandidateSetSchema).max(3), confirmation: confirmedMoodSchema.nullable(),
});
export type MoodCandidateSet = z.infer<typeof moodCandidateSetSchema>;
export type ProjectedMood = z.infer<typeof projectedMoodSchema>;
export type ConfirmedMood = z.infer<typeof confirmedMoodSchema>;
export type MoodReview = z.infer<typeof moodReviewSchema>;

export async function validateMoodBatch(batch: MoodCandidateSet): Promise<boolean> {
  if (batch.candidate_set_sha256 !== await canonicalHash(without(batch, ["candidate_set_sha256"]))) return false;
  for (const row of batch.candidates) {
    if (row.candidate_id !== await canonicalHash({ job_id: batch.job_id, image: batch.payload_sha256,
      observation: row.observation, provider_id: batch.provider_id, policy_sha256: batch.policy_sha256 })) return false;
  }
  return true;
}

export function aggregateMoodBatches(batches: MoodCandidateSet[], selected?: string[]): ProjectedMood[] | null {
  const images = new Map<string, MoodCandidateSet>();
  for (const batch of batches) {
    const previous = images.get(batch.payload_sha256);
    if (previous && !same(previous.candidates, batch.candidates)) return null;
    images.set(batch.payload_sha256, batch);
  }
  const candidates = [...images.values()].flatMap((batch) => batch.candidates);
  if (selected && selected.some((id) => !candidates.some((candidate) => candidate.candidate_id === id))) return null;
  return MOOD_KEYS.map((dimension) => {
    const rows = candidates.filter((candidate) => candidate.observation.dimension === dimension && candidate.observation.state === "OBSERVED" &&
      (!selected || selected.includes(candidate.candidate_id)));
    return { dimension, value: rows.length ? halfUp(rows.reduce((sum, row) => sum + row.observation.level! * 25, 0), rows.length) : null,
      distinct_images: rows.length, candidate_ids: rows.map((row) => row.candidate_id).sort() };
  });
}

export async function validateMoodConfirmation(confirmation: ConfirmedMood, review?: MoodReview): Promise<boolean> {
  if (confirmation.receipt_id !== await canonicalHash(without(confirmation, ["receipt_id"]))) return false;
  if (!review) return true;
  const candidates = new Map(review.batches.flatMap((batch) => batch.candidates).map((candidate) => [candidate.candidate_id, candidate]));
  return confirmation.job_id === review.job_id && confirmation.preference_profile_id === review.preference_profile_id &&
    confirmation.draft_sha256 === review.draft_sha256 && same(confirmation.candidate_set_sha256, [...new Set(review.batches.map((batch) => batch.candidate_set_sha256))].sort()) &&
    confirmation.choices.every((choice) => candidates.has(choice.candidate_id) && (!choice.included || candidates.get(choice.candidate_id)!.observation.state === "OBSERVED")) &&
    same(confirmation.moods, aggregateMoodBatches(review.batches, confirmation.choices.filter((choice) => choice.included).map((choice) => choice.candidate_id)));
}

export async function validateMoodReview(review: MoodReview): Promise<boolean> {
  if (review.batches.some((batch) => batch.job_id !== review.job_id) ||
    !(await Promise.all(review.batches.map(validateMoodBatch))).every(Boolean)) return false;
  const draft = await canonicalHash({ schema_version: "photo-mood-draft.v1", job_id: review.job_id,
    preference_profile_id: review.preference_profile_id, policy_sha256: MOOD_POLICY_SHA,
    candidate_set_sha256: [...new Set(review.batches.map((batch) => batch.candidate_set_sha256))].sort() });
  return review.draft_sha256 === draft && (review.confirmation === null || await validateMoodConfirmation(review.confirmation, review));
}
