import questionnaireV1Artifact from "../../../contracts/questionnaire-v1.json";
import { z } from "zod";

import type { components } from "../contracts/generated/api";

export type TripConditions = components["schemas"]["TripConditions"];
export type QuestionnaireAnswers = components["schemas"]["QuestionnaireAnswersV2"];

export const DRAFT_SCHEMA_VERSION = "phase1-draft-v1" as const;
export const PROFILE_REFERENCE_SCHEMA_VERSION = "phase1-profile-reference-v1" as const;
export const QUESTIONNAIRE_VERSION = "questionnaire-v2" as const;
/** Canonical schema_version for currently created (questionnaire-v2) profiles. */
export const PROFILE_SCHEMA_VERSION = "preference-profile-v2" as const;
export const SCORING_VERSION = "choice-distribution-v3" as const;
export const DESCRIPTION_TEMPLATE_VERSION = "current-trip-expectation-v1" as const;

/** Legacy questionnaire-v1 generation: stored profiles remain readable and replayable. */
export const LEGACY_PROFILE_SCHEMA_VERSION = "preference-profile-v1" as const;
export const LEGACY_QUESTIONNAIRE_VERSION = "questionnaire-v1" as const;
export const LEGACY_SCORING_VERSION = "integer-bp-v1" as const;
export const LEGACY_CONFIG_HASH = questionnaireV1Artifact.config_hash as string;

export const COMPARE_SELECTION_SCHEMA_VERSION = "phase5-compare-selection-v1" as const;
export const PHOTO_DRAFT_SCHEMA_VERSION = "itda.phase6.photo-draft.v1" as const;

const companionSchema = z.enum([
  "SOLO",
  "FRIEND_OR_PARTNER",
  "FAMILY_WITH_CHILDREN",
  "WITH_SENIORS",
  "GROUP",
]);
const transportSchema = z.enum(["WALK_OR_TRANSIT", "CAR_OR_TAXI", "MIXED"]);
const walkingToleranceSchema = z.enum([
  "WITHIN_30_MINUTES",
  "ABOUT_1_HOUR",
  "EXTENDED_WALKING_OK",
]);
const indoorOutdoorPreferenceSchema = z.enum(["INDOOR", "NO_PREFERENCE", "OUTDOOR"]);
const crowdAvoidanceSchema = z.enum(["LOW", "MEDIUM", "HIGH"]);
const visitTimeSchema = z.enum(["MORNING", "DAYTIME", "SUNSET", "EVENING", "UNDECIDED"]);

const isoDateTimeSchema = z.iso.datetime({ offset: true });
const nullableVisitDateSchema = z.union([z.iso.date(), z.null()]);

export const tripConditionsSchema: z.ZodType<TripConditions> = z.strictObject({
  visit_date: nullableVisitDateSchema,
  visit_time: visitTimeSchema,
  companion: companionSchema,
  transport: transportSchema,
  walking_tolerance: walkingToleranceSchema,
  indoor_outdoor_preference: indoorOutdoorPreferenceSchema,
  crowd_avoidance: crowdAvoidanceSchema,
});

export const partialTripConditionsSchema = z.strictObject({
  visit_date: nullableVisitDateSchema.optional(),
  visit_time: visitTimeSchema.optional(),
  companion: companionSchema.optional(),
  transport: transportSchema.optional(),
  walking_tolerance: walkingToleranceSchema.optional(),
  indoor_outdoor_preference: indoorOutdoorPreferenceSchema.optional(),
  crowd_avoidance: crowdAvoidanceSchema.optional(),
});

const answerSchema = z.int().min(1).max(3);
const legacyAnswerSchema = z.int().min(1).max(5);

export const partialAnswersSchema = z.strictObject({
  q1: answerSchema.optional(),
  q2: answerSchema.optional(),
  q3: answerSchema.optional(),
  q4: answerSchema.optional(),
  q5: answerSchema.optional(),
  q6: answerSchema.optional(),
  q7: answerSchema.optional(),
  q8: answerSchema.optional(),
  q9: answerSchema.optional(),
  q10: answerSchema.optional(),
  q11: answerSchema.optional(),
  q12: answerSchema.optional(),
});

export const questionnaireAnswersSchema = z.strictObject({
  q1: answerSchema,
  q2: answerSchema,
  q3: answerSchema,
  q4: answerSchema,
  q5: answerSchema,
  q6: answerSchema,
  q7: answerSchema,
  q8: answerSchema,
  q9: answerSchema,
  q10: answerSchema,
  q11: answerSchema,
  q12: answerSchema,
});

export const legacyQuestionnaireAnswersSchema = z.strictObject({
  q1: legacyAnswerSchema,
  q2: legacyAnswerSchema,
  q3: legacyAnswerSchema,
  q4: legacyAnswerSchema,
  q5: legacyAnswerSchema,
  q6: legacyAnswerSchema,
  q7: legacyAnswerSchema,
  q8: legacyAnswerSchema,
  q9: legacyAnswerSchema,
});

export const draftRecordSchema = z.strictObject({
  schema_version: z.literal(DRAFT_SCHEMA_VERSION),
  questionnaire_version: z.literal(QUESTIONNAIRE_VERSION),
  updated_at: isoDateTimeSchema,
  current_route: z.enum(["/start", "/quiz", "/profile"]),
  current_question: z.int().min(1).max(12),
  trip_conditions: partialTripConditionsSchema,
  answers: partialAnswersSchema,
});

/**
 * Stored profile references are version-coupled: every recorded field must
 * belong to one questionnaire generation. Mixed combinations (e.g. a legacy
 * v1 profile carrying the v2 scoring version) are rejected as corrupt rather
 * than silently reinterpreted.
 */
const profileReferenceFields = {
  schema_version: z.literal(PROFILE_REFERENCE_SCHEMA_VERSION),
  updated_at: isoDateTimeSchema,
  profile_id: z.string().trim().min(1).max(160),
};

export const currentProfileReferenceRecordSchema = z.strictObject({
  ...profileReferenceFields,
  profile_schema_version: z.literal(PROFILE_SCHEMA_VERSION),
  questionnaire_version: z.literal(QUESTIONNAIRE_VERSION),
  scoring_version: z.literal(SCORING_VERSION),
  description_template_version: z.literal(DESCRIPTION_TEMPLATE_VERSION),
});

export const legacyProfileReferenceRecordSchema = z.strictObject({
  ...profileReferenceFields,
  profile_schema_version: z.literal(LEGACY_PROFILE_SCHEMA_VERSION),
  questionnaire_version: z.literal(LEGACY_QUESTIONNAIRE_VERSION),
  scoring_version: z.literal(LEGACY_SCORING_VERSION),
  description_template_version: z.literal(DESCRIPTION_TEMPLATE_VERSION),
});

export const profileReferenceRecordSchema = z.union([
  currentProfileReferenceRecordSchema,
  currentProfileReferenceRecordSchema.extend({ scoring_version: z.literal("choice-bp-v2") }),
  legacyProfileReferenceRecordSchema,
]);

const recommendationIdentitySchema = z
  .string()
  .trim()
  .min(1)
  .max(160)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);

export const compareSelectionRecordSchema = z
  .strictObject({
    schema_version: z.literal(COMPARE_SELECTION_SCHEMA_VERSION),
    run_id: recommendationIdentitySchema,
    release_sha256: z.string().regex(/^[0-9a-f]{64}$/),
    place_ids: z.array(recommendationIdentitySchema).max(3),
    updated_at: isoDateTimeSchema,
  })
  .refine((record) => new Set(record.place_ids).size === record.place_ids.length, {
    message: "compare place IDs must be unique",
    path: ["place_ids"],
  });

export type DraftRecord = z.infer<typeof draftRecordSchema>;
export type DraftContents = Omit<
  DraftRecord,
  "schema_version" | "questionnaire_version" | "updated_at"
>;
export type ProfileReferenceRecord = z.infer<typeof profileReferenceRecordSchema>;
export type CompareSelectionRecord = z.infer<typeof compareSelectionRecordSchema>;

/**
 * Session-only photo job reference. Deliberately opaque and minimal: schema
 * version, opaque job ID, current profile ID, consent notice version, and
 * creation time. No bytes, previews, filenames, candidates, confirmed values,
 * provider output, or deletion evidence may ever enter this record.
 */
export const photoDraftRecordSchema = z.strictObject({
  schema_version: z.literal(PHOTO_DRAFT_SCHEMA_VERSION),
  job_id: recommendationIdentitySchema,
  profile_id: recommendationIdentitySchema,
  notice_version: z.string().trim().min(1).max(160),
  created_at: isoDateTimeSchema,
});

export type PhotoDraftRecord = z.infer<typeof photoDraftRecordSchema>;

export const tripConditionFormSchema = z.strictObject({
  visit_date: z.union([z.literal(""), z.iso.date()]).transform((value) => value || null),
  visit_time: visitTimeSchema,
  companion: companionSchema,
  transport: transportSchema,
  walking_tolerance: walkingToleranceSchema,
  indoor_outdoor_preference: indoorOutdoorPreferenceSchema,
  crowd_avoidance: crowdAvoidanceSchema,
});

export type TripConditionFormValues = {
  visit_date: string;
  visit_time: TripConditions["visit_time"] | "";
  companion: TripConditions["companion"] | "";
  transport: TripConditions["transport"] | "";
  walking_tolerance: TripConditions["walking_tolerance"] | "";
  indoor_outdoor_preference: TripConditions["indoor_outdoor_preference"] | "";
  crowd_avoidance: TripConditions["crowd_avoidance"] | "";
};
