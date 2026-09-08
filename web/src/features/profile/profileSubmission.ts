import {
  createPreferenceProfile,
  profileSubmissionFingerprint,
  type PreferenceProfile,
  type QuestionnaireSubmission,
} from "../../api/api";
import type { QuestionnaireAnswers, TripConditions } from "../../app/schemas";
import {
  clearPendingProfileSubmission,
  readPendingProfileSubmission,
  writePendingProfileSubmission,
  writeProfileReference,
  type ProfileWriteResult,
} from "../../app/storage";

export async function createAndStorePreferenceProfile(
  tripConditions: TripConditions,
  answers: QuestionnaireAnswers,
  signal?: AbortSignal,
  shouldStore: () => boolean = () => true,
): Promise<{ profile: PreferenceProfile; reference: ProfileWriteResult | null }> {
  const payloadSha256 = await profileSubmissionFingerprint(tripConditions, answers);
  const existingPending = readPendingProfileSubmission(payloadSha256);
  const requestId = existingPending?.request_id ?? crypto.randomUUID();
  if (existingPending === null) writePendingProfileSubmission(payloadSha256, requestId);
  const submission: QuestionnaireSubmission = {
    request_id: requestId,
    trip_conditions: tripConditions,
    answers,
  };
  const profile = await createPreferenceProfile(submission, { signal });
  if (!shouldStore()) return { profile, reference: null };
  const reference = writeProfileReference(profile.profile_id);
  if (reference.state === "persisted") clearPendingProfileSubmission(requestId);
  return { profile, reference };
}
