import type { PreferenceProfile } from "../../api/api";
import type { components } from "../../contracts/generated/api";
import { readGroundedTripInput } from "../journey/groundedTrip";
import { api, currentToken, ensureSession, json, type Intent, type Photo, type Run } from "./api";

export type ScenarioSubmission = components["schemas"]["ScenarioSubmission"];
export const SCENARIO_PHOTO_KEY = "itda.scenario.confirmed-photo.v1";
const pendingKey = "itda.scenario.pending-run.v1";
export const scenarioResultsPath = (id: string) => `/recommendations/a-${encodeURIComponent(id)}`;
export const scenarioRunId = (id?: string) => id?.startsWith("a-") ? id.slice(2) : null;

export function readScenarioPhoto(profileId: string): Photo | null {
  try {
    const stored = JSON.parse(sessionStorage.getItem(SCENARIO_PHOTO_KEY) ?? "null");
    const photo = stored?.photo;
    return stored?.profileId === profileId && photo?.state === "CONFIRMED"
      && typeof photo.photo_id === "string" && /^[a-f0-9]{64}$/.test(photo.receipt_sha256)
      && Array.isArray(photo.batches) && photo.batches.every((batch: Photo["batches"][number]) =>
        Array.isArray(batch?.candidates) && batch.candidates.every(candidate => candidate?.observation && typeof candidate.candidate_id === "string"))
      && Array.isArray(photo.selected_candidate_ids) && photo.selected_candidate_ids.every((id: unknown) => typeof id === "string")
      && photo.targets && typeof photo.targets === "object" && !Array.isArray(photo.targets)
      ? photo as Photo : null;
  } catch { return null; }
}
export function writeScenarioPhoto(profileId: string, photo: Photo | null) {
  if (photo) sessionStorage.setItem(SCENARIO_PHOTO_KEY, json({ profileId, photo }));
  else sessionStorage.removeItem(SCENARIO_PHOTO_KEY);
}

export function scenarioInput(profile: PreferenceProfile, photo: Photo | null): Omit<ScenarioSubmission, "request_id"> {
  const conditions = readGroundedTripInput();
  if (!("q12" in profile.answers)) throw new Error("현재 상황형 문항으로 답변을 다시 확인해 주세요.");
  return {
    schema_version: "scenario-expectation-bridge.v1",
    questionnaire_config_hash: profile.config_hash,
    answers: profile.answers,
    trip_conditions: profile.trip_conditions,
    exact_visit_time: conditions.visit_time,
    requirements: { region_code: conditions.region_code ?? null, required_facilities: conditions.required_facilities },
    visual_targets: photo?.targets ?? {},
    visual_input_kind: photo ? "CONFIRMED_PHOTO" : "NONE",
    photo_receipt_sha256: photo?.receipt_sha256 ?? null,
  };
}

let pendingMemory: { fingerprint: string; profileRequest: string; runRequest: string } | null = null;
export async function recommendScenario(profile: PreferenceProfile, photo: Photo | null, signal: AbortSignal): Promise<Run> {
  const input = scenarioInput(profile, photo);
  await ensureSession();
  signal.throwIfAborted();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(json({ input, token: currentToken() })));
  const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  try { pendingMemory = JSON.parse(sessionStorage.getItem(pendingKey) ?? "null") ?? pendingMemory; } catch { /* in-memory retry */ }
  if (pendingMemory?.fingerprint !== fingerprint || !pendingMemory.profileRequest || !pendingMemory.runRequest) {
    pendingMemory = { fingerprint, profileRequest: crypto.randomUUID(), runRequest: crypto.randomUUID() };
  }
  const pending = pendingMemory;
  try { sessionStorage.setItem(pendingKey, json(pending)); } catch { /* current page still retries safely */ }
  const intent = await api<Intent>("/scenario-profiles", { method: "POST", body: json({ ...input, request_id: pending.profileRequest }), signal });
  signal.throwIfAborted();
  const run = await api<Run>("/runs", { method: "POST", body: json({ profile_id: intent.profile_id, request_id: pending.runRequest }), signal });
  if (run.profile_id !== intent.profile_id || run.intent_sha256 !== intent.intent_sha256 || run.ranking_version !== "scenario-axis-bridge-ranking.v1") {
    throw new Error("현재 답변과 추천 결과의 연결을 확인하지 못했어요. 다시 시도해 주세요.");
  }
  signal.throwIfAborted();
  pendingMemory = null;
  try { sessionStorage.removeItem(pendingKey); } catch { /* completed request remains idempotent */ }
  return run;
}
