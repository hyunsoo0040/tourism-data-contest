/**
 * Photo-job HTTP client for the optional photo subflow.
 *
 * Plain fetch against the shipped loopback API. The flow's closed reducers
 * already decode snapshots with whole-payload validators, so this client only
 * handles transport: request building, status checks, and JSON reading. It
 * never touches providers, credentials, or non-loopback hosts.
 */

type PhotoJsonResponse = unknown;

import { moodReviewSchema, confirmedMoodSchema, validateMoodReview, validateMoodConfirmation,
  type MoodReview, type ConfirmedMood } from "../../api/visual-mood";

export async function getPhotoJobMoodsRequest(jobId: string): Promise<MoodReview> {
  const parsed = moodReviewSchema.safeParse(await requestJson(`/v1/photo-jobs/${encodeURIComponent(jobId)}/moods`,
    { method: "GET", credentials: "same-origin" }, "사진 분위기 제안을 확인하지 못했어요."));
  if (!parsed.success || parsed.data.job_id !== jobId || !await validateMoodReview(parsed.data)) {
    throw new Error("사진 분위기 근거를 확인하지 못했어요.");
  }
  return parsed.data;
}

export async function confirmPhotoJobMoodsRequest(jobId: string, input: {
  draft_sha256: string; choices: Array<{ candidate_id: string; included: boolean }>;
}): Promise<ConfirmedMood> {
  const parsed = confirmedMoodSchema.safeParse(await requestJson(`/v1/photo-jobs/${encodeURIComponent(jobId)}/moods/confirm`,
    { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input) },
    "사진 분위기를 확정하지 못했어요."));
  if (!parsed.success || parsed.data.job_id !== jobId || !await validateMoodConfirmation(parsed.data)) {
    throw new Error("사진 분위기 확정 근거를 확인하지 못했어요.");
  }
  return parsed.data;
}

async function requestJson(
  path: string,
  init: RequestInit,
  failureMessage: string,
): Promise<PhotoJsonResponse> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new Error(failureMessage);
  }
  if (!response.ok) {
    throw new Error(failureMessage);
  }
  try {
    return (await response.json()) as PhotoJsonResponse;
  } catch {
    throw new Error(failureMessage);
  }
}

export function createPhotoJobRequest(
  input: { consent_accepted: boolean; consent_version: string },
): Promise<unknown> {
  return requestJson(
    "/v1/photo-jobs",
    {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    },
    "사진 작업을 만들지 못했어요.",
  );
}

export function getPhotoJobRequest(jobId: string): Promise<unknown> {
  const normalized = jobId.trim();
  if (normalized.length === 0 || normalized.length > 160) {
    return Promise.reject(new Error("사진 작업을 확인하지 못했어요."));
  }
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(normalized)}`,
    { method: "GET", credentials: "same-origin" },
    "사진 진행 상태를 확인하지 못했어요.",
  );
}

export function getPhotoJobTraitsRequest(jobId: string): Promise<unknown> {
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(jobId)}/traits`,
    { method: "GET", credentials: "same-origin" },
    "사진 취향 후보를 확인하지 못했어요.",
  );
}

export function putPhotoJobImageRequest(input: {
  jobId: string;
  imageIndex: number;
  file: File;
}): Promise<unknown> {
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(input.jobId)}/images/${input.imageIndex}`,
    {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": input.file.type || "application/octet-stream" },
      body: input.file,
    },
    "사진을 보내지 못했어요.",
  );
}

export function submitPhotoJobRequest(jobId: string): Promise<unknown> {
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(jobId)}/submit`,
    { method: "POST", credentials: "same-origin" },
    "사진 분석 시작을 확인하지 못했어요.",
  );
}

export function confirmPhotoJobTraitsRequest(
  jobId: string,
  input: {
    confirmations: Array<{
      trait_id: string;
      text_ko: string;
      source_candidate_id: string | null;
      included: boolean;
    }>;
  },
): Promise<unknown> {
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(jobId)}/traits/confirm`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    },
    "확정한 취향을 저장하지 못했어요.",
  );
}

export function requestPhotoDeletionRequest(jobId: string): Promise<unknown> {
  return requestJson(
    `/v1/photo-jobs/${encodeURIComponent(jobId)}`,
    { method: "DELETE", credentials: "same-origin" },
    "삭제 요청을 확인하지 못했어요.",
  );
}
