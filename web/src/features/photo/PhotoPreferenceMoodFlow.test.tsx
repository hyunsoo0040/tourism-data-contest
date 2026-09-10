import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { writePhotoDraft, clearPhotoDraft } from "../../app/storage";
import { canonicalHash, MOOD_KEYS, MOOD_POLICY_SHA } from "../../api/grounded-core";
import { aggregateMoodBatches, type MoodReview, type ConfirmedMood } from "../../api/visual-mood";
import { PhotoPreferenceFlow } from "./PhotoPreferenceFlow";

afterEach(() => { cleanup(); clearPhotoDraft(); window.sessionStorage.clear(); });

async function fixture() {
  const job = "a".repeat(64), profile = "profile:mood-flow";
  const candidates = await Promise.all(MOOD_KEYS.map(async (dimension) => {
    const observation = { dimension, state: dimension === "water" ? "OBSERVED" as const : "UNKNOWN" as const,
      level: dimension === "water" ? 3 : null, certainty: dimension === "water" ? "HIGH" as const : "LOW" as const };
    return { observation, candidate_id: await canonicalHash({ job_id: job, image: "b".repeat(64), observation,
      provider_id: "glm-mood-test", policy_sha256: MOOD_POLICY_SHA }) };
  }));
  const batchFields = { schema_version: "photo-mood-candidates.v1" as const, family: "photo-mood-v1" as const,
    mood_version: "visual-mood-v1" as const, authority_scope: "VISUAL_MOOD_ONLY" as const,
    job_id: job, image_index: 1, payload_sha256: "b".repeat(64), policy_sha256: MOOD_POLICY_SHA as typeof MOOD_POLICY_SHA,
    provider_id: "glm-mood-test", analysis_kind: "MODEL" as const, model: "glm-5.3-flash" as const, candidates };
  const batch = { ...batchFields, candidate_set_sha256: await canonicalHash(batchFields) };
  const draft = await canonicalHash({ schema_version: "photo-mood-draft.v1", job_id: job,
    preference_profile_id: profile, policy_sha256: MOOD_POLICY_SHA, candidate_set_sha256: [batch.candidate_set_sha256] });
  const review: MoodReview = { schema_version: "photo-mood-review.v1", family: "photo-mood-v1", job_id: job,
    preference_profile_id: profile, draft_sha256: draft, batches: [batch], confirmation: null };
  const confirm = vi.fn(async (_job: string, input: { draft_sha256: string; choices: { candidate_id: string; included: boolean }[] }) => {
    const fields = { schema_version: "photo-mood-projection.v1" as const, family: "photo-mood-v1" as const, job_id: job,
      preference_profile_id: profile, policy_sha256: MOOD_POLICY_SHA as typeof MOOD_POLICY_SHA, draft_sha256: draft,
      candidate_set_sha256: [batch.candidate_set_sha256], choices: input.choices,
      moods: aggregateMoodBatches([batch], input.choices.filter((row) => row.included).map((row) => row.candidate_id))! };
    return { ...fields, receipt_id: await canonicalHash(fields) } satisfies ConfirmedMood;
  });
  const client = { createPhotoJob: vi.fn(), getPhotoJob: vi.fn().mockResolvedValue({ job_id: job, state: "succeeded", analysis_family: "photo-mood-v1" }),
    getPhotoJobMoods: vi.fn().mockResolvedValue(review), getPhotoJobTraits: vi.fn(), confirmPhotoJobMoods: confirm, requestPhotoDeletion: vi.fn().mockResolvedValue({ state: "deleted" }) };
  writePhotoDraft({ jobId: job, profileId: profile, noticeVersion: "photo-consent-2026-08-v1" });
  return { job, profile, review, client, confirm };
}

describe("actual mood family flow", () => {
  it("resumes the server mood family and confirms only its stored references", async () => {
    const data = await fixture(), onMoodConfirmed = vi.fn(), onConfirmed = vi.fn();
    render(<PhotoPreferenceFlow profileId={data.profile} client={data.client} onNoPhoto={vi.fn()} onConfirmed={onConfirmed} onMoodConfirmed={onMoodConfirmed} />);
    await screen.findByText("사진에서 마음에 든 분위기를 골라 주세요");
    fireEvent.click(screen.getByRole("button", { name: "선택한 분위기로 계속" }));
    await waitFor(() => expect(onMoodConfirmed).toHaveBeenCalledTimes(1));
    expect(data.client.getPhotoJobTraits).not.toHaveBeenCalled();
    expect(onConfirmed).not.toHaveBeenCalled();
    expect(data.confirm.mock.calls[0]![1]).toEqual({ draft_sha256: data.review.draft_sha256,
      choices: [{ candidate_id: data.review.batches[0]!.candidates[1]!.candidate_id, included: true }] });
  });

  it("retains a confirmed receipt when all appearance choices are excluded", async () => {
    const data = await fixture(), confirmed = vi.fn(), noPhoto = vi.fn();
    render(<PhotoPreferenceFlow profileId={data.profile} client={data.client} onNoPhoto={noPhoto} onMoodConfirmed={confirmed} />);
    await screen.findByText("사진에서 마음에 든 분위기를 골라 주세요");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "사진 분위기 없이 계속" }));
    await waitFor(() => expect(confirmed).toHaveBeenCalledTimes(1));
    expect(confirmed.mock.calls[0]![0].moods.every((row: { value: number | null }) => row.value === null)).toBe(true);
    expect(noPhoto).not.toHaveBeenCalled();
  });

  it("does not reinterpret a corrupted mood payload as historical traits", async () => {
    const data = await fixture();
    data.client.getPhotoJobMoods.mockResolvedValue({ ...data.review, draft_sha256: "f".repeat(64) });
    render(<PhotoPreferenceFlow profileId={data.profile} client={data.client} onNoPhoto={vi.fn()} onMoodConfirmed={vi.fn()} />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
    expect(data.client.getPhotoJobTraits).not.toHaveBeenCalled();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("reopens an immutable all-excluded confirmation without another confirmation POST", async () => {
    const data = await fixture(), confirmed = vi.fn();
    const receipt = await data.confirm(data.job, { draft_sha256: data.review.draft_sha256, choices: [] });
    data.confirm.mockClear();
    data.client.getPhotoJobMoods.mockResolvedValue({ ...data.review, confirmation: receipt });
    render(<PhotoPreferenceFlow profileId={data.profile} client={data.client} onNoPhoto={vi.fn()} onMoodConfirmed={confirmed} />);
    await screen.findByText("이미 확정한 사진 분위기입니다. 저장된 선택으로 계속할 수 있어요.");
    expect(screen.getByRole("checkbox").matches(":disabled")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "사진 분위기 없이 계속" }));
    await waitFor(() => expect(confirmed).toHaveBeenCalledWith(receipt, data.job));
    expect(data.confirm).not.toHaveBeenCalled();
  });
});
