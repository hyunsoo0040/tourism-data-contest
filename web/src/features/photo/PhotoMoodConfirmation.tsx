"use client";

import { useState } from "react";

type MoodDimension = "greenery" | "water" | "open_composition" | "traditional_appearance"
  | "contemporary_design" | "warm_light" | "vivid_color" | "night_lighting";
type MoodCandidateView = {
  candidate_id: string;
  observation: { dimension: MoodDimension; state: "OBSERVED" | "UNKNOWN"; level: number | null; certainty: "HIGH" | "LOW" };
};

/** A view projection of the validated versioned wire contract. The API decoder
 * owns full hash/schema validation; the component submits no scores or prose. */
export type MoodReviewView = {
  schema_version: "photo-mood-review.v1"; family: "photo-mood-v1";
  job_id: string; preference_profile_id: string; draft_sha256: string;
  batches: readonly { image_index: number; analysis_kind: "MODEL" | "SYNTHETIC"; candidates: readonly MoodCandidateView[] }[];
  confirmation: { choices: readonly { candidate_id: string; included: boolean }[] } | null;
};

export type MoodConfirmationInput = { draft_sha256: string; choices: { candidate_id: string; included: boolean }[] };

type Props = { review: MoodReviewView; onConfirm: (input: MoodConfirmationInput) => Promise<void>; onSkip: () => void };

export function PhotoMoodConfirmation(props: Props) {
  return <MoodConfirmationDraft key={props.review.draft_sha256} {...props} />;
}

function MoodConfirmationDraft({ review, onConfirm, onSkip }: Props) {
  const candidates = [...new Map(review.batches.flatMap((batch) =>
    batch.analysis_kind === "MODEL" ? batch.candidates
      .filter((row) => row.observation.state === "OBSERVED" && row.observation.certainty === "HIGH" && row.observation.level !== null)
      .map((row) => [row.candidate_id, { ...row, image_index: batch.image_index }] as const) : []
  )).values()];
  // Historical receipts are immutable; new analyses include every usable candidate.
  const choices = review.confirmation?.choices.map(row => ({ ...row })) ?? candidates
    .map(row => ({ candidate_id: row.candidate_id, included: true }))
    .sort((left, right) => left.candidate_id.localeCompare(right.candidate_id));
  const hasAtmosphere = choices.some(row => row.included);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);

  async function confirm() {
    if (pending) return;
    setPending(true);
    setError(false);
    try {
      await onConfirm({ draft_sha256: review.draft_sha256,
        choices,
      });
    } catch {
      setError(true);
    } finally {
      setPending(false);
    }
  }

  return <section aria-labelledby="photo-mood-heading" className="photo-review">
    <h2 id="photo-mood-heading">사진 분위기 분석을 완료했어요</h2>
    {review.confirmation !== null
      ? <p>이미 저장된 사진 분위기로 계속할 수 있어요.</p>
      : <p role="status">{hasAtmosphere ? "사진에서 확인한 분위기를 모두 추천에 자동으로 반영해요." : "사진에서 분위기를 확인하지 못했어요. 사진 없이 추천을 이어갈 수 있어요."}</p>}
    {error && <p role="alert">사진 분위기를 확정하지 못했어요. 다시 시도해 주세요.</p>}
    <div className="photo-action-bar" style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
      <button type="button" className="button button--primary" style={{ flex: "1 1 15rem", minHeight: "44px" }} disabled={pending} onClick={() => void confirm()}>
        {pending ? "사진 분위기 반영 중…" : hasAtmosphere ? "사진 분위기로 계속" : "사진 분위기 없이 계속"}
      </button>
      <button type="button" className="button button--secondary" style={{ flex: "1 1 12rem", minHeight: "44px" }} disabled={pending} onClick={onSkip}>사진 입력 건너뛰기</button>
    </div>
  </section>;
}
