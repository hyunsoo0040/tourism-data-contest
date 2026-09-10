"use client";

import { useState } from "react";

const MOOD_LABELS = {
  greenery: "초록 식물이 보이는 풍경", water: "물이 보이는 풍경",
  open_composition: "시야가 트여 보이는 구도", traditional_appearance: "전통적으로 보이는 외관",
  contemporary_design: "현대적으로 보이는 디자인", warm_light: "따뜻한 빛의 색감",
  vivid_color: "선명한 색감", night_lighting: "밤 조명이 보이는 장면",
} as const;

type MoodDimension = keyof typeof MOOD_LABELS;
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
      .filter((row) => row.observation.state === "OBSERVED" && row.observation.certainty === "HIGH")
      .map((row) => [row.candidate_id, { ...row, image_index: batch.image_index }] as const) : []
  )).values()];
  const [selected, setSelected] = useState<Set<string>>(() => new Set(
    review.confirmation ? review.confirmation.choices.filter((row) => row.included).map((row) => row.candidate_id)
      : candidates.map((row) => row.candidate_id),
  ));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);

  async function confirm() {
    if (pending) return;
    setPending(true);
    setError(false);
    try {
      await onConfirm({ draft_sha256: review.draft_sha256,
        choices: candidates.map((row) => ({ candidate_id: row.candidate_id, included: selected.has(row.candidate_id) }))
          .sort((left, right) => left.candidate_id.localeCompare(right.candidate_id)),
      });
    } catch {
      setError(true);
    } finally {
      setPending(false);
    }
  }

  return <section aria-labelledby="photo-mood-heading" className="photo-review">
    <h2 id="photo-mood-heading">사진에서 마음에 든 분위기를 골라 주세요</h2>
    <p>빛과 색, 풍경의 인상을 추천에 참고합니다. 마음에 들지 않는 제안은 빼도 괜찮아요.</p>
    {candidates.length === 0 ? <p>사진에서 확실히 확인할 수 있는 분위기 제안이 없습니다.</p>
      : <fieldset disabled={pending || review.confirmation !== null} style={{ border: 0, padding: 0, display: "grid", gap: "1rem" }}>
        <legend className="visually-hidden">추천에 참고할 사진 분위기</legend>
        {candidates.map((candidate) => <label key={candidate.candidate_id} className="photo-review__row"
          style={{ display: "flex", alignItems: "center", gap: "0.75rem", minHeight: "44px" }}>
          <input type="checkbox" checked={selected.has(candidate.candidate_id)}
            onChange={() => setSelected((previous) => {
              const next = new Set(previous);
              if (next.has(candidate.candidate_id)) next.delete(candidate.candidate_id);
              else next.add(candidate.candidate_id);
              return next;
            })} />
          <span>사진 {candidate.image_index} · {MOOD_LABELS[candidate.observation.dimension]}</span>
        </label>)}
      </fieldset>}
    <p>확인하기 어려운 분위기는 점수로 채우지 않습니다.</p>
    {review.confirmation !== null && <p>이미 확정한 사진 분위기입니다. 저장된 선택으로 계속할 수 있어요.</p>}
    {error && <p role="alert">사진 분위기를 확정하지 못했어요. 다시 시도해 주세요.</p>}
    <div className="photo-action-bar" style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
      <button type="button" className="button button--primary" style={{ flex: "1 1 15rem", minHeight: "44px" }} disabled={pending} onClick={() => void confirm()}>
        {pending ? "선택 저장 중…" : selected.size ? "선택한 분위기로 계속" : "사진 분위기 없이 계속"}
      </button>
      <button type="button" className="button button--secondary" style={{ flex: "1 1 12rem", minHeight: "44px" }} disabled={pending} onClick={onSkip}>사진 입력 건너뛰기</button>
    </div>
  </section>;
}
