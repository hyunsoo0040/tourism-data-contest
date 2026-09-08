import type { RecommendationResultsResponse } from "../../api/api";

type Mismatch = RecommendationResultsResponse["run"]["items"][number]["mismatch"];

const CONTROLLED_COPY = {
  NO_GUIDANCE: "이번 여행의 기대와 크게 다르지 않아요.",
  SUPPRESSED_LOW_CONFIDENCE: "근거가 충분하지 않아 기대 차이 안내를 생략했어요.",
} as const;

export function MismatchGuidance({
  mismatch,
  expectedValue,
  placeValue,
}: {
  mismatch: Mismatch;
  expectedValue?: number;
  placeValue?: number;
}) {
  const copy =
    mismatch.state === "NO_GUIDANCE" || mismatch.state === "SUPPRESSED_LOW_CONFIDENCE"
      ? CONTROLLED_COPY[mismatch.state]
      : mismatch.message_ko;
  return (
    <section className="recommendation-copy-section" data-mismatch-state={mismatch.state}>
      <p className="recommendation-copy-section__title">
        이번 여행에서 기대한 것과 다른 점
      </p>
      <p>{copy}</p>
      {mismatch.state === "SUPPRESSED_LOW_CONFIDENCE" && mismatch.suppression_reason !== null ? (
        <p className="recommendation-guidance-note" data-suppression-reason={mismatch.suppression_reason}>
          안내 생략 사유: 근거 신뢰도가 기준보다 낮아요.
        </p>
      ) : null}
      {mismatch.important_trait_floor_applied ? (
        <p className="recommendation-guidance-note">
          중요하게 고른 특성 차이가 저장된 안내에 반영됐어요.
        </p>
      ) : null}
      {expectedValue !== undefined && placeValue !== undefined ? (
        <p className="recommendation-guidance-note">
          기대 값 {expectedValue}점 · 장소 값 {placeValue}점
        </p>
      ) : null}
    </section>
  );
}
