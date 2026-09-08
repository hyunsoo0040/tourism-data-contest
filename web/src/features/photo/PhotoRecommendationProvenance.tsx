/**
 * Static recommendation provenance sentence. Only two closed values exist:
 * a confirmed-photo projection or the original no-photo projection. Provider,
 * model, and internal state names never appear in the public sentence.
 */

export type PhotoRecommendationProvenanceValue = "CONFIRMED_PHOTO" | "NO_PHOTO";

const COPY = {
  CONFIRMED_PHOTO:
    "직접 확인한 사진 취향을 기대 프로필에 반영해 고른 경주 여행지예요.",
  NO_PHOTO: "사진 없이 만든 기대 프로필로 고른 경주 여행지예요.",
} as const;

export function PhotoRecommendationProvenance({
  provenance,
}: {
  provenance: PhotoRecommendationProvenanceValue;
}) {
  return <p className="privacy-note">{COPY[provenance]}</p>;
}
