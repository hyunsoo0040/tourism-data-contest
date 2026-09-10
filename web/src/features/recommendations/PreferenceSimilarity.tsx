export function similarityLabel(value: number | null): string {
  return value === null ? "비교 어려움" : `${value}%`;
}

export function SimilaritySummary({ value }: { value: number | null }) {
  return <p className="recommendation-fit" data-preference-similarity={value ?? "unknown"}>
    {value === null ? "내 취향과 비교할 근거가 부족해요" : <>내 취향과 <strong>{value}%</strong> 유사</>}
  </p>;
}

export const SIMILARITY_DESCRIPTION = "역사·전통, 감성·이미지, 휴식·몰입에서 내가 기대한 경험과 얼마나 가까운지 보여줘요.";
export const RECOMMENDATION_ORDER_DESCRIPTION = "추천 순서는 여행 조건과 사진 분위기, 장소의 다양성도 함께 고려해요.";
