import type { ComparisonRow, RecommendationResultsResponse } from "../../api/api";
import { OperatingInformation } from "./OperatingInformation";
import type { OperatingInformationState } from "./useOperatingInformation";
import { similarityLabel } from "./PreferenceSimilarity";

type RecommendationItem = RecommendationResultsResponse["run"]["items"][number];

const AXIS_LABELS = {
  HISTORY_TRADITION: "역사·전통 유사도",
  EMOTION_IMAGE: "감성·이미지 유사도",
  REST_IMMERSION: "휴식·몰입 유사도",
} as const;

const MISSING_REASON_COPY = {
  OPERATING_INFORMATION_UNVERIFIED: "운영 정보가 확인되지 않았어요.",
} as const;

function cellValue(row: ComparisonRow, index: number): string {
  const reason = row.missing_reasons[index];
  if (reason === null) return row.values_ko[index] || "정보 없음";
  const copy = MISSING_REASON_COPY[reason as keyof typeof MISSING_REASON_COPY] ?? "확인되지 않았어요.";
  return `정보 없음 — ${copy}`;
}

export function ComparisonTable({
  placeNames,
  rows,
  placeIds,
  items = [],
  operatingInformation,
}: {
  placeNames: readonly string[];
  rows: readonly ComparisonRow[];
  placeIds?: readonly string[];
  items?: readonly RecommendationItem[];
  operatingInformation?: OperatingInformationState;
}) {
  const byId = new Map(items.map((item) => [item.place_id, item]));
  const selected = placeNames.map((_, index) => byId.get(placeIds?.[index] ?? ""));
  const similarityRows: ComparisonRow[] = [
    {
      row_id: "preference-similarity",
      label_ko: "내 취향과의 유사도",
      values_ko: selected.map((item) => similarityLabel(item?.contribution.experience_fit_score ?? null)),
      missing_reasons: selected.map(() => null),
    },
    ...Object.entries(AXIS_LABELS).map(([axis, label]) => ({
      row_id: `similarity-${axis}`,
      label_ko: label,
      values_ko: selected.map((item) => similarityLabel(
        item?.contribution.axis_components.find((component) => component.axis === axis)?.fit_score ?? null,
      )),
      missing_reasons: selected.map(() => null),
    })),
  ];
  const displayRows = [
    ...similarityRows,
    ...rows.filter((row) => row.row_id !== "fit-score"
      && !row.row_id.startsWith("axis-")
      && !row.row_id.startsWith("trait-")
      && row.row_id !== "time-season-context"),
  ];
  return (
    <section className="comparison-table-section" aria-labelledby="comparison-table-heading">
      <h2 id="comparison-table-heading">내 취향과의 유사도 비교</h2>
      <p id="comparison-table-instruction">
        표를 좌우로 이동해 모든 장소를 확인할 수 있어요.
      </p>
      <div
        className="comparison-table-region"
        role="region"
        aria-label="장소 비교표"
        aria-describedby="comparison-table-instruction"
        tabIndex={0}
      >
        <table className="comparison-table">
          <caption>선택한 장소 2~3곳 비교</caption>
          <thead>
            <tr>
              <th scope="col">비교 항목</th>
              {placeNames.map((placeName) => (
                <th scope="col" key={placeName}>{placeName}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {displayRows.map((row) => (
              <tr key={row.row_id}>
                <th scope="row">{row.label_ko}</th>
                {placeNames.map((placeName, index) => (
                  <td key={`${row.row_id}:${placeName}`}>{cellValue(row, index)}</td>
                ))}
              </tr>
            ))}
            {placeIds === undefined || operatingInformation === undefined ? null : (
              <tr data-operating-comparison-row>
                <th scope="row">최신 운영 정보</th>
                {placeIds.map((placeId) => (
                  <td key={`current-operating:${placeId}`}>
                    <OperatingInformation
                      information={
                        operatingInformation.kind === "resolved"
                          ? operatingInformation.places.get(placeId)
                          : undefined
                      }
                      loading={operatingInformation.kind === "loading"}
                      compact
                    />
                  </td>
                ))}
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
