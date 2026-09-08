import type { ComparisonRow } from "../../api/api";
import { OperatingInformation } from "./OperatingInformation";
import type { OperatingInformationState } from "./useOperatingInformation";

const MISSING_REASON_COPY = {
  OPERATING_INFORMATION_UNVERIFIED: "운영 정보가 확인되지 않았어요.",
} as const;

function cellValue(row: ComparisonRow, index: number): string {
  const reason = row.missing_reasons[index];
  if (reason === null) return row.values_ko[index]!;
  const copy = MISSING_REASON_COPY[reason as keyof typeof MISSING_REASON_COPY];
  return `정보 없음 — ${copy}`;
}

export function ComparisonTable({
  placeNames,
  rows,
  placeIds,
  operatingInformation,
}: {
  placeNames: readonly string[];
  rows: readonly ComparisonRow[];
  placeIds?: readonly string[];
  operatingInformation?: OperatingInformationState;
}) {
  return (
    <section className="comparison-table-section" aria-labelledby="comparison-table-heading">
      <h2 id="comparison-table-heading">장소별 저장 근거 비교</h2>
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
            {rows.map((row) => (
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
