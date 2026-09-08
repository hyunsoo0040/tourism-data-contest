import type { PlaceOperatingInformation } from "../../api/api";

const UNAVAILABLE_COPY = {
  ENRICHMENT_DISABLED: "운영 정보 미확인 — 방문 전 공식 안내를 확인해 주세요.",
  NOT_IN_PROVIDER_SCOPE: "공식 운영 정보 조회 범위에 포함되지 않았어요.",
  NO_OPERATING_FIELDS: "공식 제공 자료에서 운영 정보를 확인하지 못했어요.",
  PROVIDER_UNAVAILABLE: "현재 공식 운영 정보를 불러오지 못했어요. 방문 전 다시 확인해 주세요.",
} as const;

function formatRetrievedAt(value: string): string {
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(new Date(value));
}

export function OperatingInformation({
  information,
  loading,
  compact = false,
}: {
  information?: PlaceOperatingInformation;
  loading: boolean;
  compact?: boolean;
}) {
  if (loading) {
    return <p data-operating-information-state="loading">최신 운영 정보를 확인하고 있어요.</p>;
  }
  const snapshot = information?.snapshot;
  if (information?.state !== "AVAILABLE" || snapshot == null) {
    const reason = information?.unavailable_reason;
    const copy = reason == null ? undefined : UNAVAILABLE_COPY[reason];
    return (
      <p data-operating-information-state="unverified">
        {copy ?? "운영 정보 미확인 — 방문 전 공식 안내를 확인해 주세요."}
      </p>
    );
  }

  const entries = compact ? snapshot.entries.slice(0, 3) : snapshot.entries;
  return (
    <div data-operating-information-state="available">
      <dl className="operating-information-list">
        {entries.map((entry) => (
          <div key={entry.provider_field}>
            <dt>{entry.label_ko}</dt>
            <dd>{entry.value_ko}</dd>
          </div>
        ))}
      </dl>
      <p className="operating-information-meta">
        {snapshot.source_label_ko} · {formatRetrievedAt(snapshot.retrieved_at)} 확인
      </p>
    </div>
  );
}
