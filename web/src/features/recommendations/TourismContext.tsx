import { useEffect, useId, useState } from "react";
import { Link } from "react-router-dom";

import { fetchTourismContext, type ConcentrationForecast, type TourismContext, type TourismPlace } from "../../api/tourism-context";
import { sourceAttribution, type SourceObservation } from "../../api/trip-context";
import { hasConfirmedValue, TripContext, visibleFacilityFacts } from "./TripContext";
import { FACILITY_CHOICES } from "../journey/groundedTrip";

const FACT_LABELS: Record<string, string> = { ...Object.fromEntries(FACILITY_CHOICES.map((choice) => [choice.id, choice.label])),
  toilet_count: "화장실 수", shower_count: "샤워실 수", washing_stand_count: "개수대 수", toilet_available: "화장실",
  caravan_toilet: "카라반 화장실", glamping_toilet: "글램핑 화장실", registered_operating_status: "등록 운영 상태",
  published_operating_days: "안내된 운영 요일", published_operating_seasons: "안내된 운영 계절",
  published_closure_start: "안내된 휴장 시작일", published_closure_end: "안내된 휴장 종료일" };
function valueLabel(fact: SourceObservation) { return fact.value === true ? "있음" : fact.value === false ? "없음" : String(fact.value); }
function safeLink(value: string | null): string | null {
  if (!value) return null;
  try { const url = new URL(value); return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null; } catch { return null; }
}
function SourceLink({ service }: { service: Parameters<typeof sourceAttribution>[0] }) {
  const source = sourceAttribution(service);
  return <a href={source.url} target="_blank" rel="noreferrer">{source.label}</a>;
}
export type TourismState = { kind: "loading" } | { kind: "unavailable" } | { kind: "resolved"; context: TourismContext };
export function useTourismContext(runId: string) {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<{ runId: string; value: TourismState } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setState({ runId, value: { kind: "loading" } });
    // React's development mount replay must not start two seven-source requests.
    const timer = window.setTimeout(() => {
      void fetchTourismContext(runId, { signal: controller.signal }).then((context) => {
        if (!controller.signal.aborted) setState({ runId, value: { kind: "resolved", context } });
      }).catch(() => {
        if (!controller.signal.aborted) setState({ runId, value: { kind: "unavailable" } });
      });
    }, 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [runId, attempt]);
  return { state: state?.runId === runId ? state.value : { kind: "loading" as const }, refresh: () => setAttempt((count) => count + 1) };
}

export function TourismRegionalPanel({ state, onRefresh }: { state: TourismState; onRefresh: () => void }) {
  const heading = useId();
  const context = state.kind === "resolved" ? state.context : null;
  const visitors = (context?.temporal.regional_visitors ?? (context ? [context.temporal.visitors] : []))
    .filter((row) => row.state !== "UNKNOWN")
    .map((row) => ({ ...row, points: row.points.filter((point) => point.state === "AVAILABLE" && point.value !== null) }))
    .filter((row) => row.points.length > 0);
  const demand = (context?.temporal.regional_demand ?? context?.temporal.demand ?? [])
    .filter((row) => row.state === "AVAILABLE" && row.measures.some((measure) =>
      measure.state === "AVAILABLE" && measure.unit === "TOURISM_DEMAND_INDEX" && measure.value !== null));
  const demandRegions = [...new Set(demand.map((row) => row.region_code))].map((code) => demand.filter((row) => row.region_code === code));
  return <section className="recommendation-copy-section tourism-regional-panel" aria-labelledby={heading} data-tourism-context-state={state.kind}>
    <div className="tourism-regional-header">
      <div>
        <h2 id={heading}>방문 날짜와 지역 여행 정보</h2>
        {context && <p className="tourism-note">방문 날짜 {context.temporal.trip_date} · {context.mode === "PINNED" ? "추천 당시 정보" : "새로 조회한 참고 정보"}</p>}
      </div>
      <button className="button button--secondary" type="button" onClick={onRefresh} disabled={state.kind === "loading"}>방문 참고 정보 다시 확인</button>
    </div>
    {state.kind === "loading" && <p className="tourism-note" role="status">공식 여행 정보를 확인하고 있어요.</p>}
    {visitors.map((region) => <details key={region.region_code} className="tourism-regional-details">
      <summary>{region.region_name} 방문자 추이</summary>
      <section className="tourism-info-card" aria-label={`${region.region_name} 방문자 추이`}>
        <p className="tourism-note">{region.period_start} ~ {region.period_end}</p>
        <p className="tourism-note">{region.warning_ko}</p>
        <div className="tourism-table-scroll" role="region" aria-label="날짜별 방문자 추정치" tabIndex={0}>
          <table className="comparison-table">
            <caption>날짜·방문자 구분별 추정치</caption><thead><tr><th>날짜</th><th>구분</th><th>방문 추정치</th></tr></thead>
            <tbody>{region.points.map((point) => <tr key={`${point.measurement_date}:${point.category_code}`}>
              <td>{point.measurement_date}</td><td>{point.category_name}</td><td>{point.value}명 (추정)</td>
            </tr>)}</tbody>
          </table>
        </div>
        <p className="tourism-source"><SourceLink service="DataLabService" />{region.retrieved_at && ` · ${region.retrieved_at.slice(0, 10)} 확인`}</p>
      </section>
    </details>)}
    {demandRegions.map((rows) => <details key={rows[0]!.region_code} className="tourism-regional-details">
      <summary>{rows[0]!.region_name} 관광 수요 지수</summary>
      <section className="tourism-info-card" aria-label={`${rows[0]!.region_name} 관광 수요 지수`}>
        <p className="tourism-note">{rows[0]!.base_month?.replace(/^(\d{4})(\d{2})$/, "$1-$2")} 기준 · {rows[0]!.region_name} 전체</p>
        <dl className="operating-information-list tourism-facts">{rows.map((row) => <div key={row.measure_kind}>
          <dt>{row.measure_kind === "REGIONAL_STAY_INTENSITY" ? "관광 체류 강도" : "관광 소비 강도"}</dt>
          <dd><strong>{row.measures[0]!.value}</strong> 지수</dd>
        </div>)}</dl>
        <p className="tourism-note">{rows[0]!.region_name}의 관광 수요를 다른 시·군·구와 비교한 상대 지수예요. 기준월마다 척도가 달라질 수 있어요.</p>
        <p className="tourism-source"><SourceLink service="AreaTarDemDsService" />{rows[0]!.retrieved_at && ` · ${rows[0]!.retrieved_at.slice(0, 10)} 확인`}</p>
      </section>
    </details>)}
  </section>;
}

export function ForecastPanel({ forecast }: { forecast?: ConcentrationForecast }) {
  if (forecast?.state !== "AVAILABLE" || forecast.value === null) return null;
  return <section className="tourism-info-card" aria-label="방문 집중 예측" data-forecast-state={forecast.state}>
    <h3>방문 집중 예측</h3>
    <p className="tourism-note">{forecast.target_date} 방문 기준</p>
    <p className="tourism-forecast-value"><span>상대 지수</span> <strong>{forecast.value}</strong><span> / 100</span></p>
    {forecast.alternatives.length > 0 && <div className="tourism-alternatives">
      <p>더 낮게 예측된 날짜</p>
      <ul className="tourism-chips">{forecast.alternatives.map((alternative) =>
        <li key={alternative.target_date}>{alternative.target_date} · {alternative.value}</li>)}</ul>
    </div>}
    <p className="tourism-note">{forecast.warning_ko}</p>
    <p className="operating-information-meta">예측 제공 기간 {forecast.window_start} ~ {forecast.window_end}</p>
    <p className="tourism-source"><SourceLink service="TatsCnctrRateService" />{forecast.retrieved_at && ` · ${forecast.retrieved_at.slice(0, 10)} 확인`}</p>
  </section>;
}

export function TourismPlacePanel({ context, placeId, runId, rankedPlaceIds }: {
  context?: TourismContext; placeId: string; runId: string; rankedPlaceIds: string[];
}) {
  const place: TourismPlace | undefined = context?.places.find((place) => place.place_id === placeId);
  const forecast = context?.temporal.forecasts.find((forecast) => forecast.place_id === placeId);
  const hasForecast = forecast?.state === "AVAILABLE" && forecast.value !== null;
  const facilities = visibleFacilityFacts(place?.accessibility);
  const camping = place?.camping.state !== "UNKNOWN" ? place?.camping : undefined;
  const campingFacts = Object.values(camping?.facts ?? {}).filter((fact) => FACT_LABELS[fact.key]
    && hasConfirmedValue(fact));
  const bookingUrl = safeLink(camping?.booking_url ?? null);
  const hasCamping = campingFacts.length > 0 || bookingUrl !== null;
  const courses = place?.walking.state !== "UNKNOWN" ? place?.walking.courses.filter((course) => course.state === "AVAILABLE") ?? [] : [];
  const suggestions = place?.related.state !== "UNKNOWN" ? place?.related.suggestions ?? [] : [];
  const sections = [hasForecast && "방문 예측", facilities.length > 0 && "편의시설", hasCamping && "캠핑장",
    courses.length > 0 && "걷기 코스", suggestions.length > 0 && "연관 장소"].filter(Boolean);
  if (sections.length === 0) return null;
  return <details className="recommendation-copy-section tourism-place-panel" data-tourism-place={placeId}>
    <summary><span>방문 참고 정보</span><span className="tourism-summary-meta">{sections.join(" · ")}</span></summary>
    <div className="tourism-info-grid">
      <ForecastPanel forecast={forecast} />
      <TripContext place={place?.accessibility} loading={false} checkedAt={context?.checked_at} mode={context?.mode} />
      {hasCamping && camping && <section className="tourism-info-card" aria-label="캠핑장 공식 안내">
        <h3>캠핑장 공식 안내</h3>
          {campingFacts.length > 0 && <dl className="operating-information-list tourism-facts">{campingFacts.map((fact) => <div key={fact.key}>
            <dt>{FACT_LABELS[fact.key]}</dt><dd>{valueLabel(fact)}{fact.reference_date && ` · ${fact.reference_date} 기준`}</dd>
          </div>)}</dl>}
          {bookingUrl && <a className="tourism-action-link" href={bookingUrl} target="_blank" rel="noreferrer">공식 예약 안내 확인 ↗</a>}
        <p className="tourism-note">{camping.warning_ko}</p>
        <p className="tourism-source"><SourceLink service="GoCamping" /> · {camping.source_modified_date ?? camping.retrieved_at.slice(0, 10)} 기준</p>
      </section>}
      {suggestions.length > 0 && place && <section className="tourism-info-card" aria-label="함께 둘러볼 장소">
        <h3>함께 둘러볼 장소</h3>
        <ul className="tourism-chips">{suggestions.map((suggestion) => <li key={suggestion.place_id}>
          {rankedPlaceIds.includes(suggestion.place_id) ? <Link to={`/recommendations/${encodeURIComponent(runId)}/places/${encodeURIComponent(suggestion.place_id)}`}>{suggestion.place_name_ko}</Link> : suggestion.place_name_ko}
        </li>)}</ul>
        <p className="tourism-note">{place.related.warning_ko}</p>
        <p className="tourism-source"><SourceLink service="TarRlteTarService1" /> · {place.related.base_month.replace(/^(\d{4})(\d{2})$/, "$1-$2")} 기준</p>
      </section>}
      {courses.length > 0 && place && <section className="tourism-info-card tourism-info-card--courses" aria-label="연결된 걷기 코스">
        <h3>연결된 걷기 코스</h3>
        <ul className="tourism-course-list">{courses.map((course) => <li key={course.course_id}>
          <strong>{course.name_ko}</strong><p className="tourism-note">{course.scope_label_ko}</p>
          <p className="tourism-course-stats">{[course.distance_km !== null && `${course.distance_km}km`,
            course.duration_minutes !== null && `${course.duration_minutes}분`, course.difficulty_label_ko].filter(Boolean).join(" · ")}</p>
          {course.distance_from_place_meters !== null && <p className="tourism-note">장소에서 코스까지 직선거리 약 {Math.round(course.distance_from_place_meters)}m</p>}
          {safeLink(course.gpx_url) && <a className="tourism-action-link" href={safeLink(course.gpx_url)!} target="_blank" rel="noreferrer">공식 코스 경로(GPX) ↗</a>}
          {course.source_modified_date && <p className="operating-information-meta">{course.source_modified_date} 기준</p>}
        </li>)}</ul>
        <p className="tourism-note">{place.walking.warning_ko}</p>
        <p className="tourism-source"><SourceLink service="Durunubi" /></p>
      </section>}
    </div>
  </details>;
}
