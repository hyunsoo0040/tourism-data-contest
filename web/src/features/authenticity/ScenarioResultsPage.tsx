import { useEffect, useState } from "react";
import { Link, useParams } from "../../app/react-router-dom";
import { RecommendationShell } from "../recommendations/RecommendationShell";
import { PlacePhotos } from "./PlacePhotos";
import { PlaceInformation } from "./PlaceInformation";
import { ResultReason } from "./Journey";
import { api, escapeId, type Detail, type Run } from "./api";
import { scenarioResultsPath, scenarioRunId } from "./scenario";
import { clearPreparedScenario, readPreparedScenario } from "./preparedScenario";
import { kakaoMapSearchUrl } from "./placeMetadata";
import "./scenario.css";

const AXES = { H: { label: "대상•원형형", color: "history" }, E: { label: "의미•이미지형", color: "emotion" }, R: { label: "자기•몰입형", color: "rest" } };
const errorMessage = (reason: unknown) => reason instanceof Error ? reason.message : "추천을 불러오지 못했어요. 다시 시도해 주세요.";

function ScenarioPlace({ item, runId, preparedDetail, failedPhotoUrls, preparedImages }: {
  item: Run["items"][number]; runId: string;
  preparedDetail?: Detail; failedPhotoUrls?: string[];
  preparedImages?: Readonly<Record<string, HTMLImageElement>>;
}) {
  const [detail, setDetail] = useState<Detail | null>(preparedDetail ?? null), [error, setError] = useState<string | null>(null), [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (preparedDetail && attempt === 0) return;
    const controller = new AbortController(); setDetail(null); setError(null);
    api<Detail>(`/runs/${escapeId(runId)}/places/${escapeId(item.place_id)}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setDetail(value); })
      .catch(reason => { if (!controller.signal.aborted) setError(errorMessage(reason)); });
    return () => controller.abort();
  }, [runId, item.place_id, attempt, preparedDetail]);
  const href = `${scenarioResultsPath(runId)}/places/${escapeId(item.place_id)}`;
  const mapUrl = kakaoMapSearchUrl(item.name_ko, detail?.address ?? item.region_name);
  const visibleAxes = (["H", "E", "R"] as const).flatMap(axis => {
    const score = item.axes[axis];
    return score == null ? [] : [{ axis, score }];
  });
  return <article className="recommendation-card" data-recommendation-card data-scenario-place={item.place_id} data-details-loaded={Boolean(detail)}>
    <header className="recommendation-card__header"><h2>{item.rank}위 {item.name_ko}</h2><strong className="scenario-match">내 선호와 {item.score}% 연결</strong></header>
    <p className="recommendation-location">{item.region_name} · {item.category}</p>
    <div className="scenario-place-media"><PlacePhotos name={item.name_ko} photos={detail?.photos ?? []} loading={!detail && !error} unavailable={Boolean(error)} preparedImages={preparedImages} failedUrls={failedPhotoUrls} />
      {detail ? <PlaceInformation detail={detail} /> : error ? <div role="status"><p>이 장소의 사진과 정보를 불러오지 못했어요. 추천 결과는 유지됩니다.</p><button className="control" onClick={() => setAttempt(value => value + 1)}>{item.name_ko} 정보 다시 불러오기</button></div> : <p role="status">장소 정보를 불러오고 있어요.</p>}
    </div>
    {visibleAxes.length > 0 && <section className="recommendation-axes" aria-label={`${item.name_ko} 장소의 경험 특성`}><h3>장소의 경험 특성</h3>
      {visibleAxes.map(({ axis, score }) => { const copy = AXES[axis]; return <div className={`recommendation-axis recommendation-axis--${copy.color}`} key={axis}>
        <div className="recommendation-axis__label"><span>{copy.label}</span><span>{score}점</span></div>
        <div className="axis-meter" role="meter" aria-label={`${copy.label} 장소 특성 ${score}점`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}><span className="axis-meter__fill" style={{ width: `${score}%` }} /></div>
      </div>; })}
    </section>}
    <section className="recommendation-copy-section"><h3>잘 맞는 이유</h3>{detail && <ResultReason detail={detail} />}
    </section>
    <div className="recommendation-card__actions">
      <Link className="button button--secondary" to={href}>상세 보기</Link>
      <a className="button button--secondary" href={mapUrl} target="_blank" rel="noreferrer">지도에서 보기</a>
    </div>
  </article>;
}

export function ScenarioResultsPage() {
  const params = useParams(); const runId = scenarioRunId(params.runId);
  return <ScenarioResults key={runId} runId={runId} />;
}

function ScenarioResults({ runId }: { runId: string | null }) {
  const [prepared] = useState(() => readPreparedScenario(runId));
  const [run, setRun] = useState<Run | null>(prepared?.run ?? null);
  const [error, setError] = useState<string | null>(null), [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (prepared && attempt === 0) { clearPreparedScenario(prepared); return; }
    const controller = new AbortController(); setRun(null); setError(null);
    if (!runId) { setError("추천 주소를 확인해 주세요."); return; }
    api<Run>(`/runs/${escapeId(runId)}`, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) setRun(value);
    }).catch(reason => { if (!controller.signal.aborted) setError(errorMessage(reason)); });
    return () => controller.abort();
  }, [runId, attempt, prepared]);
  return <RecommendationShell><article className="recommendations-page panel" data-status="success">
    <header className="page-intro recommendations-intro"><h1>이번 여행에 맞는 {run?.result_count ?? ""}{run ? "곳" : "장소"}</h1>
      <p>상황형 답변의 세 가지 경험 비중을 최신 관광지 분석과 비교했어요.</p>
    </header>
    {error && <section role="alert"><p>{error}</p><button className="control" onClick={() => { setAttempt(value => value + 1); }}>다시 불러오기</button></section>}
    {!run && !error && <p role="status">최신 분석으로 추천한 장소를 불러오고 있어요.</p>}
    {run?.state === "EMPTY" && <section className="profile-state"><h2>이 조건에 맞는 여행지가 아직 충분하지 않아요.</h2><p>지역이나 필수 시설을 조정해 주세요. 근거가 없는 장소로 결과를 채우지 않아요.</p><Link to="/start?mode=edit">여행 조건 수정</Link></section>}
    {run?.state === "LIMITED" && <p role="status">조건과 근거를 확인한 {run.result_count}곳을 찾았어요.</p>}
    <section id="recommendation-list" className="recommendation-list" aria-label="추천 장소">{run?.items.map(item => <ScenarioPlace key={`${runId}:${item.place_id}`} item={item} runId={runId!} preparedDetail={attempt === 0 ? prepared?.details[item.place_id] : undefined} preparedImages={attempt === 0 ? prepared?.images[item.place_id] : undefined} failedPhotoUrls={prepared?.failedPhotoUrls} />)}</section>
  </article></RecommendationShell>;
}
