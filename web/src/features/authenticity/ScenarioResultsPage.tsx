import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "../../app/react-router-dom";
import { RecommendationShell } from "../recommendations/RecommendationShell";
import { PlacePhotos } from "./PlacePhotos";
import { PlaceInformation } from "./PlaceInformation";
import { ResultReason } from "./Journey";
import { api, escapeId, json, type Detail, type Intent, type Run } from "./api";
import { scenarioResultsPath, scenarioRunId } from "./scenario";
import { clearPreparedScenario, readPreparedScenario } from "./preparedScenario";
import { tripChoiceLabel, TRIP_FIELD_LABELS } from "../../content/journey.ko";
import "./scenario.css";

const AXES = { H: { label: "대상•원형형", color: "history" }, E: { label: "의미•이미지형", color: "emotion" }, R: { label: "자기•몰입형", color: "rest" } };
const errorMessage = (reason: unknown) => reason instanceof Error ? reason.message : "추천을 불러오지 못했어요. 다시 시도해 주세요.";

function ScenarioPlace({ item, runId, saved, saving, compared, compareFull, onSave, onCompare, preparedDetail, failedPhotoUrls, preparedImages }: {
  item: Run["items"][number]; runId: string; saved: boolean; saving: boolean; compared: boolean; compareFull: boolean;
  onSave: () => void; onCompare: () => void;
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
  return <article className="recommendation-card" data-recommendation-card data-scenario-place={item.place_id} data-details-loaded={Boolean(detail)}>
    <header className="recommendation-card__header"><h2>{item.rank}위 {item.name_ko}</h2><strong className="scenario-match">내 선호와 {item.score}% 연결</strong></header>
    <p className="recommendation-location">{item.region_name} · {item.category}</p>
    <div className="scenario-place-media"><PlacePhotos name={item.name_ko} photos={detail?.photos ?? []} loading={!detail && !error} unavailable={Boolean(error)} preparedImages={preparedImages} failedUrls={failedPhotoUrls} />
      {detail ? <PlaceInformation detail={detail} /> : error ? <div role="status"><p>이 장소의 사진과 정보를 불러오지 못했어요. 추천 결과는 유지됩니다.</p><button className="control" onClick={() => setAttempt(value => value + 1)}>{item.name_ko} 정보 다시 불러오기</button></div> : <p role="status">장소 정보를 불러오고 있어요.</p>}
    </div>
    <section className="recommendation-axes" aria-label={`${item.name_ko} 장소의 경험 특성`}><h3>장소의 경험 특성</h3>
      {(["H", "E", "R"] as const).map(axis => { const score = item.axes[axis]; const copy = AXES[axis]; return <div className={`recommendation-axis recommendation-axis--${copy.color}`} key={axis}>
        <div className="recommendation-axis__label"><span>{copy.label}</span><span>{score === null ? "미확인" : `${score}점`}</span></div>
        {score !== null && <div className="axis-meter" role="meter" aria-label={`${copy.label} 장소 특성 ${score}점`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={score}><span className="axis-meter__fill" style={{ width: `${score}%` }} /></div>}
      </div>; })}
    </section>
    <section className="recommendation-copy-section"><h3>잘 맞는 이유</h3>{detail && <ResultReason detail={detail} />}
      <p>상황형 답변에서 나타난 경험 비중과, 근거가 확인된 장소 특성을 비교했어요.</p>
    </section>
    <section className="recommendation-copy-section"><h3>확인할 점</h3><p>{item.warnings.length ? "일부 경험이나 사진 분위기는 비교할 근거가 부족해요. 확인 가능한 항목으로 계산했습니다." : "확인된 자료 범위에서 계산한 값이며, 방문 만족도나 당일 운영을 보장하지 않아요."}</p></section>
    <div className="recommendation-card__actions">
      <Link className="button button--secondary" to={href}>{item.name_ko} 상세 보기</Link>
      <button className="button button--secondary" aria-pressed={saved} disabled={saving} onClick={onSave}>{item.name_ko} {saved ? "저장됨" : "저장"}</button>
      <button className="button button--secondary" aria-pressed={compared} disabled={compareFull && !compared} onClick={onCompare}>{item.name_ko} {compared ? "비교에서 빼기" : "비교에 추가"}</button>
    </div>
  </article>;
}

export function ScenarioResultsPage() {
  const params = useParams(); const runId = scenarioRunId(params.runId);
  return <ScenarioResults key={runId} runId={runId} />;
}

function ScenarioResults({ runId }: { runId: string | null }) {
  const [prepared] = useState(() => readPreparedScenario(runId));
  const [run, setRun] = useState<Run | null>(prepared?.run ?? null), [profile, setProfile] = useState<Intent | null>(prepared?.profile ?? null);
  const [saved, setSaved] = useState<string[]>(prepared?.saved ?? []), [compare, setCompare] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null), [actionError, setActionError] = useState<string | null>(prepared?.savedError ?? null), [attempt, setAttempt] = useState(0);
  const [saving, setSaving] = useState<string[]>([]);
  const saveRequests = useRef(new Map<string, AbortController>());
  useEffect(() => {
    if (prepared && attempt === 0) {
      clearPreparedScenario(prepared);
      return () => { saveRequests.current.forEach(request => request.abort()); saveRequests.current.clear(); };
    }
    const controller = new AbortController(); setRun(null); setProfile(null); setError(null); setSaved([]); setCompare([]); setSaving([]);
    if (!runId) { setError("추천 주소를 확인해 주세요."); return; }
    api<Run>(`/runs/${escapeId(runId)}`, { signal: controller.signal }).then(async value => {
      if (controller.signal.aborted) return; setRun(value);
      const intent = await api<Intent>(`/profiles/${escapeId(value.profile_id)}`, { signal: controller.signal });
      if (!controller.signal.aborted) setProfile(intent);
    }).catch(reason => { if (!controller.signal.aborted) setError(errorMessage(reason)); });
    api<{ run_sha256: string; place_id: string }[]>("/saved", { signal: controller.signal })
      .then(rows => { if (!controller.signal.aborted) setSaved(rows.filter(row => row.run_sha256 === runId).map(row => row.place_id)); })
      .catch(() => { if (!controller.signal.aborted) setActionError("저장한 장소 목록을 불러오지 못했어요. 다시 불러오면 확인할 수 있어요."); });
    return () => { controller.abort(); saveRequests.current.forEach(request => request.abort()); saveRequests.current.clear(); };
  }, [runId, attempt, prepared]);
  async function save(placeId: string) {
    if (saveRequests.current.has(placeId)) return;
    const controller = new AbortController(); saveRequests.current.set(placeId, controller);
    setSaving(value => [...value, placeId]); setActionError(null);
    try { await api(`/runs/${escapeId(runId!)}/places/${escapeId(placeId)}/saved`, { method: "PUT", body: json({ saved: !saved.includes(placeId) }), signal: controller.signal }); if (!controller.signal.aborted) setSaved(value => value.includes(placeId) ? value.filter(id => id !== placeId) : [...value, placeId]); }
    catch (reason) { if (!controller.signal.aborted) setActionError(errorMessage(reason)); }
    finally { if (saveRequests.current.get(placeId) === controller) { saveRequests.current.delete(placeId); setSaving(value => value.filter(id => id !== placeId)); } }
  }
  const scenario = profile?.submission && "trip_conditions" in profile.submission ? profile.submission : null;
  return <RecommendationShell><article className="recommendations-page panel" data-status="success">
    <header className="page-intro recommendations-intro"><h1>이번 여행에 맞는 {run?.result_count ?? ""}{run ? "곳" : "장소"}</h1>
      <p>상황형 답변의 세 가지 경험 비중을 최신 관광지 분석과 비교했어요.</p>
      <div className="inline-actions"><Link className="button button--secondary" to="/profile">취향 결과 확인</Link><Link className="button button--secondary" to="/start?mode=edit">여행 지역·방문 조건 수정</Link><Link className="button button--secondary" to="/saved">저장한 장소</Link></div>
    </header>
    {(error || actionError) && <section role="alert"><p>{error ?? actionError}</p><button className="control" onClick={() => { setActionError(null); setAttempt(value => value + 1); }}>다시 불러오기</button></section>}
    {!run && !error && <p role="status">최신 분석으로 추천한 장소를 불러오고 있어요.</p>}
    {scenario && <details className="recommendation-copy-section"><summary>내 답변과 추천의 연결 방식</summary>
      <p>기존 상황형 채점표의 축별 점수를 합계 100%의 상대 비중으로 변환했습니다. 장소의 H·E·R 점수는 각각 독립적인 0~100점입니다. 세부 항목의 강도나 회피 여부를 답한 것으로 간주하지 않습니다.</p>
      <p>{(["H", "E", "R"] as const).map(axis => `${AXES[axis].label} ${profile!.axis_importance[axis]}%`).join(" · ")}</p>
      <p>{scenario.visual_input_kind === "CONFIRMED_PHOTO" ? "경험 비중 80%와 직접 확정한 사진 분위기 20%를 비교하며, 미확인 항목의 비중은 확인된 항목에 재배분합니다." : "사진 입력 없이 경험 비중으로 계산했습니다."} 주요 선호 축이 미확인이거나 비교 근거가 절반 미만인 장소는 제외합니다.</p>
      <p>방문 날짜 {scenario.trip_conditions.visit_date ?? "미정"}{scenario.exact_visit_time ? ` · ${scenario.exact_visit_time}` : ""}</p>
      <p>{Object.keys(TRIP_FIELD_LABELS).map(key => tripChoiceLabel(key as keyof typeof TRIP_FIELD_LABELS, scenario.trip_conditions[key as keyof typeof TRIP_FIELD_LABELS])).join(" · ")}</p>
      <p>지역·필수 시설은 추천 조건으로 적용했습니다. 나머지 방문 계획은 보관한 참고 정보이며 당일 운영·날씨·혼잡도는 확인하지 않았습니다.</p>
      <p>변환 규칙: {scenario.schema_version} · 추천 규칙: {run?.ranking_version}</p>
    </details>}
    {run?.state === "EMPTY" && <section className="profile-state"><h2>이 조건에 맞는 여행지가 아직 충분하지 않아요.</h2><p>지역이나 필수 시설을 조정해 주세요. 근거가 없는 장소로 결과를 채우지 않아요.</p><Link to="/start?mode=edit">여행 조건 수정</Link></section>}
    {run?.state === "LIMITED" && <p role="status">조건과 근거를 확인한 {run.result_count}곳을 찾았어요.</p>}
    <section id="recommendation-list" className="recommendation-list" aria-label="추천 장소">{run?.items.map(item => <ScenarioPlace key={`${runId}:${item.place_id}`} item={item} runId={runId!} preparedDetail={attempt === 0 ? prepared?.details[item.place_id] : undefined} preparedImages={attempt === 0 ? prepared?.images[item.place_id] : undefined} failedPhotoUrls={prepared?.failedPhotoUrls} saved={saved.includes(item.place_id)} saving={saving.includes(item.place_id)} compared={compare.includes(item.place_id)} compareFull={compare.length >= 3} onSave={() => save(item.place_id)} onCompare={() => setCompare(value => value.includes(item.place_id) ? value.filter(id => id !== item.place_id) : value.length < 3 ? [...value, item.place_id] : value)} />)}</section>
    {compare.length > 0 && <aside className="scenario-compare-tray" aria-label="장소 비교"><span>{compare.length}/3곳 선택</span><Link className="button button--primary" to={`${scenarioResultsPath(runId!)}/compare?places=${encodeURIComponent(compare.join(","))}`}>선택한 장소 비교하기</Link></aside>}
  </article></RecommendationShell>;
}
