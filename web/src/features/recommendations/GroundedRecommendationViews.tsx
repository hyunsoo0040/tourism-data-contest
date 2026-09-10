import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import type { GroundedFitTrace, GroundedItem, GroundedResults } from "../../api/grounded-recommendation";
import type { GroundedDetail } from "../../api/grounded-detail";
import { MOOD_LABELS } from "../../api/grounded-core";
import { sourceAttribution } from "../../api/trip-context";
import { hasSavedPlaceReference, readCompareSelection, readSavedPlaceReferences, removeSavedPlaceReference,
  writeCompareSelection, writeSavedPlaceReference, type SavedPlaceReference } from "../../app/storage";
import { useJourneyAnnouncements } from "../../app/AppShell";
import { RecommendationShell } from "./RecommendationShell";
import { CompareTray } from "./CompareTray";
import { CompareToggle } from "./CompareToggle";
import { SaveToggle } from "./SaveToggle";
import { SavedSection } from "./SavedSection";
import { TourismPlacePanel, TourismRegionalPanel, useTourismContext, type TourismState } from "./TourismContext";
import { RECOMMENDATION_ORDER_DESCRIPTION, SIMILARITY_DESCRIPTION, SimilaritySummary, similarityLabel } from "./PreferenceSimilarity";
import { travelRegionName, useTravelRegions } from "../../api/recommendation-regions";

const AXES = { H: { label: "역사·전통", className: "recommendation-axis--history" }, E: { label: "감성·이미지", className: "recommendation-axis--emotion" }, R: { label: "휴식·몰입", className: "recommendation-axis--rest" } };
const TRAITS: Record<string, string> = { M1: "공간 성격", M2: "방문객 성격", M3: "현장 밀도", M4: "경험 방식", M5: "체류 방식", M6: "시간 의존성" };
const SUBATTRIBUTES: Record<string, string> = { H1: "역사 이야기", H2: "문화유산·원형", H3: "전통의 지속성", H4: "학습·해설",
  E1: "시각적 상징성", E2: "사진·경관 매력", E3: "현대적 재해석", E4: "분위기·감각 경험",
  R1: "자연·회복 환경", R2: "산책·체류", R3: "정적·저자극", R4: "참여·몰입" };
function dimensionSimilarity(trace: GroundedFitTrace, key: string): string {
  const component = trace.components.find((row) => row.key === key);
  return component?.exclusion_reason === "USER_UNSPECIFIED" ? "선택하지 않은 항목" : similarityLabel(component?.fit ?? null);
}

function PlaceLocation({ item, address = false }: { item: GroundedItem; address?: boolean }) {
  const location = address ? item.address_ko ?? item.region_name : item.region_name ?? item.address_ko;
  return location ? <p className="recommendation-location" data-place-region={item.region_code ?? undefined}>{location}</p> : null;
}

function useGroundedActions(results: GroundedResults) {
  const run = results.run, release = run.authority.candidate_sha256;
  const [references, setReferences] = useState(() => readSavedPlaceReferences().references);
  const [compareIds, setCompareIds] = useState(() => readCompareSelection(run.run_id, release).selection?.place_ids
    .filter((id) => run.items.some((item) => item.place_id === id)) ?? []);
  const [message, setMessage] = useState("");
  const toggleSave = (placeId: string) => {
    const selected = hasSavedPlaceReference(references, placeId, release);
    const outcome = selected ? removeSavedPlaceReference(placeId, release) : writeSavedPlaceReference({ placeId, releaseSha256: release });
    setReferences(outcome.references);
    setMessage(outcome.state === "rejected" || outcome.state === "memory-fallback" ? outcome.message : selected ? "저장한 장소에서 삭제했어요." : "이 브라우저에 장소를 저장했어요.");
  };
  const toggleCompare = (placeId: string) => {
    const selected = compareIds.includes(placeId);
    if (!selected && compareIds.length >= 3) return;
    const next = selected ? compareIds.filter((id) => id !== placeId) : [...compareIds, placeId];
    const outcome = writeCompareSelection({ runId: run.run_id, releaseSha256: release, placeIds: next });
    setCompareIds(next);
    setMessage(outcome.state === "memory-fallback" ? outcome.message : selected ? "비교에서 뺐어요." : "비교에 추가했어요.");
  };
  const removeSaved = (reference: SavedPlaceReference) => { const outcome = removeSavedPlaceReference(reference.place_id, reference.release_sha256); setReferences(outcome.references); };
  return { references, compareIds, message, toggleSave, toggleCompare, removeSaved };
}
type Actions = ReturnType<typeof useGroundedActions>;

function GroundedIntro({ results, title }: { results: GroundedResults; title: string }) {
  const heading = useRef<HTMLHeadingElement>(null), announcements = useJourneyAnnouncements();
  const travelRegions = useTravelRegions(results.run.preference.trip_input.region_code != null);
  useEffect(() => { heading.current?.focus(); announcements?.announcePage(title); }, [title, announcements]);
  return <header className="page-intro recommendations-intro">
    <p className="eyebrow">확인된 근거로 고른 나의 여행</p>
    <h1 ref={heading} tabIndex={-1}>{title}</h1>
    <p>{SIMILARITY_DESCRIPTION}</p>
    <p className="recommendation-guidance-note">{RECOMMENDATION_ORDER_DESCRIPTION}</p>
    <p className="recommendation-selected-region">{travelRegionName(results.run.preference.trip_input.region_code, travelRegions.regions)}에서 고른 여행지</p>
    <p>{results.run.preference.trip_input.visit_date ? `방문 날짜 ${results.run.preference.trip_input.visit_date}` : "방문 날짜 미정"}
      {results.run.preference.trip_input.visit_time ? ` · ${results.run.preference.trip_input.visit_time}` : ""}</p>
    <Link className="button button--secondary" to="/start?mode=edit">여행 지역·방문 조건 수정</Link>
  </header>;
}

export function GroundedAxes({ item }: { item: GroundedItem }) {
  return <section className="recommendation-axes" aria-label={`${item.place_name_ko} 경험별 취향 유사도`}>
    <h3 className="recommendation-similarity-title">경험별 취향 유사도</h3>
    {item.axis_scores.map((axis) => {
      const copy = AXES[axis.key as keyof typeof AXES];
      const similarity = item.contribution.experience.components.find((component) => component.key === axis.key)?.fit ?? null;
      return <div className={`recommendation-axis ${copy.className}`} key={axis.key} data-supported-axis={axis.key}>
        <div className="recommendation-axis__label"><span>{copy.label}</span><span>{similarityLabel(similarity)}</span></div>
        {similarity !== null ? <div className="axis-meter" role="meter" aria-label={`${copy.label} 취향 유사도 ${similarity}%`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={similarity} aria-valuetext={`내 취향과 ${similarity}% 유사`}>
          <span className="axis-meter__fill" style={{ width: `${similarity}%` }} />
        </div> : <p className="recommendation-guidance-note">내 취향과 비교할 근거가 부족해요.</p>}
      </div>;
    })}
  </section>;
}

function GroundedMismatch({ item }: { item: GroundedItem }) {
  const copy = item.mismatch.message_ko ?? (item.mismatch.state === "NO_GUIDANCE" ? "확인된 근거 범위에서 기대와 큰 차이가 없어요."
    : item.mismatch.state === "SUPPRESSED_LOW_CONFIDENCE" ? "근거가 충분하지 않아 기대 차이 안내를 생략했어요." : "기대 차이를 비교할 근거가 부족해요.");
  return <section className="recommendation-copy-section" data-mismatch-state={item.mismatch.state}>
    <h3>기대와 다른 점</h3><p>{copy}</p>
  </section>;
}

function SourceEvidenceList({ item }: { item: GroundedItem }) {
  return <details className="recommendation-copy-section"><summary>추천에 사용한 근거 확인</summary>
    {item.evidence.map((evidence) => {
      const source = sourceAttribution(evidence.receipt.service);
      return <article key={evidence.evidence_id}>
        <p>{evidence.quote}</p><p><a href={source.url} target="_blank" rel="noreferrer">{source.label}</a>
          {" · "}{evidence.receipt.reference_date ?? evidence.receipt.retrieved_at.slice(0, 10)} 기준</p>
      </article>;
    })}
  </details>;
}

function ItemActions({ item, results, actions, detailLink = true }: { item: GroundedItem; results: GroundedResults; actions: Actions; detailLink?: boolean }) {
  return <div className="recommendation-card__actions">
    {detailLink && <Link className="button button--secondary" aria-label={`${item.place_name_ko} 상세 보기`}
      to={`/recommendations/${encodeURIComponent(results.run.run_id)}/places/${encodeURIComponent(item.place_id)}`}>상세 보기</Link>}
    <SaveToggle placeId={item.place_id} placeName={item.place_name_ko}
      selected={hasSavedPlaceReference(actions.references, item.place_id, results.run.authority.candidate_sha256)} onToggle={actions.toggleSave} />
    <CompareToggle placeId={item.place_id} placeName={item.place_name_ko} selected={actions.compareIds.includes(item.place_id)}
      disabled={actions.compareIds.length >= 3 && !actions.compareIds.includes(item.place_id)} onToggle={actions.toggleCompare} maxNoteId="compare-limit-note" />
  </div>;
}
function GroundedCompareTray({ results, actions }: { results: GroundedResults; actions: Actions }) {
  const navigate = useNavigate();
  return <CompareTray selectedPlaces={actions.compareIds.map((id) => {
    const item = results.run.items.find((item) => item.place_id === id)!;
    return { placeId: id, placeName: item.place_name_ko, regionName: item.region_name };
  })}
    announcement={actions.message} onRemove={actions.toggleCompare} onCompare={() => void navigate(`/recommendations/${encodeURIComponent(results.run.run_id)}/compare`)} />;
}

function GroundedCard({ item, results, actions, tourism }: { item: GroundedItem; results: GroundedResults; actions: Actions; tourism: TourismState }) {
  return <article className="recommendation-card" data-recommendation-card data-rank={item.rank} data-grounded-item={item.place_id}>
    <header className="recommendation-card__header"><h2>{item.rank}위 {item.place_name_ko}</h2><SimilaritySummary value={item.contribution.experience.score} /></header>
    <PlaceLocation item={item} />
    <p className="recommendation-guidance-note">세 가지 경험 중 {item.supported_axes}가지를 비교했어요.</p>
    <GroundedAxes item={item} />
    <section className="recommendation-copy-section"><h3>잘 맞는 이유</h3>{item.explanations.map((explanation) => <p key={explanation.dimension}>{explanation.message_ko}</p>)}</section>
    {item.contribution.mood.score !== null ? <p data-mood-fit>내 사진 분위기와 {item.contribution.mood.score}% 유사해요.</p> :
      results.run.preference.photo_input_sha256 !== null && <p>비교할 사진 분위기 근거가 부족해 경험과 여행 조건으로 추천했어요.</p>}
    <GroundedMismatch item={item} />
    <SourceEvidenceList item={item} />
    <TourismPlacePanel context={tourism.kind === "resolved" ? tourism.context : undefined} placeId={item.place_id} runId={results.run.run_id} rankedPlaceIds={results.run.items.map((item) => item.place_id)} />
    <footer className="recommendation-card__footer">{item.reference_date ? `${item.reference_date} 근거 기준` : "근거 기준일 미확인"}</footer>
    <ItemActions item={item} results={results} actions={actions} />
  </article>;
}

export function GroundedResultsView({ results }: { results: GroundedResults }) {
  const actions = useGroundedActions(results), tourism = useTourismContext(results.run.run_id);
  return <RecommendationShell><article className="recommendations-page panel" data-status="success" data-grounded-run={results.run.run_id}>
    <GroundedIntro results={results} title="이번 여행에 맞는 5곳" />
    <SavedSection references={actions.references} onRemove={actions.removeSaved} />
    <TourismRegionalPanel state={tourism.state} onRefresh={tourism.refresh} />
    <ol className="recommendation-list" aria-label="추천 5곳" id="recommendation-list">{results.run.items.map((item) => <li key={item.place_id}>
      <GroundedCard item={item} results={results} actions={actions} tourism={tourism.state} />
    </li>)}</ol>
    <GroundedCompareTray results={results} actions={actions} />
  </article></RecommendationShell>;
}

export function GroundedDetailView({ results, detail }: { results: GroundedResults; detail: GroundedDetail }) {
  const actions = useGroundedActions(results), tourism = useTourismContext(results.run.run_id), item = detail.item;
  return <RecommendationShell><article className="recommendations-page place-detail panel" data-grounded-detail={item.place_id}>
    <GroundedIntro results={results} title={item.place_name_ko} />
    <PlaceLocation item={item} address />
    <Link to={`/recommendations/${encodeURIComponent(results.run.run_id)}`}>추천 5곳으로 돌아가기</Link>
    <SimilaritySummary value={item.contribution.experience.score} />
    <p className="recommendation-guidance-note">세 가지 경험 중 {item.supported_axes}가지를 비교했어요.</p>
    <ItemActions item={item} results={results} actions={actions} detailLink={false} />
    <GroundedAxes item={item} />
    <section className="place-detail__section"><h2>이런 경험을 만날 수 있어요</h2>
      <dl className="operating-information-list">{Object.entries(SUBATTRIBUTES).map(([key, label]) => {
        const row = detail.assessment.dimensions[key]!;
        return row.state === "UNKNOWN" ? null : <div key={key}><dt>{label}</dt><dd>{row.reason}</dd></div>;
      })}</dl>
    </section>
    <section className="place-detail__section"><h2>여행 방식 유사도</h2><p>내가 선택한 여행 방식과 장소 특성을 비교했어요.</p><dl className="operating-information-list">{item.mismatch_traits.map((trait) => <div key={trait.key} data-grounded-trait={trait.key}>
      <dt>{TRAITS[trait.key]}</dt><dd>{dimensionSimilarity(item.contribution.traits, trait.key)}<p>{trait.reason}</p></dd>
    </div>)}</dl></section>
    <GroundedMismatch item={item} /><SourceEvidenceList item={item} />
    <section className="place-detail__section" aria-label="사진에서 확인한 분위기"><h2>사진에서 확인한 분위기</h2>
      <p>{detail.mood.limit_ko}</p>
      {detail.mood.images.length === 0 ? <p>분위기를 확인한 사진이 없어요.</p> : detail.mood.strata.map((stratum) => <div key={`${stratum.season}:${stratum.light_context}`}>
        <h3>{{ SPRING: "봄", SUMMER: "여름", AUTUMN: "가을", WINTER: "겨울", UNKNOWN: "계절 미확인" }[stratum.season]} · {{ DAY: "낮", NIGHT: "밤", UNKNOWN: "촬영 시간 미확인" }[stratum.light_context]}</h3>
        <dl>{stratum.moods.filter((mood) => mood.value !== null).map((mood) => <div key={mood.dimension}><dt>{MOOD_LABELS[mood.dimension]}</dt><dd>{mood.value === 0 ? "사진에서 두드러지지 않아요" : "사진에서 확인한 분위기예요"}</dd></div>)}</dl>
      </div>)}
      {detail.mood.images.map((image) => <p key={image.asset_id}>{image.attribution_ko} · {image.capture_date ?? image.capture_month ?? "촬영일 미확인"}</p>)}
      <p>사진은 외관·빛·색의 인상에만 사용해요. 혼잡이나 운영·시설 정보의 근거로 사용하지 않아요.</p>
    </section>
    <TourismRegionalPanel state={tourism.state} onRefresh={tourism.refresh} />
    <TourismPlacePanel context={tourism.state.kind === "resolved" ? tourism.state.context : undefined} placeId={item.place_id} runId={results.run.run_id} rankedPlaceIds={results.run.items.map((item) => item.place_id)} />
    <GroundedCompareTray results={results} actions={actions} />
  </article></RecommendationShell>;
}

export function GroundedComparisonView({ results, details }: { results: GroundedResults; details: GroundedDetail[] }) {
  const tourism = useTourismContext(results.run.run_id);
  return <RecommendationShell><article className="recommendations-page compare-page panel" data-grounded-comparison>
    <GroundedIntro results={results} title="선택한 장소 비교" />
    <Link to={`/recommendations/${encodeURIComponent(results.run.run_id)}`}>추천 5곳으로 돌아가기</Link>
    <p>각 장소가 내 취향과 얼마나 가까운지 나란히 확인해요.</p>
    <p id="grounded-comparison-instruction">표를 좌우로 이동해 모든 장소를 확인할 수 있어요.</p>
    <div className="comparison-table-region" role="region" aria-label="장소 비교표" aria-describedby="grounded-comparison-instruction" tabIndex={0}><table className="comparison-table"
      style={{ tableLayout: "fixed", width: "100%", minWidth: 144 + details.length * 180 }}>
      <colgroup><col style={{ width: 144 }} />{details.map((detail) => <col key={detail.item.place_id} style={{ width: 180 }} />)}</colgroup>
      <caption>선택한 장소와 내 취향의 유사도</caption><thead><tr><th scope="col">비교 항목</th>{details.map((detail) => <th scope="col" key={detail.item.place_id}>{detail.item.place_name_ko}<PlaceLocation item={detail.item} /></th>)}</tr></thead>
      <tbody><tr><th scope="row">내 취향과의 유사도</th>{details.map((detail) => <td key={detail.item.place_id}>{similarityLabel(detail.item.contribution.experience.score)}</td>)}</tr>
        {Object.entries(AXES).map(([key, copy]) => <tr key={key}><th scope="row">{copy.label} 유사도</th>{details.map((detail) => <td key={detail.item.place_id}>{dimensionSimilarity(detail.item.contribution.experience, key)}</td>)}</tr>)}
        {Object.entries(TRAITS).map(([key, label]) => <tr key={key}><th scope="row">{label} 유사도</th>{details.map((detail) => <td key={detail.item.place_id}>{dimensionSimilarity(detail.item.contribution.traits, key)}</td>)}</tr>)}
      </tbody>
    </table></div>
    <TourismRegionalPanel state={tourism.state} onRefresh={tourism.refresh} />
    {details.map((detail) => <section key={detail.item.place_id}><h2>{detail.item.place_name_ko}</h2><PlaceLocation item={detail.item} /><GroundedMismatch item={detail.item} />
      <TourismPlacePanel context={tourism.state.kind === "resolved" ? tourism.state.context : undefined} placeId={detail.item.place_id} runId={results.run.run_id} rankedPlaceIds={results.run.items.map((item) => item.place_id)} />
    </section>)}
  </article></RecommendationShell>;
}
