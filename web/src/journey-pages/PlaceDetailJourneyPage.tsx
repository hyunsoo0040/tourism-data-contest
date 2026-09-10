import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ApiRequestError,
  RecommendationContractError,
  fetchRecommendationDetail,
  recommendationErrorCode,
  type RecommendationDetail,
  type RecommendationResultsResponse,
} from "../api/api";
import { MismatchGuidance } from "../features/recommendations/MismatchGuidance";
import { RecommendationStatePage, type RecommendationPageState } from "../features/recommendations/RecommendationStatePage";
import { RecommendationStatusBanner } from "../features/recommendations/RecommendationStatusBanner";
import { mediaStateFromImageState, TextFirstMediaState } from "../features/recommendations/TextFirstMediaState";
import { CompareToggle } from "../features/recommendations/CompareToggle";
import { CompareTray } from "../features/recommendations/CompareTray";
import { SaveToggle } from "../features/recommendations/SaveToggle";
import {
  clearCompareSelection,
  hasSavedPlaceReference,
  readCompareSelection,
  readSavedPlaceReferences,
  removeSavedPlaceReference,
  type SavedPlaceReference,
  writeSavedPlaceReference,
  writeCompareSelection,
} from "../app/storage";
import { useJourneyAnnouncements } from "../app/AppShell";
import { clearCurrentRecommendationReferenceIfMatches } from "../features/profile/ProfileRecommendationCTA";
import { OperatingInformation } from "../features/recommendations/OperatingInformation";
import { RecommendationShell } from "../features/recommendations/RecommendationShell";
import { useOperatingInformation } from "../features/recommendations/useOperatingInformation";
import { useTripContext } from "../features/recommendations/useTripContext";
import { TripContext } from "../features/recommendations/TripContext";
import { fetchRecommendationEnvelope, type GroundedResults } from "../api/grounded-recommendation";
import { fetchGroundedDetail, type GroundedDetail } from "../api/grounded-detail";
import { GroundedDetailView } from "../features/recommendations/GroundedRecommendationViews";
import { RECOMMENDATION_ORDER_DESCRIPTION, SIMILARITY_DESCRIPTION, SimilaritySummary, similarityLabel } from "../features/recommendations/PreferenceSimilarity";

type PageState =
  | { kind: "loading" }
  | { kind: "success"; detail: RecommendationDetail; results: RecommendationResultsResponse }
  | { kind: "grounded"; detail: GroundedDetail; results: GroundedResults }
  | { kind: "closed"; state: Exclude<RecommendationPageState, "loading"> };

const AXIS_COPY = {
  HISTORY_TRADITION: { label: "역사·전통", className: "recommendation-axis--history" },
  EMOTION_IMAGE: { label: "감성·이미지", className: "recommendation-axis--emotion" },
  REST_IMMERSION: { label: "휴식·몰입", className: "recommendation-axis--rest" },
} as const;

function formatReferenceDate(value: string) {
  return `${value.replaceAll("-", ".")} 기준`;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isPinnedDetail(
  detail: RecommendationDetail,
  results: RecommendationResultsResponse,
  placeId: string,
) {
  const item = results.run.items.find((candidate) => candidate.place_id === placeId);
  const operating = results.operating_states.find((candidate) => candidate.place_id === placeId);
  const resultIds = new Set(results.run.items.map((candidate) => candidate.place_id));
  return (
    item !== undefined &&
    operating !== undefined &&
    detail.run_id === results.run.run_id &&
    detail.release_sha256 === results.release_disclosure.release_sha256 &&
    detail.release_sha256 === results.release_disclosure.release_sha256 &&
    detail.item.place_id === placeId &&
    stableJson(detail.item) === stableJson(item) &&
    detail.operating_state === operating.state &&
    detail.similar_place_ids.every((similarId) => similarId !== placeId && resultIds.has(similarId))
  );
}

function closedState(error: unknown): Exclude<RecommendationPageState, "loading"> {
  if (error instanceof RecommendationContractError) {
    return error.code === "NO_ACTIVE_SCORED_RELEASE"
      ? "NO_ACTIVE_SCORED_RELEASE"
      : "RECOMMENDATION_PIN_INVALID";
  }
  if (error instanceof ApiRequestError) {
    const code = recommendationErrorCode(error.body);
    if (code === "NO_ACTIVE_SCORED_RELEASE") return code;
    if (code === "RECOMMENDATION_RUN_NOT_FOUND") return code;
    if (code === "RECOMMENDATION_PIN_INVALID") return code;
    if (code === "RECOMMENDATION_PLACE_UNAVAILABLE") return code;
  }
  return "RECOVERABLE_API_FAILURE";
}

export function PlaceDetailPage() {
  const { runId = "", placeId = "" } = useParams();
  const navigate = useNavigate();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<PageState>({ kind: "loading" });
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [compareAnnouncement, setCompareAnnouncement] = useState("");
  const [savedReferences, setSavedReferences] = useState<SavedPlaceReference[]>([]);
  const [saveAnnouncement, setSaveAnnouncement] = useState("");
  const [saveWarning, setSaveWarning] = useState("");
  const announcements = useJourneyAnnouncements();
  const tripContext = useTripContext(runId, state.kind === "success");
  const operatingInformation = useOperatingInformation(
    runId,
    state.kind === "success" ? [placeId] : [],
  );

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: "loading" });
    void fetchRecommendationEnvelope(runId, { signal: controller.signal })
      .then(async (results) => {
        if (controller.signal.aborted) return;
        if (results.schema_version === "itda.grounded-recommendation-results.v1") {
          const detail = await fetchGroundedDetail(results, placeId, { signal: controller.signal });
          if (!controller.signal.aborted) setState({ kind: "grounded", detail, results });
          return;
        }
        const expectedItem = results.run.items.find(
          (candidate) => candidate.place_id === placeId,
        );
        if (expectedItem === undefined) {
          throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
        }
        const detail = await fetchRecommendationDetail(
          runId,
          placeId,
          { signal: controller.signal },
          expectedItem,
        );
        if (controller.signal.aborted) return;
        if (!isPinnedDetail(detail, results, placeId)) {
          throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
        }
        setState({ kind: "success", detail, results });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ kind: "closed", state: closedState(error) });
      });
    return () => controller.abort();
  }, [attempt, placeId, runId]);

  useEffect(() => {
    if (state.kind !== "success") return;
    const frame = requestAnimationFrame(() => headingRef.current?.focus());
    announcements?.announcePage(`${state.detail.item.place_name_ko} 상세 정보를 준비했어요.`);
    return () => cancelAnimationFrame(frame);
  }, [announcements, placeId, state]);

  useEffect(() => {
    if (saveAnnouncement !== "") announcements?.announceInteraction(saveAnnouncement);
  }, [announcements, saveAnnouncement]);

  useEffect(() => {
    if (state.kind !== "success") return;
    const releaseSha256 = state.results.release_disclosure.release_sha256;
    const read = readCompareSelection(runId, releaseSha256);
    const selection = read.selection;
    if (selection === null) {
      setCompareIds([]);
      if ("message" in read) setCompareAnnouncement(read.message);
      return;
    }
    const availableIds = new Set(state.results.run.items.map((candidate) => candidate.place_id));
    if (!selection.place_ids.every((selectedId) => availableIds.has(selectedId))) {
      clearCompareSelection();
      setCompareIds([]);
      setCompareAnnouncement("현재 추천 실행에 없는 비교 선택을 정리했어요.");
      return;
    }
    setCompareIds([...selection.place_ids]);
    if (read.state === "unavailable") setCompareAnnouncement(read.message);
  }, [runId, state]);

  useEffect(() => {
    if (state.kind !== "success") return;
    const read = readSavedPlaceReferences();
    setSavedReferences(read.references);
    setSaveWarning("message" in read ? (read.message ?? "") : "");
  }, [state]);

  if (state.kind === "loading") return <RecommendationStatePage state="loading" />;
  if (state.kind === "closed") {
    const stale =
      state.state === "RECOMMENDATION_RUN_NOT_FOUND" ||
      state.state === "RECOMMENDATION_PIN_INVALID" ||
      state.state === "RECOMMENDATION_PLACE_UNAVAILABLE";
    return (
      <RecommendationStatePage
        state={state.state}
        onPrimary={
          stale
            ? () => {
                clearCurrentRecommendationReferenceIfMatches(runId);
                void navigate("/profile");
              }
            : () => setAttempt((value) => value + 1)
        }
      />
    );
  }

  if (state.kind === "grounded") return <GroundedDetailView key={`${state.results.run.run_id}:${state.detail.item.place_id}`} results={state.results} detail={state.detail} />;

  const { detail, results } = state;
  const item = detail.item;
  const photoExplanation =
    results.run.schema_version === "recommendation-run.v3"
      ? results.run.photo_scores[item.rank - 1]?.explanation_ko
      : undefined;
  const similarById = new Map(results.run.items.map((candidate) => [candidate.place_id, candidate]));
  const selectedPlaces = compareIds.map((selectedId) => {
    const selected = similarById.get(selectedId)!;
    return { placeId: selectedId, placeName: selected.place_name_ko };
  });
  const toggleCompare = (selectedId: string) => {
    const selected = similarById.get(selectedId);
    if (selected === undefined) return;
    const alreadySelected = compareIds.includes(selectedId);
    if (!alreadySelected && compareIds.length >= 3) return;
    const next = alreadySelected
      ? compareIds.filter((candidate) => candidate !== selectedId)
      : [...compareIds, selectedId];
    const write = writeCompareSelection({
      runId,
      releaseSha256: results.release_disclosure.release_sha256,
      placeIds: next,
    });
    setCompareIds(next);
    setCompareAnnouncement(
      alreadySelected
        ? `${selected.place_name_ko}을 비교에서 뺐어요.`
        : `${selected.place_name_ko}을 비교에 추가했어요.`,
    );
    if (write.state === "memory-fallback") setCompareAnnouncement(write.message);
  };
  const toggleSave = (selectedId: string) => {
    if (selectedId !== item.place_id) return;
    const releaseSha256 = results.release_disclosure.release_sha256;
    const selected = hasSavedPlaceReference(savedReferences, selectedId, releaseSha256);
    const result = selected
      ? removeSavedPlaceReference(selectedId, releaseSha256)
      : writeSavedPlaceReference({ placeId: selectedId, releaseSha256 });
    setSavedReferences(result.references);
    if (result.state === "rejected") {
      setSaveAnnouncement("");
      setSaveWarning(result.message);
      return;
    }
    setSaveAnnouncement(
      selected
        ? `${item.place_name_ko}을 저장에서 삭제했어요.`
        : `${item.place_name_ko}을 이 브라우저에 저장했어요.`,
    );
    setSaveWarning(result.state === "memory-fallback" ? result.message : "");
  };
  const saveSelected = hasSavedPlaceReference(
    savedReferences,
    item.place_id,
    results.release_disclosure.release_sha256,
  );
  return (
    <RecommendationShell>
      <article className="recommendations-page place-detail panel" data-place-detail data-status="success">
      <header className="page-intro recommendations-intro">
        <p className="eyebrow">같은 추천 실행의 장소 상세</p>
        <h1 ref={headingRef} tabIndex={-1}>{item.place_name_ko}</h1>
        <p>{item.rank}위</p>
        <SimilaritySummary value={item.contribution.experience_fit_score} />
        <p>{SIMILARITY_DESCRIPTION}</p>
        <p>{RECOMMENDATION_ORDER_DESCRIPTION}</p>
        <Link className="button button--secondary" to={`/recommendations/${encodeURIComponent(runId)}`}>
          추천 5곳으로 돌아가기
        </Link>
        <SaveToggle
          placeId={item.place_id}
          placeName={item.place_name_ko}
          selected={saveSelected}
          onToggle={toggleSave}
        />
        <CompareToggle
          placeId={item.place_id}
          placeName={item.place_name_ko}
          selected={compareIds.includes(item.place_id)}
          disabled={compareIds.length >= 3 && !compareIds.includes(item.place_id)}
          onToggle={toggleCompare}
          maxNoteId="compare-limit-note"
        />
      </header>
      {announcements === null ? (
        <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
          {item.place_name_ko} 상세 정보를 준비했어요.
        </p>
      ) : null}
      {saveWarning === "" ? null : <p className="storage-warning">{saveWarning}</p>}

      <RecommendationStatusBanner disclosure={results.release_disclosure} />
      <TextFirstMediaState state={mediaStateFromImageState(item.image_state)} />
      <TripContext
        place={tripContext.kind === "resolved" ? tripContext.places.get(placeId) : undefined}
        loading={tripContext.kind === "loading" || tripContext.kind === "idle"}
        checkedAt={tripContext.kind === "resolved" ? tripContext.response.checked_at : undefined}
        mode={tripContext.kind === "resolved" ? tripContext.response.mode : undefined}
      />

      <section
        className="place-detail__section place-detail__confidence"
        aria-label="근거 상태"
        data-evidence-confidence-state={detail.evidence_confidence_state}
      >
        <h2>근거 상태</h2>
        <p className="place-detail__confidence-status">
          <strong>
            {detail.evidence_confidence_state === "EVIDENCE_SUPPORTED" ? "근거 충분" : "근거 제한"}
          </strong>
          <span>{detail.evidence_confidence_reason_ko}</span>
        </p>
      </section>

      <section className="place-detail__section" aria-label={`${item.place_name_ko} 내 취향과의 유사도`}>
        <h2>내 취향과의 유사도</h2>
        <div className="recommendation-axes">
          {item.contribution.axis_components.map((axis) => {
            const copy = AXIS_COPY[axis.axis];
            return (
              <div className={`recommendation-axis ${copy.className}`} key={axis.axis}>
                <div className="recommendation-axis__label">
                  <span>{copy.label}</span><span>{similarityLabel(axis.fit_score)}</span>
                </div>
                <div
                  className="axis-meter"
                  role="meter"
                  aria-label={`${copy.label} 취향 유사도 ${similarityLabel(axis.fit_score)}`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={axis.fit_score}
                >
                  <span className="axis-meter__fill" style={{ width: `${axis.fit_score}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="place-detail__section">
        <h2>잘 맞는 이유</h2>
        <div className="recommendation-reason-list">
          {photoExplanation === undefined ? null : (
            <p data-photo-recommendation-explanation>{photoExplanation}</p>
          )}
          {item.explanations.map((reason) => (
            <p key={`${reason.contribution_id}:${reason.evidence_id}`}>{reason.message_ko}</p>
          ))}
        </div>
      </section>

      <MismatchGuidance mismatch={item.mismatch} />

      <section className="place-detail__section" data-operating-state={
        operatingInformation.kind === "resolved"
          ? (operatingInformation.places.get(placeId)?.state ?? detail.operating_state)
          : detail.operating_state
      }>
        <h2>최신 운영 정보</h2>
        <OperatingInformation
          information={
            operatingInformation.kind === "resolved"
              ? operatingInformation.places.get(placeId)
              : undefined
          }
          loading={operatingInformation.kind === "loading"}
        />
      </section>

      <section className="place-detail__section">
        <h2>저장된 근거</h2>
        <div className="place-detail__evidence-list">
          {detail.evidence.map((evidence, index) => (
            <article key={evidence.evidence_id}>
              <h3>저장된 릴리스 근거 {index + 1}</h3>
              <p>{evidence.excerpt_ko}</p>
              <p className="place-detail__meta">
                {evidence.source_label_ko} · {evidence.attribution_ko}
              </p>
              <p className="place-detail__meta">
                {formatReferenceDate(evidence.reference_date)} · 공모전 데모 사용 확인 · 근거 ID{" "}
                {evidence.evidence_id}
              </p>
            </article>
          ))}
        </div>
      </section>

      <section className="place-detail__section">
        <h2>같은 추천 실행의 비슷한 장소</h2>
        {detail.similar_place_ids.length === 0 ? (
          <p>정보 없음 — 같은 실행에서 연결된 장소가 없어요.</p>
        ) : (
          <ul className="place-detail__similar-list" aria-label="같은 추천 실행의 비슷한 장소">
            {detail.similar_place_ids.map((similarId) => {
              const similar = similarById.get(similarId)!;
              return (
                <li key={similarId}>
                  <Link
                    aria-label={`${similar.place_name_ko} 상세 보기`}
                    to={`/recommendations/${encodeURIComponent(runId)}/places/${encodeURIComponent(similarId)}`}
                  >
                    {similar.place_name_ko} · 내 취향과 {similarityLabel(similar.contribution.experience_fit_score)} 유사
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <footer className="place-detail__footer">
        <span>{formatReferenceDate(item.reference_date)}</span>
        <span>이 상세 정보는 현재 포인터가 아니라 위 추천 실행과 릴리스에 고정돼 있어요.</span>
      </footer>
      <CompareTray
        selectedPlaces={selectedPlaces}
        announcement={compareAnnouncement}
        onRemove={toggleCompare}
        onCompare={() => void navigate(`/recommendations/${encodeURIComponent(runId)}/compare`)}
      />
      </article>
    </RecommendationShell>
  );
}
