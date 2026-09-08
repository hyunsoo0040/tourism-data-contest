import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import {
  ApiRequestError,
  RecommendationContractError,
  fetchRecommendationResults,
  recommendationErrorCode,
  type RecommendationResultsResponse,
} from "../api/api";
import { RecommendationCard } from "../features/recommendations/RecommendationCard";
import { RecommendationStatusBanner } from "../features/recommendations/RecommendationStatusBanner";
import {
  RecommendationStatePage,
  type RecommendationPageState,
} from "../features/recommendations/RecommendationStatePage";
import { CompareTray } from "../features/recommendations/CompareTray";
import { SavedSection } from "../features/recommendations/SavedSection";
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
import { PhotoRecommendationProvenance } from "../features/photo/PhotoRecommendationProvenance";
import { RecommendationShell } from "../features/recommendations/RecommendationShell";
import { useOperatingInformation } from "../features/recommendations/useOperatingInformation";

type PageState =
  | { kind: "loading" }
  | { kind: "success"; results: RecommendationResultsResponse }
  | { kind: "closed"; state: Exclude<RecommendationPageState, "loading"> };

function closedState(error: unknown): Exclude<RecommendationPageState, "loading"> {
  if (error instanceof RecommendationContractError) {
    return error.code === "NO_ACTIVE_SCORED_RELEASE"
      ? "NO_ACTIVE_SCORED_RELEASE"
      : "RECOVERABLE_API_FAILURE";
  }
  if (error instanceof ApiRequestError) {
    const code = recommendationErrorCode(error.body);
    if (code === "NO_ACTIVE_SCORED_RELEASE") return code;
    if (code === "INSUFFICIENT_ELIGIBLE_CANDIDATES") return code;
    if (code === "RECOMMENDATION_RUN_NOT_FOUND") return code;
    if (code === "RECOMMENDATION_PIN_INVALID") return code;
  }
  return "RECOVERABLE_API_FAILURE";
}

export function RecommendationsPage() {
  const { runId = "" } = useParams();
  const navigate = useNavigate();
  const [state, setState] = useState<PageState>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [compareAnnouncement, setCompareAnnouncement] = useState("");
  const [savedReferences, setSavedReferences] = useState<SavedPlaceReference[]>([]);
  const [saveAnnouncement, setSaveAnnouncement] = useState("");
  const [saveWarning, setSaveWarning] = useState("");
  const [saveCleanupNotice, setSaveCleanupNotice] = useState("");
  const announcements = useJourneyAnnouncements();
  const operatingInformation = useOperatingInformation(
    runId,
    state.kind === "success"
      ? state.results.run.items.map((item) => item.place_id)
      : [],
  );

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: "loading" });
    void fetchRecommendationResults(runId, { signal: controller.signal })
      .then((results) => {
        if (!controller.signal.aborted) setState({ kind: "success", results });
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setState({ kind: "closed", state: closedState(error) });
        }
      });
    return () => controller.abort();
  }, [attempt, runId]);

  useEffect(() => {
    if (state.kind !== "success") return;
    const frame = requestAnimationFrame(() => headingRef.current?.focus());
    announcements?.announcePage("추천 5곳을 준비했어요.");
    return () => cancelAnimationFrame(frame);
  }, [announcements, state.kind]);

  useEffect(() => {
    if (saveAnnouncement !== "") announcements?.announceInteraction(saveAnnouncement);
  }, [announcements, saveAnnouncement]);

  useEffect(() => {
    if (state.kind !== "success") return;
    const read = readCompareSelection(runId, state.results.release_disclosure.release_sha256);
    const selection = read.selection;
    if (selection === null) {
      setCompareIds([]);
      if ("message" in read) setCompareAnnouncement(read.message);
      return;
    }
    const availableIds = new Set(state.results.run.items.map((item) => item.place_id));
    if (!selection.place_ids.every((placeId) => availableIds.has(placeId))) {
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
    setSaveCleanupNotice(
      read.state === "cleaned" && read.reason === "corrupt" ? (read.message ?? "") : "",
    );
    setSaveWarning(read.state === "unavailable" ? read.message : "");
  }, [state]);

  if (state.kind === "loading") {
    return <RecommendationStatePage state="loading" />;
  }

  if (state.kind === "closed") {
    return (
      <RecommendationStatePage
        state={state.state}
        onPrimary={
          state.state === "RECOMMENDATION_RUN_NOT_FOUND" ||
          state.state === "RECOMMENDATION_PIN_INVALID"
            ? () => {
                clearCurrentRecommendationReferenceIfMatches(runId);
                void navigate("/profile");
              }
            : () => setAttempt((value) => value + 1)
        }
      />
    );
  }

  const operatingByPlace = new Map(
    state.results.operating_states.map((row) => [row.place_id, row.state]),
  );
  const photoRun =
    state.results.run.schema_version === "recommendation-run.v3" &&
    "photo_scores" in state.results.run
      ? state.results.run
      : null;
  const photoConfirmed = photoRun !== null;
  const photoExplanationByPlace = new Map(
    photoRun === null
      ? []
      : photoRun.items.map((item, index) => [
          item.place_id,
          photoRun.photo_scores[index]!.explanation_ko,
        ]),
  );
  const itemById = new Map(state.results.run.items.map((item) => [item.place_id, item]));
  const selectedPlaces = compareIds.map((placeId) => ({
    placeId,
    placeName: itemById.get(placeId)!.place_name_ko,
  }));
  const toggleCompare = (placeId: string) => {
    const item = itemById.get(placeId);
    if (item === undefined) return;
    const selected = compareIds.includes(placeId);
    if (!selected && compareIds.length >= 3) return;
    const next = selected
      ? compareIds.filter((candidate) => candidate !== placeId)
      : [...compareIds, placeId];
    const write = writeCompareSelection({
      runId,
      releaseSha256: state.results.release_disclosure.release_sha256,
      placeIds: next,
    });
    setCompareIds(next);
    setCompareAnnouncement(
      selected
        ? `${item.place_name_ko}을 비교에서 뺐어요.`
        : `${item.place_name_ko}을 비교에 추가했어요.`,
    );
    if (write.state === "memory-fallback") setCompareAnnouncement(write.message);
  };
  const toggleSave = (placeId: string) => {
    const item = itemById.get(placeId);
    if (item === undefined) return;
    const releaseSha256 = state.results.release_disclosure.release_sha256;
    const selected = hasSavedPlaceReference(savedReferences, placeId, releaseSha256);
    const result = selected
      ? removeSavedPlaceReference(placeId, releaseSha256)
      : writeSavedPlaceReference({ placeId, releaseSha256 });
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
  const removeSaved = (reference: SavedPlaceReference) => {
    const result = removeSavedPlaceReference(
      reference.place_id,
      reference.release_sha256,
    );
    setSavedReferences(result.references);
    setSaveWarning(result.state === "memory-fallback" ? result.message : "");
  };
  return (
    <RecommendationShell>
      <article className="recommendations-page panel" data-status="success">
      <header className="page-intro recommendations-intro">
        <p className="eyebrow">
          {photoConfirmed ? "사진 취향을 반영한 경주 여행지" : "사진 없이 고른 경주 여행지"}
        </p>
        <h1 ref={headingRef} tabIndex={-1}>이번 경주에 맞는 5곳</h1>
        <p>확인한 이번 여행의 기대 프로필과 저장된 장소 근거를 연결한 결과예요.</p>
      </header>
      {announcements === null ? (
        <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
          추천 5곳을 준비했어요.
        </p>
      ) : null}
      {saveWarning === "" ? null : <p className="storage-warning">{saveWarning}</p>}
      <RecommendationStatusBanner disclosure={state.results.release_disclosure} />
      <PhotoRecommendationProvenance
        provenance={photoConfirmed ? "CONFIRMED_PHOTO" : "NO_PHOTO"}
      />
      <SavedSection
        references={savedReferences}
        cleanupNotice={saveCleanupNotice}
        onRemove={removeSaved}
      />
      <ol className="recommendation-list" aria-label="추천 5곳" id="recommendation-list">
        {state.results.run.items.map((item) => (
          <li key={item.place_id}>
            <RecommendationCard
              item={item}
              operatingState={operatingByPlace.get(item.place_id)!}
              operatingInformation={
                operatingInformation.kind === "resolved"
                  ? operatingInformation.places.get(item.place_id)
                  : undefined
              }
              operatingInformationLoading={operatingInformation.kind === "loading"}
              runId={runId}
              analysisOrigin={state.results.analysis_origin}
              photoExplanation={photoExplanationByPlace.get(item.place_id)}
              compareSelected={compareIds.includes(item.place_id)}
              compareDisabled={compareIds.length >= 3 && !compareIds.includes(item.place_id)}
              onCompareToggle={toggleCompare}
              saveSelected={hasSavedPlaceReference(
                savedReferences,
                item.place_id,
                state.results.release_disclosure.release_sha256,
              )}
              onSaveToggle={toggleSave}
            />
          </li>
        ))}
      </ol>
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
