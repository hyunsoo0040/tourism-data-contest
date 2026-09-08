import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ApiRequestError,
  fetchRecommendationComparison,
  fetchRecommendationResults,
  recommendationErrorCode,
  type ComparisonRow,
  type RecommendationResultsResponse,
} from "../api/api";
import {
  clearCompareSelection,
  readCompareSelectionForRun,
} from "../app/storage";
import { ComparisonTable } from "../features/recommendations/ComparisonTable";
import { RecommendationStatusBanner } from "../features/recommendations/RecommendationStatusBanner";
import { RecommendationStatePage } from "../features/recommendations/RecommendationStatePage";
import { useJourneyAnnouncements } from "../app/AppShell";
import { clearCurrentRecommendationReferenceIfMatches } from "../features/profile/ProfileRecommendationCTA";
import { RecommendationShell } from "../features/recommendations/RecommendationShell";
import { useOperatingInformation } from "../features/recommendations/useOperatingInformation";

type TerminalCompareState = "RECOMMENDATION_RUN_NOT_FOUND" | "RECOMMENDATION_PIN_INVALID";

function terminalCompareState(error: unknown): TerminalCompareState | null {
  if (!(error instanceof ApiRequestError)) return null;
  const code = recommendationErrorCode(error.body);
  return code === "RECOMMENDATION_RUN_NOT_FOUND" || code === "RECOMMENDATION_PIN_INVALID"
    ? code
    : null;
}

type CompareState =
  | { kind: "loading" }
  | { kind: "invalid"; message: string }
  | { kind: "terminal"; state: TerminalCompareState }
  | { kind: "error" }
  | {
      kind: "success";
      results: RecommendationResultsResponse;
      rows: ComparisonRow[];
      placeIds: string[];
      placeNames: string[];
    };

export function ComparePage() {
  const { runId = "" } = useParams();
  const navigate = useNavigate();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<CompareState>({ kind: "loading" });
  const announcements = useJourneyAnnouncements();
  const operatingInformation = useOperatingInformation(
    runId,
    state.kind === "success" ? state.placeIds : [],
  );

  useEffect(() => {
    const prepared = readCompareSelectionForRun(runId);
    const selection = prepared.selection;
    if (selection === null || selection.place_ids.length < 2 || selection.place_ids.length > 3) {
      setState({
        kind: "invalid",
        message:
          "message" in prepared
            ? prepared.message
            : "같은 추천 실행에서 장소 2~3곳을 다시 선택해 주세요.",
      });
      return;
    }

    const controller = new AbortController();
    setState({ kind: "loading" });
    void fetchRecommendationResults(runId, { signal: controller.signal })
      .then(async (results) => {
        if (controller.signal.aborted) return;
        const selectedIds = selection.place_ids;
        const itemsById = new Map(results.run.items.map((item) => [item.place_id, item]));
        if (
          selection.release_sha256 !== results.release_disclosure.release_sha256 ||
          !selectedIds.every((placeId) => itemsById.has(placeId))
        ) {
          clearCompareSelection();
          setState({
            kind: "invalid",
            message: "같은 추천 실행에서 장소 2~3곳을 다시 선택해 주세요.",
          });
          return;
        }
        const rows = await fetchRecommendationComparison(
          runId,
          results.release_disclosure.release_sha256,
          selectedIds,
          {
            signal: controller.signal,
          },
        );
        if (controller.signal.aborted) return;
        setState({
          kind: "success",
          results,
          rows,
          placeIds: [...selectedIds],
          placeNames: selectedIds.map((placeId) => itemsById.get(placeId)!.place_name_ko),
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        const terminal = terminalCompareState(error);
        if (terminal !== null) {
          clearCompareSelection();
          setState({ kind: "terminal", state: terminal });
          return;
        }
        setState({ kind: "error" });
      });
    return () => controller.abort();
  }, [attempt, runId]);

  useEffect(() => {
    if (state.kind === "loading") return;
    const frame = requestAnimationFrame(() => headingRef.current?.focus());
    if (state.kind === "success") announcements?.announcePage("선택한 장소 비교를 준비했어요.");
    return () => cancelAnimationFrame(frame);
  }, [announcements, state.kind]);

  if (state.kind === "loading") {
    return <RecommendationStatePage state="loading" />;
  }

  if (state.kind === "invalid") {
    return (
      <RecommendationStatePage
        state="COMPARE_SELECTION_INVALID"
        primaryHref={`/recommendations/${encodeURIComponent(runId)}`}
        statusMessage={
          state.message === "같은 추천 실행에서 장소 2~3곳을 다시 선택해 주세요."
            ? ""
            : state.message
        }
      />
    );
  }

  if (state.kind === "terminal") {
    return (
      <RecommendationStatePage
        state={state.state}
        onPrimary={() => {
          clearCurrentRecommendationReferenceIfMatches(runId);
          void navigate("/profile");
        }}
      />
    );
  }

  if (state.kind === "error") {
    return (
      <RecommendationStatePage
        state="COMPARE_API_FAILURE"
        onPrimary={() => setAttempt((value) => value + 1)}
      />
    );
  }

  const photoRun =
    state.results.run.schema_version === "recommendation-run.v3" &&
    "photo_scores" in state.results.run
      ? state.results.run
      : null;
  const photoExplanations =
    photoRun === null
      ? []
      : state.placeIds.map((placeId, selectedIndex) => {
          const itemIndex = photoRun.items.findIndex((item) => item.place_id === placeId);
          return {
            placeId,
            placeName: state.placeNames[selectedIndex]!,
            explanation: photoRun.photo_scores[itemIndex]!.explanation_ko,
          };
        });

  return (
    <RecommendationShell>
      <article className="recommendations-page compare-page panel" data-status="success">
      <header className="page-intro recommendations-intro">
        <p className="eyebrow">같은 추천 실행의 장소 비교</p>
        <h1 ref={headingRef} tabIndex={-1}>선택한 장소 비교</h1>
        <p>저장된 결과를 바꾸거나 다시 계산하지 않고 나란히 확인해요.</p>
        <Link className="button button--secondary" to={`/recommendations/${encodeURIComponent(runId)}`}>
          추천 5곳으로 돌아가기
        </Link>
      </header>
      <RecommendationStatusBanner disclosure={state.results.release_disclosure} />
      {photoExplanations.length === 0 ? null : (
        <section
          className="recommendation-copy-section"
          aria-labelledby="photo-comparison-heading"
        >
          <h2 id="photo-comparison-heading">사진 취향 반영 이유</h2>
          <div className="recommendation-reason-list">
            {photoExplanations.map((row) => (
              <p key={row.placeId} data-photo-recommendation-explanation>
                <strong>{row.placeName}</strong> — {row.explanation}
              </p>
            ))}
          </div>
        </section>
      )}
      <ComparisonTable
        placeNames={state.placeNames}
        rows={state.rows}
        placeIds={state.placeIds}
        operatingInformation={operatingInformation}
      />
      </article>
    </RecommendationShell>
  );
}
