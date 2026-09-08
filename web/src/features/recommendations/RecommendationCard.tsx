import { Link } from "react-router-dom";

import type {
  PlaceOperatingInformation,
  RecommendationResultsResponse,
} from "../../api/api";
import { OperatingInformation } from "./OperatingInformation";
import { MismatchGuidance } from "./MismatchGuidance";
import { mediaStateFromImageState, TextFirstMediaState } from "./TextFirstMediaState";
import { CompareToggle } from "./CompareToggle";
import { SaveToggle } from "./SaveToggle";

type RecommendationItem = RecommendationResultsResponse["run"]["items"][number];
type OperatingState = RecommendationResultsResponse["operating_states"][number]["state"];
type EvidenceConfidenceState = RecommendationItem["evidence_confidence_state"];

const CONFIDENCE_LABEL: Record<EvidenceConfidenceState, string> = {
  EVIDENCE_AUDIT_ONLY: "참고 정보",
  EVIDENCE_LIMITED_MISMATCH_SUPPRESSED: "근거 제한",
  EVIDENCE_LIMITED_MISMATCH_AVAILABLE: "근거 제한",
  EVIDENCE_SUPPORTED: "근거 충분",
};

const AXIS_COPY = {
  HISTORY_TRADITION: { label: "역사·전통", className: "recommendation-axis--history" },
  EMOTION_IMAGE: { label: "감성·이미지", className: "recommendation-axis--emotion" },
  REST_IMMERSION: { label: "휴식·몰입", className: "recommendation-axis--rest" },
} as const;

function formatReferenceDate(value: string) {
  return `${value.replaceAll("-", ".")} 기준`;
}

export function RecommendationCard({
  item,
  operatingState,
  operatingInformation,
  operatingInformationLoading = false,
  runId,
  analysisOrigin,
  photoExplanation,
  compareSelected = false,
  compareDisabled = false,
  onCompareToggle,
  saveSelected = false,
  onSaveToggle,
}: {
  item: RecommendationItem;
  operatingState: OperatingState;
  operatingInformation?: PlaceOperatingInformation;
  operatingInformationLoading?: boolean;
  runId: string;
  analysisOrigin: RecommendationResultsResponse["analysis_origin"];
  photoExplanation?: string;
  compareSelected?: boolean;
  compareDisabled?: boolean;
  onCompareToggle?: (placeId: string) => void;
  saveSelected?: boolean;
  onSaveToggle?: (placeId: string) => void;
}) {
  const mediaState = mediaStateFromImageState(item.image_state);
  return (
    <article
      className="recommendation-card"
      data-recommendation-card
      data-rank={item.rank}
      data-evidence-confidence-state={item.evidence_confidence_state}
    >
      <header className="recommendation-card__header">
        <div>
          <p className="recommendation-rank">{item.rank}위</p>
          <h2>{item.rank}위 {item.place_name_ko}</h2>
        </div>
        <p className="recommendation-fit">적합도 {item.fit_score}점 / 100점</p>
      </header>

      <div
        className="recommendation-status-row"
        aria-label="추천 상태"
        data-analysis-origin={analysisOrigin}
      >
        <span>
          분석 출처: {
            analysisOrigin === "GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED"
              ? "GLM 공개 근거 모델"
              : "데모 모델"
          }
        </span>
        <span data-media-state={mediaState}>미디어 상태: {
          mediaState === "IMAGE_MISSING"
            ? "대표 이미지 없음"
            : mediaState === "IMAGE_RIGHTS_RESTRICTED"
              ? "이미지 표시 제한"
              : "검증된 대표 이미지"
        }</span>
        <span data-operating-state={operatingState}>
          운영 상태: {operatingInformation?.state === "AVAILABLE" ? "공식 정보 확인" : "미확인"}
        </span>
        <span
          className="recommendation-confidence-status"
          data-evidence-confidence-state={item.evidence_confidence_state}
          aria-label={`근거 상태: ${CONFIDENCE_LABEL[item.evidence_confidence_state]}`}
        >
          <span className="recommendation-confidence-status__label">
            {CONFIDENCE_LABEL[item.evidence_confidence_state]}
          </span>
          <span>{item.evidence_confidence_reason_ko}</span>
        </span>
      </div>

      <TextFirstMediaState state={mediaState} />

      <section className="recommendation-axes" aria-label={`${item.place_name_ko} 경험 점수`}>
        {item.axis_scores.map((axis) => {
          const copy = AXIS_COPY[axis.axis];
          return (
            <div className={`recommendation-axis ${copy.className}`} key={axis.axis}>
              <div className="recommendation-axis__label">
                <span>{copy.label}</span>
                <span>{axis.value}점</span>
              </div>
              <div
                className="axis-meter"
                role="meter"
                aria-label={`${copy.label} ${axis.value}점 / 100점`}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={axis.value}
              >
                <span className="axis-meter__fill" style={{ width: `${axis.value}%` }} />
              </div>
            </div>
          );
        })}
      </section>

      <section className="recommendation-copy-section">
        <p className="recommendation-copy-section__title">잘 맞는 이유</p>
        <div className="recommendation-reason-list">
          {photoExplanation === undefined ? null : (
            <p data-photo-recommendation-explanation>{photoExplanation}</p>
          )}
          {item.explanations.map((reason) => (
            <p key={`${reason.contribution_id}:${reason.evidence_id}`}>
              {reason.message_ko}
            </p>
          ))}
        </div>
      </section>

      <MismatchGuidance mismatch={item.mismatch} />

      <section className="recommendation-copy-section recommendation-operating-summary">
        <p className="recommendation-copy-section__title">최신 운영 정보</p>
        <OperatingInformation
          information={operatingInformation}
          loading={operatingInformationLoading}
          compact
        />
      </section>

      <footer className="recommendation-card__footer">
        <span>{formatReferenceDate(item.reference_date)}</span>
      </footer>
      <div className="recommendation-card__actions">
        <Link
          aria-label={`${item.place_name_ko} 상세 보기`}
          className="button button--secondary"
          to={`/recommendations/${encodeURIComponent(runId)}/places/${encodeURIComponent(item.place_id)}`}
        >
          상세 보기
        </Link>
        {onSaveToggle === undefined ? null : (
          <SaveToggle
            placeId={item.place_id}
            placeName={item.place_name_ko}
            selected={saveSelected}
            onToggle={onSaveToggle}
          />
        )}
        {onCompareToggle === undefined ? null : (
          <CompareToggle
            placeId={item.place_id}
            placeName={item.place_name_ko}
            selected={compareSelected}
            disabled={compareDisabled}
            onToggle={onCompareToggle}
            maxNoteId="compare-limit-note"
          />
        )}
      </div>
    </article>
  );
}
