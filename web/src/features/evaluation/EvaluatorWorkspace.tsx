import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";
import { createPortal } from "react-dom";

import {
  EvaluatorApiError,
  createEvaluatorClient,
  type EvaluatorCorrection,
  type EvaluatorEvidence,
  type EvaluatorPrimaryAxis,
  type EvaluatorSubmission,
  type EvaluatorUnknownReason,
  type StoredLabelRevision,
} from "./api";
import { useModalFocus } from "./useModalFocus";

type RubricSpec = {
  attribute_id: string;
  axis: string;
  label_ko: string;
  examples_ko: string[];
  counterexamples_ko: string[];
};

type EvidenceItem = Omit<EvaluatorEvidence, "complete_context" | "supports_absence"> & {
  complete_context?: boolean;
  sentence_text_ko?: string;
  supports_absence?: boolean;
};

const SCORE_LABELS = [
  "0, 확인된 부재",
  "1, 약함",
  "2, 보통",
  "3, 강함",
  "4, 지배적",
] as const;

const RUBRIC_SPECS: RubricSpec[] = [
  { attribute_id: "H1", axis: "역사·전통", label_ko: "역사 서사 밀도", examples_ko: ["시대와 유래를 직접 설명한다"], counterexamples_ko: ["유래 설명 없이 시설만 나열한다"] },
  { attribute_id: "H2", axis: "역사·전통", label_ko: "문화유산·원형 기반성", examples_ko: ["보존 흔적이 경험의 중심이다"], counterexamples_ko: ["원형과 무관한 임시 장식뿐이다"] },
  { attribute_id: "H3", axis: "역사·전통", label_ko: "전통의 지속성", examples_ko: ["전통생활이 현재 경험과 이어진다"], counterexamples_ko: ["현재와의 연결 근거가 없다"] },
  { attribute_id: "H4", axis: "역사·전통", label_ko: "학습·해설 깊이", examples_ko: ["해설과 교육 탐색이 구체적이다"], counterexamples_ko: ["학습 가능한 설명이 없다"] },
  { attribute_id: "I1", axis: "감성·이미지", label_ko: "시각적 상징성", examples_ko: ["기억되는 형태가 직접 묘사된다"], counterexamples_ko: ["구별되는 장면 근거가 없다"] },
  { attribute_id: "I2", axis: "감성·이미지", label_ko: "사진·경관 매력", examples_ko: ["경관의 구도와 계절감이 설명된다"], counterexamples_ko: ["경관 정보가 전혀 없다"] },
  { attribute_id: "I3", axis: "감성·이미지", label_ko: "현대적 재해석", examples_ko: ["전통 요소를 현재 방식으로 잇는다"], counterexamples_ko: ["재해석 근거가 없다"] },
  { attribute_id: "I4", axis: "감성·이미지", label_ko: "분위기·감각 경험", examples_ko: ["빛과 공간 분위기가 구체적이다"], counterexamples_ko: ["감각 경험 설명이 없다"] },
  { attribute_id: "R1", axis: "휴식·몰입", label_ko: "자연·회복 환경", examples_ko: ["회복을 돕는 자연 요소가 있다"], counterexamples_ko: ["자연 요소를 확인할 수 없다"] },
  { attribute_id: "R2", axis: "휴식·몰입", label_ko: "산책·체류 적합성", examples_ko: ["천천히 걷고 머무는 동선이 있다"], counterexamples_ko: ["체류 가능성을 뒷받침하지 않는다"] },
  { attribute_id: "R3", axis: "휴식·몰입", label_ko: "정적·저자극 가능성", examples_ko: ["조용히 머무를 수 있다고 설명한다"], counterexamples_ko: ["정적 환경 근거가 없다"] },
  { attribute_id: "R4", axis: "휴식·몰입", label_ko: "참여·몰입 경험", examples_ko: ["탐방과 이야기 몰입이 연결된다"], counterexamples_ko: ["참여 또는 몰입 근거가 없다"] },
];

type RuntimeSource = {
  source_id: string;
  lane: "DESCRIPTION" | "ODII";
  text_ko: string;
};

type RuntimeFixture = {
  synthetic_only: true;
  assignment: {
    assignment_id: string;
    rubric_version: string;
    source_snapshot_version: string;
  };
  sources: RuntimeSource[];
};

type JudgmentDraft = {
  score: number | null;
  unknownSelected: boolean;
  reason: EvaluatorUnknownReason | null;
  note: string;
  selectedEvidenceIds: string[];
};

function emptyDrafts(): Record<string, JudgmentDraft> {
  return Object.fromEntries(
    RUBRIC_SPECS.map((spec) => [
      spec.attribute_id,
      { score: null, unknownSelected: false, reason: null, note: "", selectedEvidenceIds: [] },
    ]),
  );
}

function isRuntimeFixture(value: unknown): value is RuntimeFixture {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const root = value as Record<string, unknown>;
  if (root.synthetic_only !== true || typeof root.assignment !== "object" || root.assignment === null) return false;
  const assignment = root.assignment as Record<string, unknown>;
  if (
    typeof assignment.assignment_id !== "string" ||
    typeof assignment.rubric_version !== "string" ||
    typeof assignment.source_snapshot_version !== "string" ||
    !Array.isArray(root.sources)
  ) {
    return false;
  }
  return root.sources.every(
    (source) =>
      typeof source === "object" &&
      source !== null &&
      !Array.isArray(source) &&
      typeof (source as Record<string, unknown>).source_id === "string" &&
      ["DESCRIPTION", "ODII"].includes(String((source as Record<string, unknown>).lane)) &&
      typeof (source as Record<string, unknown>).text_ko === "string",
  );
}

function evidenceForSources(sources: RuntimeSource[]): EvidenceItem[] {
  const description = sources.find((source) => source.lane === "DESCRIPTION");
  const odii = sources.find((source) => source.lane === "ODII");
  const descriptionId = description?.source_id ?? "synthetic-runtime-description-alpha";
  const odiiId = odii?.source_id ?? "synthetic-runtime-odii-alpha";
  return [
    { evidence_id: "synthetic-desc-direct-a", source_id: descriptionId, lane: "DESCRIPTION", dedup_cluster_id: "synthetic-cluster-a", direct: true, concordance_key: "synthetic-theme-a", sentence_text_ko: description?.text_ko, supports_absence: true, complete_context: true },
    { evidence_id: "synthetic-desc-direct-a-copy", source_id: descriptionId, lane: "DESCRIPTION", dedup_cluster_id: "synthetic-cluster-a", direct: true, concordance_key: "synthetic-theme-a", sentence_text_ko: description?.text_ko },
    { evidence_id: "synthetic-desc-direct-b", source_id: descriptionId, lane: "DESCRIPTION", dedup_cluster_id: "synthetic-cluster-b", direct: true, concordance_key: "synthetic-theme-b", sentence_text_ko: description?.text_ko },
    { evidence_id: "synthetic-odii-direct-a", source_id: odiiId, lane: "ODII", dedup_cluster_id: "synthetic-cluster-c", direct: true, concordance_key: "synthetic-theme-a", sentence_text_ko: odii?.text_ko },
    { evidence_id: "synthetic-odii-discordant", source_id: odiiId, lane: "ODII", dedup_cluster_id: "synthetic-cluster-d", direct: true, concordance_key: "synthetic-theme-z", sentence_text_ko: odii?.text_ko },
  ];
}

export function InternalRoleShell({
  actorLabel,
  accessState,
  clearRoleState,
  onExit,
  children,
}: {
  actorLabel: string;
  accessState: "AUTHORIZED" | "FORBIDDEN";
  clearRoleState: () => void;
  onExit?: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (accessState === "FORBIDDEN") clearRoleState();
  }, [accessState, clearRoleState]);

  if (accessState === "FORBIDDEN") {
    return (
      <main className="evaluator-shell evaluator-shell--forbidden">
        <h1 tabIndex={-1}>이 역할은 이 자료를 볼 수 없습니다.</h1>
        <p>권한이 바뀌어 이전 평가 내용과 브라우저 상태를 모두 지웠습니다.</p>
      </main>
    );
  }

  return (
    <main className="evaluator-shell" data-evaluator-scope="isolated">
      <InternalRoleHeader
        onExit={onExit === undefined ? undefined : () => {
          clearRoleState();
          onExit();
        }}
        roleLabel={actorLabel}
      />
      {children}
    </main>
  );
}

export function InternalRoleHeader({
  roleLabel,
  onExit,
}: {
  roleLabel: string;
  onExit?: () => void;
}) {
  return (
    <header className="internal-role-header">
      <p className="internal-role-header__wordmark">IT-DA 내부 증거 원장</p>
      <div>
        <p className="evaluator-actor" aria-label="현재 내부 역할">
          {roleLabel}
        </p>
        {onExit ? (
          <button className="button button--secondary" onClick={onExit} type="button">
            역할 화면 종료
          </button>
        ) : null}
      </div>
    </header>
  );
}

export function RubricAnchorPanel() {
  return (
    <aside className="rubric-anchor-panel" aria-labelledby="rubric-anchor-title">
      <h2 id="rubric-anchor-title">공통 0–4 판단 기준</h2>
      <ol>
        {SCORE_LABELS.map((label) => (
          <li key={label}>{label}</li>
        ))}
      </ol>
      <p>
        4점은 한 매체 안의 서로 다른 직접 근거 묶음 두 개 이상, 또는 설명과 Odii에서
        의미가 일치하는 직접 근거가 모두 있을 때만 선택합니다.
      </p>
    </aside>
  );
}

export function AttributeScoreField({
  spec,
  score,
  unknownSelected,
  onScoreChange,
  onUnknownChange,
  children,
}: {
  spec: RubricSpec;
  score: number | null;
  unknownSelected: boolean;
  onScoreChange: (value: number | null, trigger?: HTMLInputElement) => void;
  onUnknownChange: (selected: boolean) => void;
  children?: ReactNode;
}) {
  const name = `score-${spec.attribute_id}`;
  return (
    <fieldset className="attribute-score-field" data-attribute-id={spec.attribute_id}>
      <legend>{spec.label_ko}</legend>
      <p className="attribute-score-field__axis">{spec.axis}</p>
      <div className="rubric-guidance">
        <p>
          <strong>예:</strong> {spec.examples_ko.join(" · ")}
        </p>
        <p>
          <strong>반례:</strong> {spec.counterexamples_ko.join(" · ")}
        </p>
      </div>
      <div className="score-options">
        {SCORE_LABELS.map((label, value) => (
          <label className="score-option" key={label}>
            <input
              checked={!unknownSelected && score === value}
              name={name}
              onChange={(event) => onScoreChange(value, event.currentTarget)}
              type="radio"
            />
            <span>{label}</span>
          </label>
        ))}
        <label className="score-option score-option--unknown">
          <input
            checked={unknownSelected}
            name={name}
            onChange={() => {
              onScoreChange(null);
              onUnknownChange(true);
            }}
            type="radio"
          />
          <span>판단 불가</span>
        </label>
      </div>
      {children}
    </fieldset>
  );
}

export function UnknownReasonFields({
  reason,
  note,
  showErrors,
  onReasonChange,
  onNoteChange,
}: {
  reason: string | null;
  note: string;
  showErrors: boolean;
  onReasonChange: (value: string) => void;
  onNoteChange: (value: string) => void;
}) {
  const trimmedLength = note.trim().length;
  const invalid = showErrors && (reason === null || trimmedLength < 1 || note.length > 300 || note !== note.trim());
  return (
    <div className="unknown-fields">
      <label>
        <span>판단 불가 사유</span>
        <select value={reason ?? ""} onChange={(event) => onReasonChange(event.target.value)}>
          <option value="">사유를 선택하세요</option>
          <option value="NO_EVIDENCE">근거 없음</option>
          <option value="INSUFFICIENT_EVIDENCE">근거 부족</option>
          <option value="CONFLICTING_EVIDENCE">근거 충돌</option>
          <option value="OUT_OF_SCOPE_INFORMATION">범위 밖 정보</option>
        </select>
      </label>
      <label>
        <span>판단 불가 설명</span>
        <textarea
          aria-describedby="unknown-note-help"
          maxLength={301}
          onChange={(event) => onNoteChange(event.target.value)}
          value={note}
        />
      </label>
      <p id="unknown-note-help">앞뒤 공백 없이 1–300자로 적어 주세요.</p>
      {invalid ? <p role="alert">사유와 설명을 확인해 주세요. 설명은 1–300자의 완전한 문장이어야 합니다.</p> : null}
    </div>
  );
}

export function PrimaryAxisField({
  value,
  onChange,
}: {
  value: EvaluatorPrimaryAxis | null;
  onChange: (value: EvaluatorPrimaryAxis | null) => void;
}) {
  const options: Array<{ value: EvaluatorPrimaryAxis | null; label: string }> = [
    { value: null, label: "주 경험축 판단 보류" },
    { value: "HISTORY_TRADITION", label: "역사·전통" },
    { value: "EMOTION_IMAGE", label: "감성·이미지" },
    { value: "REST_IMMERSION", label: "휴식·몰입" },
  ];
  return (
    <fieldset className="primary-axis-field">
      <legend>이 장소의 주 경험축</legend>
      <p>근거가 충분하지 않다면 판단 보류를 그대로 남길 수 있습니다.</p>
      {options.map((option) => (
        <label key={option.label}>
          <input
            checked={value === option.value}
            name="primary-axis"
            onChange={() => onChange(option.value)}
            type="radio"
          />
          <span>{option.label}</span>
        </label>
      ))}
    </fieldset>
  );
}

function evidenceError(items: EvidenceItem[], selectedIds: string[], mode: "ZERO" | "SCORE_3" | "SCORE_4"): string | null {
  const selected = items.filter((item) => selectedIds.includes(item.evidence_id));
  const direct = selected.filter((item) => item.direct);
  if (mode === "ZERO") {
    return selected.some((item) => item.supports_absence || item.complete_context)
      ? null
      : "0점에는 확인된 부재 또는 충분히 완전한 문맥 근거가 필요합니다.";
  }
  if (mode === "SCORE_3") {
    return direct.length > 0 ? null : "3점에는 직접 근거가 필요합니다.";
  }
  const byLane = new Map<string, Set<string>>();
  for (const item of direct) {
    const clusters = byLane.get(item.lane) ?? new Set<string>();
    clusters.add(item.dedup_cluster_id);
    byLane.set(item.lane, clusters);
  }
  if ([...byLane.values()].some((clusters) => clusters.size >= 2)) return null;
  const descriptionKeys = new Set(
    direct.filter((item) => item.lane === "DESCRIPTION").map((item) => item.concordance_key),
  );
  const concordant = direct.some(
    (item) => item.lane === "ODII" && descriptionKeys.has(item.concordance_key),
  );
  if (concordant) return null;
  if (direct.length >= 2 && new Set(direct.map((item) => item.dedup_cluster_id)).size < 2) {
    return "서로 다른 직접 근거 묶음이 두 개 이상 필요합니다.";
  }
  return "설명과 Odii를 함께 쓸 때는 의미 일치 근거가 필요합니다.";
}

export function EvidencePicker({
  items,
  selectedEvidenceIds,
  requiredMode,
  onChange,
}: {
  items: EvidenceItem[];
  selectedEvidenceIds: string[];
  requiredMode: "ZERO" | "SCORE_3" | "SCORE_4";
  onChange: (value: string[]) => void;
}) {
  const error = evidenceError(items, selectedEvidenceIds, requiredMode);
  return (
    <div className="evidence-picker">
      <p className="evidence-picker__title">이 판단을 뒷받침하는 직접 근거</p>
      {items.map((item) => (
        <label key={item.evidence_id}>
          <input
            checked={selectedEvidenceIds.includes(item.evidence_id)}
            onChange={() =>
              onChange(
                selectedEvidenceIds.includes(item.evidence_id)
                  ? selectedEvidenceIds.filter((value) => value !== item.evidence_id)
                  : [...selectedEvidenceIds, item.evidence_id],
              )
            }
            type="checkbox"
          />
          <span className="evidence-picker__copy">
            <strong>{item.lane === "DESCRIPTION" ? "공식 설명" : "Odii 대본"}</strong>
            <span>
              {item.sentence_text_ko ?? "원문 문장 연결 정보를 확인할 수 없습니다."}
            </span>
            <small>
              원천 {item.source_id} · 근거 {item.evidence_id}
            </small>
          </span>
        </label>
      ))}
      {error ? <p role="alert">{error}</p> : null}
    </div>
  );
}

export function ImmutableRevisionBanner({
  status,
  revisionRef,
  receiptRef,
  parentRef,
  submittedAt,
}: {
  status: "DRAFT" | "SUBMITTED" | "CORRECTED";
  revisionRef: string;
  receiptRef?: string;
  parentRef: string | null;
  submittedAt: string | null;
}) {
  if (status === "DRAFT") return null;
  return (
    <section className="immutable-revision-banner" aria-labelledby="revision-result-title">
      <h2 id="revision-result-title" tabIndex={-1}>
        {status === "CORRECTED" ? "수정 revision 제출 완료" : "제출 완료"}
      </h2>
      <p>제출된 내용은 수정하거나 삭제할 수 없습니다. 수정은 새 successor revision으로 남습니다.</p>
      <dl>
        <div>
          <dt>Revision SHA-256</dt>
          <dd>{revisionRef}</dd>
        </div>
        {receiptRef ? (
          <div>
            <dt>Receipt SHA-256</dt>
            <dd>{receiptRef}</dd>
          </div>
        ) : null}
        {parentRef ? (
          <div>
            <dt>Predecessor SHA-256</dt>
            <dd>{parentRef}</dd>
          </div>
        ) : null}
        {submittedAt ? (
          <div>
            <dt>제출 시각</dt>
            <dd>{submittedAt}</dd>
          </div>
        ) : null}
      </dl>
    </section>
  );
}

export function AsyncStatus({ state, message }: { state: "IDLE" | "LOADING" | "SUCCESS" | "ERROR"; message: string }) {
  return (
    <p
      aria-live="polite"
      className={`async-status async-status--${state.toLowerCase()}`}
      data-error-summary={state === "ERROR" ? true : undefined}
      role={state === "ERROR" ? "alert" : "status"}
      tabIndex={state === "ERROR" ? -1 : undefined}
    >
      {message}
    </p>
  );
}

function UnknownClearConfirmation({
  score,
  onCancel,
  onConfirm,
  returnFocusRef,
}: {
  score: number;
  onCancel: () => void;
  onConfirm: () => void;
  returnFocusRef: RefObject<HTMLInputElement | null>;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const { cancelAndRestore, dialogRef, onKeyDown, restoreFocus, safeRef } = useModalFocus<HTMLElement>({
    onCancel,
    returnFocusRef,
  });
  return createPortal(
    <div
      className="confirmation-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) cancelAndRestore();
      }}
    >
      <section
        aria-describedby={descriptionId}
        aria-labelledby={titleId}
        aria-modal="true"
        className="unknown-clear-confirmation"
        onKeyDown={onKeyDown}
        ref={dialogRef}
        role="alertdialog"
        tabIndex={-1}
      >
        <h3 id={titleId}>판단 불가 내용을 지울까요?</h3>
        <p id={descriptionId}>
          입력한 판단 불가 사유와 설명은 숫자 점수로 바꾸면 삭제됩니다. 취소하면 현재
          내용을 그대로 보존합니다.
        </p>
        <div className="dialog-actions">
          <button className="button button--secondary" onClick={cancelAndRestore} ref={safeRef} type="button">
            판단 불가 유지하기
          </button>
          <button
            className="button button--primary"
            onClick={() => {
              onConfirm();
              restoreFocus();
            }}
            type="button"
          >
            내용 지우고 {score}점 선택하기
          </button>
        </div>
      </section>
    </div>,
    document.body,
  );
}

function draftError(draft: JudgmentDraft, evidenceItems: EvidenceItem[]): string | null {
  if (draft.unknownSelected) {
    if (draft.reason === null || draft.note.trim().length < 1 || draft.note.length > 300 || draft.note !== draft.note.trim()) {
      return "판단 불가 사유와 1–300자 설명이 필요합니다.";
    }
    return null;
  }
  if (draft.score === null) return "0–4 또는 판단 불가를 선택해 주세요.";
  if (draft.reason !== null || draft.note.length > 0) return "숫자 점수에는 판단 불가 사유를 함께 보낼 수 없습니다.";
  if (draft.score === 0) return evidenceError(evidenceItems, draft.selectedEvidenceIds, "ZERO");
  if (draft.score === 3) return evidenceError(evidenceItems, draft.selectedEvidenceIds, "SCORE_3");
  if (draft.score === 4) return evidenceError(evidenceItems, draft.selectedEvidenceIds, "SCORE_4");
  return null;
}

function submissionFromDrafts(
  fixture: RuntimeFixture,
  drafts: Record<string, JudgmentDraft>,
  evidenceItems: EvidenceItem[],
  primaryAxis: EvaluatorPrimaryAxis | null,
): EvaluatorSubmission {
  const judgments = RUBRIC_SPECS.map((spec) => {
    const draft = drafts[spec.attribute_id];
    const selectedEvidence = evidenceItems
      .filter((item) => draft.selectedEvidenceIds.includes(item.evidence_id))
      .map((item) => ({
        complete_context: item.complete_context ?? false,
        concordance_key: item.concordance_key,
        dedup_cluster_id: item.dedup_cluster_id,
        direct: item.direct,
        evidence_id: item.evidence_id,
        lane: item.lane,
        source_id: item.source_id,
        supports_absence: item.supports_absence ?? false,
      }));
    return {
      attribute_id: spec.attribute_id,
      evidence: selectedEvidence,
      score: draft.unknownSelected ? null : draft.score,
      unknown_note: draft.unknownSelected ? draft.note : null,
      unknown_reason: draft.unknownSelected ? draft.reason : null,
    };
  }) as unknown as EvaluatorSubmission["judgments"];
  return {
    assignment_id: fixture.assignment.assignment_id,
    judgments,
    primary_axis: primaryAxis,
    rubric_version: fixture.assignment.rubric_version,
    source_snapshot_version: fixture.assignment.source_snapshot_version,
    submitted_at: new Date().toISOString(),
  };
}

export function EvaluatorWorkspace({
  onAuthorizationLost,
}: {
  onAuthorizationLost?: () => void;
} = {}) {
  const [accessState, setAccessState] = useState<"AUTHORIZED" | "FORBIDDEN">("AUTHORIZED");
  const [fixture, setFixture] = useState<RuntimeFixture | null>(null);
  const [drafts, setDrafts] = useState<Record<string, JudgmentDraft>>(emptyDrafts);
  const [primaryAxis, setPrimaryAxis] = useState<EvaluatorPrimaryAxis | null>(null);
  const [receipt, setReceipt] = useState<StoredLabelRevision | null>(null);
  const [correctionParent, setCorrectionParent] = useState<StoredLabelRevision | null>(null);
  const [correctionReason, setCorrectionReason] = useState("");
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [pendingNumericSelection, setPendingNumericSelection] = useState<{
    attributeId: string;
    score: number;
  } | null>(null);
  const pendingNumericTriggerRef = useRef<HTMLInputElement | null>(null);
  const [showErrors, setShowErrors] = useState(false);
  const [status, setStatus] = useState<"IDLE" | "LOADING" | "SUCCESS" | "ERROR">("LOADING");
  const [statusMessage, setStatusMessage] = useState("평가 자료를 안전하게 준비하고 있습니다.");
  const headingRef = useRef<HTMLHeadingElement>(null);

  const resetSensitiveState = useCallback(() => {
    setFixture(null);
    setDrafts(emptyDrafts());
    setPrimaryAxis(null);
    setReceipt(null);
    setCorrectionParent(null);
    setCorrectionReason("");
    setConfirmationOpen(false);
    setPendingNumericSelection(null);
    setShowErrors(false);
  }, []);

  const client = useMemo(
    () =>
      createEvaluatorClient({
        onSecurityBoundary: () => {
          resetSensitiveState();
          setAccessState("FORBIDDEN");
          setStatus("ERROR");
          setStatusMessage("평가자 권한이 바뀌어 이전 평가 내용을 모두 지웠습니다.");
          onAuthorizationLost?.();
        },
      }),
    [onAuthorizationLost, resetSensitiveState],
  );

  const clearRoleState = useCallback(() => {
    client.clear();
    resetSensitiveState();
  }, [client, resetSensitiveState]);

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        const response = await fetch("/internal/test-support/phase3/fixture", {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (response.status === 401 || response.status === 403) {
          client.clear("AUTHORIZATION_LOST");
          return;
        }
        if (!response.ok) throw new Error("fixture unavailable");
        const value = (await response.json()) as unknown;
        if (!isRuntimeFixture(value)) throw new Error("fixture contract mismatch");
        setFixture(value);
        setStatus("IDLE");
        setStatusMessage("공식 근거와 12개 평가 기준을 불러왔습니다.");
        requestAnimationFrame(() => headingRef.current?.focus());
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setStatus("ERROR");
        setStatusMessage("평가 자료를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.");
      }
    };
    void load();
    return () => {
      controller.abort();
      client.clear();
    };
  }, [client]);

  const evidenceItems = useMemo(() => evidenceForSources(fixture?.sources ?? []), [fixture]);

  const updateDraft = useCallback(
    (attributeId: string, patch: Partial<JudgmentDraft>) => {
      setDrafts((current) => ({
        ...current,
        [attributeId]: { ...current[attributeId], ...patch },
      }));
      setConfirmationOpen(false);
    },
    [],
  );

  useEffect(() => {
    if (status !== "ERROR") return;
    const frame = requestAnimationFrame(() =>
      document.querySelector<HTMLElement>("[data-error-summary]")?.focus(),
    );
    return () => cancelAnimationFrame(frame);
  }, [status, statusMessage]);

  const validateAll = useCallback(() => {
    const invalid = RUBRIC_SPECS.some(
      (spec) => draftError(drafts[spec.attribute_id], evidenceItems) !== null,
    );
    const correctionInvalid =
      correctionParent !== null &&
      (correctionReason.trim().length < 1 ||
        correctionReason.length > 300 ||
        correctionReason !== correctionReason.trim());
    return !invalid && !correctionInvalid;
  }, [correctionParent, correctionReason, drafts, evidenceItems]);

  const openConfirmation = useCallback(() => {
    setShowErrors(true);
    if (!validateAll()) {
      setStatus("ERROR");
      setStatusMessage("제출 전에 표시된 평가 항목을 확인해 주세요.");
      document.querySelector<HTMLElement>("[role='alert']")?.focus();
      return;
    }
    setStatus("IDLE");
    setStatusMessage("내용을 확인한 뒤 불변 revision 제출을 확정해 주세요.");
    setConfirmationOpen(true);
  }, [validateAll]);

  const commitRevision = useCallback(async () => {
    if (fixture === null || !validateAll()) return;
    const base = submissionFromDrafts(fixture, drafts, evidenceItems, primaryAxis);
    setStatus("LOADING");
    setStatusMessage("서버의 불변 영수증을 기다리고 있습니다.");
    try {
      const stored =
        correctionParent === null
          ? await client.submitWithRecovery(base)
          : await client.correctWithRecovery(correctionParent.revision_sha256, {
              ...base,
              correction_reason: correctionReason,
            } satisfies EvaluatorCorrection);
      setReceipt(stored);
      setCorrectionParent(null);
      setCorrectionReason("");
      setConfirmationOpen(false);
      setShowErrors(false);
      setStatus("SUCCESS");
      setStatusMessage("데이터베이스의 불변 영수증을 확인했습니다.");
      requestAnimationFrame(() =>
        document.querySelector<HTMLElement>("#revision-result-title")?.focus(),
      );
    } catch (error) {
      if (error instanceof EvaluatorApiError && (error.status === 401 || error.status === 403)) {
        return;
      }
      setStatus("ERROR");
      setStatusMessage(
        error instanceof EvaluatorApiError
          ? error.message
          : "평가 revision을 제출하지 못했습니다.",
      );
    }
  }, [client, correctionParent, correctionReason, drafts, evidenceItems, fixture, primaryAxis, validateAll]);

  const beginCorrection = useCallback(() => {
    if (receipt === null) return;
    setCorrectionParent(receipt);
    setCorrectionReason("");
    setConfirmationOpen(false);
    setStatus("IDLE");
    setStatusMessage("수정은 predecessor를 보존한 새 successor revision으로 제출됩니다.");
    requestAnimationFrame(() => headingRef.current?.focus());
  }, [receipt]);

  return (
    <InternalRoleShell
      actorLabel="격리된 독립 평가 세션"
      accessState={accessState}
      clearRoleState={clearRoleState}
      onExit={onAuthorizationLost}
    >
      <header className="evaluator-intro">
        <p className="eyebrow">Phase 3 · 독립 근거 평가</p>
        <h1 ref={headingRef} tabIndex={-1}>독립 평가를 시작합니다</h1>
        <p>다른 평가자나 모델 결과 없이 공식 설명과 Odii 근거만 보고 판단합니다.</p>
      </header>
      <AsyncStatus state={status} message={statusMessage} />

      {fixture ? (
        <>
          <div className="evaluation-workspace">
            <div className="evaluation-workspace__source">
              <section className="source-material" role="region" aria-label="공식 근거">
                <h2>공식 근거</h2>
                {fixture.sources.map((source) => (
                  <article key={source.source_id}>
                    <h3>{source.lane === "DESCRIPTION" ? "공식 설명" : "Odii 대본"}</h3>
                    <p>{source.text_ko}</p>
                  </article>
                ))}
              </section>
              <RubricAnchorPanel />
            </div>
            <form
              className="evaluator-form"
              onSubmit={(event) => {
                event.preventDefault();
                if (confirmationOpen) void commitRevision();
                else openConfirmation();
              }}
            >
            <section className="attribute-list" aria-labelledby="attribute-list-title">
              <h2 id="attribute-list-title">12개 경험 속성</h2>
              {RUBRIC_SPECS.map((spec) => {
                const draft = drafts[spec.attribute_id];
                const mode =
                  draft.score === 0
                    ? "ZERO"
                    : draft.score === 3
                      ? "SCORE_3"
                      : draft.score === 4
                        ? "SCORE_4"
                        : null;
                const error = showErrors ? draftError(draft, evidenceItems) : null;
                return (
                  <section className="attribute-card" key={spec.attribute_id}>
                    <AttributeScoreField
                      spec={spec}
                      score={draft.score}
                      unknownSelected={draft.unknownSelected}
                      onScoreChange={(score, trigger) => {
                        if (score === null) return;
                        if (
                          draft.unknownSelected &&
                          (draft.reason !== null || draft.note.length > 0)
                        ) {
                          pendingNumericTriggerRef.current = trigger ?? null;
                          setPendingNumericSelection({
                            attributeId: spec.attribute_id,
                            score,
                          });
                          return;
                        }
                        updateDraft(spec.attribute_id, {
                          note: "",
                          reason: null,
                          score,
                          unknownSelected: false,
                        });
                      }}
                      onUnknownChange={(unknownSelected) =>
                        updateDraft(spec.attribute_id, {
                          unknownSelected,
                          ...(unknownSelected
                            ? { score: null }
                            : { note: "", reason: null }),
                        })
                      }
                    >
                      {draft.unknownSelected ? (
                        <UnknownReasonFields
                          reason={draft.reason}
                          note={draft.note}
                          showErrors
                          onReasonChange={(reason) =>
                            updateDraft(spec.attribute_id, {
                              reason: reason as EvaluatorUnknownReason,
                            })
                          }
                          onNoteChange={(note) => updateDraft(spec.attribute_id, { note })}
                        />
                      ) : null}
                      {pendingNumericSelection?.attributeId === spec.attribute_id ? (
                        <UnknownClearConfirmation
                          onCancel={() => setPendingNumericSelection(null)}
                          onConfirm={() => {
                            updateDraft(spec.attribute_id, {
                              note: "",
                              reason: null,
                              score: pendingNumericSelection.score,
                              unknownSelected: false,
                            });
                            setPendingNumericSelection(null);
                          }}
                          score={pendingNumericSelection.score}
                          returnFocusRef={pendingNumericTriggerRef}
                        />
                      ) : null}
                      {mode ? (
                        <EvidencePicker
                          items={evidenceItems}
                          selectedEvidenceIds={draft.selectedEvidenceIds}
                          requiredMode={mode}
                          onChange={(selectedEvidenceIds) =>
                            updateDraft(spec.attribute_id, { selectedEvidenceIds })
                          }
                        />
                      ) : null}
                      {error && !draft.unknownSelected && mode === null ? (
                        <p className="field-error" role="alert" tabIndex={-1}>{error}</p>
                      ) : null}
                    </AttributeScoreField>
                  </section>
                );
              })}
            </section>
            <PrimaryAxisField value={primaryAxis} onChange={setPrimaryAxis} />
            {correctionParent ? (
              <label className="correction-reason-field">
                <span>수정 사유</span>
                <textarea
                  maxLength={301}
                  onChange={(event) => setCorrectionReason(event.target.value)}
                  value={correctionReason}
                />
                <small>앞뒤 공백 없이 1–300자로 predecessor와 달라진 이유를 적어 주세요.</small>
              </label>
            ) : null}
            {confirmationOpen ? (
              <section className="immutable-confirmation" aria-labelledby="immutable-confirmation-title">
                <h2 id="immutable-confirmation-title">불변 제출을 확인해 주세요</h2>
                <p>제출 후에는 내용을 덮어쓸 수 없고, 수정은 새 successor로만 남습니다.</p>
                <button className="button button--primary" type="submit">
                  {correctionParent ? "수정 successor 제출하기" : "불변 revision 제출하기"}
                </button>
              </section>
            ) : (
              <button className="button button--primary evaluator-submit" type="submit">
                {correctionParent ? "수정 내용 검토하기" : "평가 revision 제출하기"}
              </button>
            )}
            </form>
          </div>
          {receipt ? (
            <>
              <ImmutableRevisionBanner
                status={receipt.revision.parent_revision_sha256 ? "CORRECTED" : "SUBMITTED"}
                revisionRef={receipt.revision_sha256}
                receiptRef={receipt.receipt_sha256}
                parentRef={receipt.revision.parent_revision_sha256 ?? null}
                submittedAt={receipt.created_at}
              />
              {correctionParent === null ? (
                <button className="button button--secondary" onClick={beginCorrection} type="button">
                  수정 revision 만들기
                </button>
              ) : null}
            </>
          ) : null}
        </>
      ) : null}
    </InternalRoleShell>
  );
}
