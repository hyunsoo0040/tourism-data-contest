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
import { useParams } from "react-router-dom";

import {
  EvaluatorApiError,
  createAdjudicatorClient,
  createOperatorClient,
  type AdjudicatedLabelExport,
  type AdjudicationProjection,
  type AggregateInput,
  type LabelFreezeInput,
  type LabelFreezeReceipt,
  type OperatorStatus,
  type ReviewTrigger,
} from "./api";
import { InternalRoleHeader } from "./EvaluatorWorkspace";
import { useModalFocus } from "./useModalFocus";

export type InternalEvaluationRole = "operator" | "adjudicator";
type StepState = "CURRENT" | "COMPLETE" | "BLOCKED";
type HalfStepInput = {
  exactMedian: string;
  lower: number;
  upper: number;
  selected: number | null;
  reason: string;
};

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ATTRIBUTE_IDS = ["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"] as const;
const TRIGGER_COPY: Record<ReviewTrigger["kind"], string> = {
  ALL_PRIMARY_AXES_DIFFER: "주유형 판단 전원 불일치",
  ATTRIBUTE_RANGE_AT_LEAST_TWO: "점수 범위 차이 2 이상",
  PRIMARY_AXIS_MISSING: "주유형 판단 누락",
  REQUIRED_EVIDENCE_MISSING: "필수 근거 누락",
};
const SUBMISSION_STATUS_COPY: Record<OperatorStatus["submission_status"], string> = {
  SUBMITTED: "제출됨 (SUBMITTED)",
};
type GateState = "PASSED" | "BLOCKED" | "EXTERNAL_PENDING";
const GATE_STATE_COPY: Record<GateState, string> = {
  BLOCKED: "차단",
  EXTERNAL_PENDING: "외부 증거 대기",
  PASSED: "통과",
};

function evaluatorLabel(index: number): string {
  return `평가자 ${String.fromCharCode(65 + index)}`;
}

function latestRevision(
  chain: AdjudicationProjection["chains"][number],
): AdjudicationProjection["chains"][number]["revisions"][number] {
  return chain.revisions[chain.revisions.length - 1]!;
}

function acceptedRevisions(projection: AdjudicationProjection | null) {
  if (
    projection === null ||
    projection.chains.length !== 3 ||
    projection.chains.some((chain) => chain.accepted_head === null)
  ) {
    return [];
  }
  return projection.chains.flatMap((chain) => {
    const acceptedRevisionSha256 = chain.accepted_head!.selection.accepted_revision_sha256;
    const accepted = chain.revisions.find(
      (revision) => revision.revision_sha256 === acceptedRevisionSha256,
    );
    return accepted ? [accepted] : [];
  });
}

function numericCompleteness(projection: AdjudicationProjection | null): boolean {
  const revisions = acceptedRevisions(projection);
  if (revisions.length !== 3) return false;
  return ATTRIBUTE_IDS.every(
    (attributeId) =>
      revisions.filter(
        (revision) =>
          typeof revision.judgments.find(
            (judgment) => judgment.attribute_id === attributeId,
          )?.score === "number",
      ).length >= 2,
  );
}

function buildHalfSteps(projection: AdjudicationProjection | null): Record<string, HalfStepInput> {
  const revisions = acceptedRevisions(projection);
  if (revisions.length !== 3) return {};
  const entries = ATTRIBUTE_IDS.flatMap((attributeId) => {
    const values = revisions
      .map(
        (revision) =>
          revision.judgments.find((judgment) => judgment.attribute_id === attributeId)?.score ??
          null,
      )
      .filter((score): score is number => score !== null)
      .sort((left, right) => left - right);
    if (values.length !== 2 || (values[0]! + values[1]!) % 2 === 0) return [];
    const lower = Math.floor((values[0]! + values[1]!) / 2);
    return [
      [
        attributeId,
        {
          exactMedian: `${lower}.5`,
          lower,
          upper: lower + 1,
          selected: null,
          reason: "",
        },
      ] as const,
    ];
  });
  return Object.fromEntries(entries);
}

export function WorkflowStepper({
  steps,
}: {
  steps: Array<{ label: string; state: StepState; reason?: string }>;
}) {
  return (
    <nav aria-label="라벨 workflow 단계" className="rubric-anchor-panel">
      <ol>
        {steps.map((step) => (
          <li
            aria-current={step.state === "CURRENT" ? "step" : undefined}
            key={step.label}
          >
            <strong>{step.label}</strong>{" "}
            {step.state === "COMPLETE"
              ? "완료"
              : step.state === "BLOCKED"
                ? `아직 진행할 수 없음${step.reason ? ` — ${step.reason}` : ""}`
                : "현재 단계"}
          </li>
        ))}
      </ol>
    </nav>
  );
}

export function SubmissionStatusList({ statuses }: { statuses: OperatorStatus[] }) {
  return (
    <section className="source-material" aria-labelledby="submission-status-title">
      <h2 id="submission-status-title">평가자 제출 상태</h2>
      {statuses.length === 0 ? (
        <p>세 평가자의 제출을 기다리는 중입니다.</p>
      ) : (
        <ul aria-label="평가자 제출 상태">
          {statuses.map((status, index) => (
            <li key={status.evaluator_pseudonym}>
              <strong>{evaluatorLabel(index)}</strong> ·{" "}
              {SUBMISSION_STATUS_COPY[status.submission_status]} ·{" "}
              {status.all_required_submissions_exist ? "필수 제출 충족" : "필수 제출 미충족"} ·{" "}
              <time dateTime={status.latest_server_event_at}>{status.latest_server_event_at}</time>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function HashBlock({ label, value }: { label: string; value: string }) {
  const [copyStatus, setCopyStatus] = useState("");
  return (
    <div className="hash-block">
      <strong>{label}</strong>
      <p style={{ overflowWrap: "anywhere" }}>{value}</p>
      <button
        className="button button--secondary"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopyStatus(`${label} 복사 완료`);
          } catch {
            setCopyStatus(`${label} 복사 실패`);
          }
        }}
        type="button"
      >
        전체 hash 복사
      </button>
      <span aria-live="polite">{copyStatus}</span>
    </div>
  );
}

export function GateChecklist({
  gates,
}: {
  gates: Array<{
    label: string;
    state: GateState;
    reason: string;
    nextActor?: string;
  }>;
}) {
  return (
    <section className="source-material" aria-labelledby="gate-checklist-title">
      <h2 id="gate-checklist-title">라벨 동결 gate</h2>
      <ul>
        {gates.map((gate) => (
          <li key={gate.label}>
            <strong>{gate.label}</strong> · {GATE_STATE_COPY[gate.state]} · {gate.reason}
            {gate.nextActor ? ` · 다음 담당: ${gate.nextActor}` : ""}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ConfirmationDialog({
  title,
  busy,
  children,
  safeLabel,
  confirmLabel,
  onCancel,
  onConfirm,
  returnFocusRef,
  error = null,
}: {
  title: string;
  busy: boolean;
  children: ReactNode;
  safeLabel: string;
  confirmLabel: string;
  onCancel: () => void;
  onConfirm: () => void;
  returnFocusRef?: RefObject<HTMLElement | null>;
  error?: string | null;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const errorRef = useRef<HTMLParagraphElement>(null);
  const { cancelAndRestore, dialogRef, onKeyDown, safeRef } = useModalFocus<HTMLDivElement>({
    busy,
    onCancel,
    returnFocusRef,
  });
  useEffect(() => {
    if (error !== null) errorRef.current?.focus();
  }, [error]);
  return (
    <div
      aria-busy={busy}
      aria-describedby={descriptionId}
      aria-labelledby={titleId}
      aria-modal="true"
      className="immutable-confirmation"
      onKeyDown={onKeyDown}
      ref={dialogRef}
      role="dialog"
      tabIndex={-1}
    >
      <h2 id={titleId}>{title}</h2>
      <div id={descriptionId}>{children}</div>
      {error ? (
        <p
          className="async-status async-status--error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
        >
          {error}
        </p>
      ) : null}
      <div className="dialog-actions">
        <button
          className="button button--secondary"
          disabled={busy}
          onClick={cancelAndRestore}
          ref={safeRef}
          type="button"
        >
          {safeLabel}
        </button>
        <button
          className="button button--primary"
          disabled={busy}
          onClick={onConfirm}
          type="button"
        >
          {confirmLabel}
        </button>
      </div>
    </div>
  );
}

export function AdjudicationComparison({
  projection,
  busyChain,
  onSelect,
}: {
  projection: AdjudicationProjection;
  busyChain: string | null;
  onSelect: (revisionSha256: string, chainSha256: string) => void;
}) {
  return (
    <>
      <section className="source-material" aria-label="공식 근거 원문">
        <h2>공식 근거</h2>
        {projection.official_sources.map((source) => (
          <article key={source.source_id}>
            <h3>{source.lane === "DESCRIPTION" ? "공식 설명" : "Odii 대본"}</h3>
            <p>{source.original_text}</p>
            <HashBlock label="Source text SHA-256" value={source.source_text_sha256} />
          </article>
        ))}
      </section>
      <section aria-labelledby="revision-comparison-title">
        <h2 id="revision-comparison-title">익명 raw revision 비교</h2>
        <div className="revision-comparison-grid">
          {projection.chains.map((chain, chainIndex) => {
            const label = evaluatorLabel(chainIndex);
            const tip = latestRevision(chain);
            const tipIsAccepted =
              chain.accepted_head?.selection.accepted_revision_sha256 === tip.revision_sha256;
            return (
              <article
                aria-label={`${label} revision chain`}
                className="attribute-card"
                key={chain.evaluator_pseudonym}
              >
                <h3>{label}</h3>
                <p>
                  {tipIsAccepted
                    ? "accepted revision 선택됨"
                    : chain.accepted_head
                      ? "이전 revision 선택됨 · 최신 correction 재검토 필요"
                      : "accepted revision 미선택"}
                </p>
                <HashBlock label="Chain SHA-256" value={chain.chain_sha256!} />
                {chain.revisions.map((revision, revisionIndex) => (
                  <section key={revision.revision_sha256}>
                    <h4>Revision {revisionIndex + 1}</h4>
                    <p>제출 시각: {revision.submitted_at}</p>
                    {revision.correction_reason ? <p>Correction 사유: {revision.correction_reason}</p> : null}
                    <dl>
                      <div>
                        <dt>주 경험축</dt>
                        <dd>{revision.primary_axis ?? "판단 불가"}</dd>
                      </div>
                      {revision.judgments.map((judgment) => (
                        <div key={judgment.attribute_id}>
                          <dt>{judgment.attribute_id}</dt>
                          <dd>
                            {judgment.score === null
                              ? `판단 불가 · ${judgment.unknown_reason} · ${judgment.unknown_note}`
                              : judgment.score === 0
                                ? "0 · 확인된 부재"
                                : `${judgment.score}`}
                            {judgment.evidence.length > 0
                              ? ` · 근거 ${judgment.evidence.map((item) => item.evidence_id).join(", ")}`
                              : ""}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </section>
                ))}
                {!tipIsAccepted ? (
                  <button
                    aria-busy={busyChain === chain.chain_sha256}
                    className="button button--primary"
                    disabled={busyChain !== null}
                    onClick={() => onSelect(tip.revision_sha256, chain.chain_sha256!)}
                    type="button"
                  >
                    {label} accepted revision 선택
                  </button>
                ) : null}
              </article>
            );
          })}
        </div>
      </section>
    </>
  );
}

function triggerLabel(trigger: ReviewTrigger): string {
  return `${TRIGGER_COPY[trigger.kind]}${trigger.attribute_id ? ` · ${trigger.attribute_id}` : ""}`;
}

export function OperatorAdjudication({
  role,
  onAuthorizationLost,
}: {
  role: InternalEvaluationRole;
  onAuthorizationLost?: () => void;
}) {
  const { assignmentId = "" } = useParams();
  const [statuses, setStatuses] = useState<OperatorStatus[]>([]);
  const [projection, setProjection] = useState<AdjudicationProjection | null>(null);
  const [persistedTriggers, setPersistedTriggers] = useState<ReviewTrigger[]>([]);
  const [resolvedTriggers, setResolvedTriggers] = useState<Set<string>>(new Set());
  const [resolutionReasons, setResolutionReasons] = useState<Record<string, string>>({});
  const [halfSteps, setHalfSteps] = useState<Record<string, HalfStepInput>>({});
  const [labelExport, setLabelExport] = useState<AdjudicatedLabelExport | null>(null);
  const [freezeInput, setFreezeInput] = useState<LabelFreezeInput>({
    dev_lineage_sha256: "",
    export_sha256: "",
    rubric_sha256: "",
    source_root_sha256: "",
  });
  const [freezeReceipt, setFreezeReceipt] = useState<LabelFreezeReceipt | null>(null);
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [accessDenied, setAccessDenied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [busyChain, setBusyChain] = useState<string | null>(null);
  const [message, setMessage] = useState("권한과 최신 서버 상태를 확인하고 있습니다.");
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const resultRef = useRef<HTMLHeadingElement>(null);
  const freezeTriggerRef = useRef<HTMLButtonElement>(null);

  const clearSensitiveState = useCallback(() => {
    setStatuses([]);
    setProjection(null);
    setPersistedTriggers([]);
    setResolvedTriggers(new Set());
    setResolutionReasons({});
    setHalfSteps({});
    setLabelExport(null);
    setFreezeInput({
      dev_lineage_sha256: "",
      export_sha256: "",
      rubric_sha256: "",
      source_root_sha256: "",
    });
    setFreezeReceipt(null);
    setConfirmationOpen(false);
  }, []);

  const securityBoundary = useCallback(() => {
    clearSensitiveState();
    setAccessDenied(true);
    setError("이 역할은 이 자료를 볼 수 없습니다.");
    onAuthorizationLost?.();
  }, [clearSensitiveState, onAuthorizationLost]);
  const operatorClient = useMemo(
    () => createOperatorClient({ onSecurityBoundary: securityBoundary }),
    [securityBoundary],
  );
  const adjudicatorClient = useMemo(
    () => createAdjudicatorClient({ onSecurityBoundary: securityBoundary }),
    [securityBoundary],
  );

  useEffect(() => {
    if (freezeReceipt === null && labelExport === null) return;
    const frame = requestAnimationFrame(() => resultRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [freezeReceipt, labelExport]);

  useEffect(() => {
    if (error === null || confirmationOpen) return;
    const frame = requestAnimationFrame(() => errorRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [confirmationOpen, error]);

  const loadProjection = useCallback(async () => {
    if (!assignmentId) throw new Error("assignment missing");
    const next = await adjudicatorClient.getProjection(assignmentId);
    setProjection(next);
    setHalfSteps(buildHalfSteps(next));
    setPersistedTriggers([]);
    setResolvedTriggers(new Set());
    setResolutionReasons({});
    setLabelExport(null);
    return next;
  }, [adjudicatorClient, assignmentId]);

  useEffect(() => {
    clearSensitiveState();
    setAccessDenied(false);
    setError(null);
    setMessage("권한과 최신 서버 상태를 확인하고 있습니다.");
    const load = async () => {
      try {
        if (role === "operator") setStatuses(await operatorClient.getStatus());
        else await loadProjection();
        setMessage("최신 서버 projection을 확인했습니다.");
        requestAnimationFrame(() => {
          if (document.querySelector('[aria-modal="true"]')) return;
          headingRef.current?.focus();
        });
      } catch (loadError) {
        if (
          loadError instanceof EvaluatorApiError &&
          (loadError.status === 401 || loadError.status === 403)
        ) {
          return;
        }
        clearSensitiveState();
        setError("현재 상태를 확인하지 못했습니다. 입력은 변경되지 않았습니다.");
      }
    };
    void load();
    return () => {
      operatorClient.clear();
      adjudicatorClient.clear();
      clearSensitiveState();
    };
  }, [adjudicatorClient, clearSensitiveState, loadProjection, operatorClient, role]);

  const selectAcceptedHead = useCallback(
    async (revisionSha256: string, chainSha256: string) => {
      setBusyChain(chainSha256);
      setError(null);
      try {
        await adjudicatorClient.selectAcceptedHead(revisionSha256, {
          expected_chain_sha256: chainSha256,
          reason: "공식 원문과 현재 correction chain tip을 대조해 선택함",
        });
        await loadProjection();
        setMessage("서버의 append-only accepted-head 영수증을 확인했습니다.");
      } catch (selectionError) {
        setError(
          selectionError instanceof EvaluatorApiError
            ? selectionError.message
            : "accepted revision을 선택하지 못했습니다.",
        );
        if (selectionError instanceof EvaluatorApiError && selectionError.status === 409) {
          await loadProjection().catch(() => undefined);
        }
      } finally {
        setBusyChain(null);
      }
    },
    [adjudicatorClient, loadProjection],
  );

  const storeTriggers = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const triggers = await adjudicatorClient.deriveReviewTriggers(assignmentId);
      setPersistedTriggers(triggers);
      setResolvedTriggers(new Set());
      setMessage("서버가 exact review trigger 목록을 불변 상태로 기록했습니다.");
    } catch (triggerError) {
      setError(triggerError instanceof EvaluatorApiError ? triggerError.message : "재검토 목록을 만들지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }, [adjudicatorClient, assignmentId]);

  const resolveTrigger = useCallback(
    async (trigger: ReviewTrigger) => {
      const digest = trigger.review_trigger_sha256!;
      const reason = resolutionReasons[digest]?.trim() ?? "";
      if (!reason) {
        setError("재검토 사유를 해결한 근거를 입력하세요.");
        return;
      }
      setBusy(true);
      setError(null);
      try {
        await adjudicatorClient.resolveReviewTrigger(assignmentId, {
          reason,
          review_trigger_sha256: digest,
        });
        setResolvedTriggers((current) => new Set(current).add(digest));
        setMessage("재검토 해결 영수증을 확인했습니다.");
      } catch (resolutionError) {
        setError(resolutionError instanceof EvaluatorApiError ? resolutionError.message : "재검토 해결을 게시하지 못했습니다.");
      } finally {
        setBusy(false);
      }
    },
    [adjudicatorClient, assignmentId, resolutionReasons],
  );

  const publishAggregate = useCallback(async () => {
    if (!projection) return;
    const incompleteHalfStep = Object.values(halfSteps).some(
      (item) => item.selected === null || item.reason.trim().length === 0,
    );
    if (incompleteHalfStep) {
      setError("모든 반 단계 median의 조정 값과 사유를 입력하세요.");
      return;
    }
    const input: AggregateInput = {
      adjudications: Object.entries(halfSteps).map(([attribute_id, item]) => ({
        adjudicated_value: item.selected!,
        attribute_id: attribute_id as (typeof ATTRIBUTE_IDS)[number],
        exact_median: item.exactMedian,
        reason: item.reason.trim(),
      })),
    };
    setBusy(true);
    setError(null);
    try {
      const exported = await adjudicatorClient.aggregate(assignmentId, input);
      setLabelExport(exported);
      setMessage("데이터베이스의 불변 label export 영수증을 확인했습니다.");
    } catch (aggregateError) {
      setError(aggregateError instanceof EvaluatorApiError ? aggregateError.message : "조정 결과를 게시하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }, [adjudicatorClient, assignmentId, halfSteps, projection]);

  const freeze = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const receipt = await operatorClient.freeze(freezeInput);
      setFreezeReceipt(receipt);
      setConfirmationOpen(false);
      setMessage("서버의 불변 label-freeze receipt를 확인했습니다.");
    } catch (freezeError) {
      setError(freezeError instanceof EvaluatorApiError ? freezeError.message : "라벨 집합을 동결하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }, [freezeInput, operatorClient]);

  if (accessDenied) {
    return (
      <main className="evaluator-shell evaluator-shell--forbidden">
        <h1 ref={headingRef} tabIndex={-1}>이 역할은 이 자료를 볼 수 없습니다.</h1>
        <p>권한이 바뀌어 이전 역할의 요청, 화면 상태, 브라우저 저장소를 모두 지웠습니다.</p>
      </main>
    );
  }

  const allSubmitted = statuses.length === 3 && statuses.every((status) => status.all_required_submissions_exist);
  const allAccepted = projection?.chains.length === 3 && projection.chains.every((chain) => chain.accepted_head !== null);
  const allHashesComplete = Object.values(freezeInput).every((value) => SHA256_PATTERN.test(value));

  const exitRole = () => {
    operatorClient.clear();
    adjudicatorClient.clear();
    clearSensitiveState();
    onAuthorizationLost?.();
  };

  const closeFreezeConfirmation = () => {
    setError(null);
    setConfirmationOpen(false);
  };

  return (
    <main className="evaluator-shell" data-evaluation-role={role}>
      <InternalRoleHeader
        onExit={onAuthorizationLost === undefined ? undefined : exitRole}
        roleLabel={role === "operator" ? "Label operator" : "Adjudicator"}
      />
      <header className="evaluator-intro">
        <p className="eyebrow">Phase 3 · 독립 라벨 원장</p>
        <h1 ref={headingRef} tabIndex={-1}>
          {role === "operator" ? "독립 제출 상태" : "익명 revision 재검토"}
        </h1>
        <p>{role === "operator" ? "점수나 근거 없이 제출 완료 상태만 확인합니다." : "모델 결과 없이 공식 원문과 익명 raw revision만 대조합니다."}</p>
      </header>
      <p aria-live="polite" className="async-status" role="status">{message}</p>
      {error && !confirmationOpen ? (
        <p
          className="async-status async-status--error"
          ref={errorRef}
          role="alert"
          tabIndex={-1}
        >
          {error}
        </p>
      ) : null}

      {role === "operator" ? (
        <>
          <WorkflowStepper
            steps={[
              { label: "제출 상태", state: allSubmitted ? "COMPLETE" : "CURRENT" },
              { label: "재검토", state: "BLOCKED", reason: "adjudicator capability 전용" },
              { label: "accepted revision 선택", state: "BLOCKED", reason: "adjudicator capability 전용" },
              { label: "라벨 동결", state: allSubmitted ? "CURRENT" : "BLOCKED", reason: "세 제출 필요" },
            ]}
          />
          <SubmissionStatusList statuses={statuses} />
          <GateChecklist
            gates={[
              { label: "세 evaluator 제출", state: allSubmitted ? "PASSED" : "BLOCKED", reason: allSubmitted ? "서버 status 확인" : "제출 대기", nextActor: allSubmitted ? undefined : "독립 평가자" },
              { label: "네 lineage hash", state: allHashesComplete ? "PASSED" : "BLOCKED", reason: allHashesComplete ? "형식 확인" : "전체 SHA-256 필요", nextActor: allHashesComplete ? undefined : "라벨 운영자" },
              { label: "동결 receipt", state: freezeReceipt !== null ? "PASSED" : "BLOCKED", reason: freezeReceipt ? "서버 receipt 확인" : "아직 생성되지 않음", nextActor: freezeReceipt ? undefined : "라벨 운영자" },
            ]}
          />
          <form
            className="evaluator-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (allSubmitted && allHashesComplete) {
                setError(null);
                setConfirmationOpen(true);
              }
            }}
          >
            {([
              ["export_sha256", "Label export SHA-256"],
              ["rubric_sha256", "Rubric SHA-256"],
              ["source_root_sha256", "Source root SHA-256"],
              ["dev_lineage_sha256", "DEV lineage SHA-256"],
            ] as const).map(([field, label]) => (
              <label className="correction-reason-field" key={field}>
                <span>{label}</span>
                <input
                  autoComplete="off"
                  inputMode="text"
                  maxLength={64}
                  onChange={(event) => setFreezeInput((current) => ({ ...current, [field]: event.target.value }))}
                  pattern="[0-9a-f]{64}"
                  spellCheck={false}
                  value={freezeInput[field]}
                />
              </label>
            ))}
            <button
              className="button button--primary"
              disabled={!allSubmitted || !allHashesComplete || busy}
              ref={freezeTriggerRef}
              type="submit"
            >
              독립 라벨 동결하기
            </button>
          </form>
          {confirmationOpen ? (
            <ConfirmationDialog
              busy={busy}
              confirmLabel="정확한 라벨 집합 동결하기"
              error={error}
              onCancel={closeFreezeConfirmation}
              onConfirm={() => void freeze()}
              returnFocusRef={freezeTriggerRef}
              safeLabel="아직 동결하지 않기"
              title="현재 독립 라벨 집합을 동결할까요?"
            >
              <p>동결은 현재 accepted revision 집합과 정확한 버전을 묶습니다. 모델 후보는 이 영수증이 생성된 뒤에만 만들 수 있습니다.</p>
            </ConfirmationDialog>
          ) : null}
          {freezeReceipt ? (
            <section className="immutable-revision-banner">
              <h2 ref={resultRef} tabIndex={-1}>독립 라벨 동결 영수증</h2>
              <HashBlock label="Receipt SHA-256" value={freezeReceipt.receipt_sha256!} />
              <p>{freezeReceipt.frozen_at}</p>
            </section>
          ) : null}
        </>
      ) : projection ? (
        <>
          <WorkflowStepper
            steps={[
              { label: "제출 상태", state: "COMPLETE" },
              { label: "재검토", state: allAccepted ? "CURRENT" : "BLOCKED", reason: "accepted head 필요" },
              { label: "accepted revision 선택", state: allAccepted ? "COMPLETE" : "CURRENT" },
              { label: "라벨 동결", state: labelExport ? "COMPLETE" : "BLOCKED", reason: "operator capability 전용" },
            ]}
          />
          <button className="button button--secondary" disabled={busy || busyChain !== null} onClick={() => void loadProjection()} type="button">
            최신 projection 다시 확인하기
          </button>
          <AdjudicationComparison projection={projection} busyChain={busyChain} onSelect={(revision, chain) => void selectAcceptedHead(revision, chain)} />
          {projection.review_triggers.length > 0 ? (
            <section className="source-material" aria-labelledby="projection-trigger-title">
              <h2 id="projection-trigger-title">서버 exact trigger</h2>
              <ul>{projection.review_triggers.map((trigger) => <li key={trigger.review_trigger_sha256!}>{triggerLabel(trigger)}</li>)}</ul>
            </section>
          ) : null}
          <GateChecklist
            gates={[
              { label: "세 accepted head", state: allAccepted ? "PASSED" : "BLOCKED", reason: allAccepted ? "현재 tip 선택됨" : "미선택 chain 있음", nextActor: allAccepted ? undefined : "조정자" },
              { label: "숫자 점수 완전성", state: numericCompleteness(projection) ? "PASSED" : "BLOCKED", reason: numericCompleteness(projection) ? "속성별 두 개 이상" : "release 차단 — 숫자 점수가 두 개 이상 필요합니다", nextActor: numericCompleteness(projection) ? undefined : "조정자" },
              { label: "재검토 resolution", state: persistedTriggers.length > 0 && persistedTriggers.every((trigger) => resolvedTriggers.has(trigger.review_trigger_sha256!)) ? "PASSED" : "BLOCKED", reason: "서버 불변 resolution 필요", nextActor: "조정자" },
              { label: "label export", state: labelExport !== null ? "PASSED" : "BLOCKED", reason: labelExport ? "서버 receipt 확인" : "아직 게시되지 않음", nextActor: labelExport ? undefined : "조정자" },
            ]}
          />
          <button className="button button--primary" disabled={!allAccepted || busy || busyChain !== null} onClick={() => void storeTriggers()} type="button">재검토 목록 생성하기</button>
          {persistedTriggers.length > 0 ? (
            <section className="source-material" aria-labelledby="review-trigger-title">
              <h2 id="review-trigger-title">재검토 사유</h2>
              <ul aria-label="재검토 사유">
                {persistedTriggers.map((trigger) => {
                  const digest = trigger.review_trigger_sha256!;
                  const resolved = resolvedTriggers.has(digest);
                  return (
                    <li key={digest}>
                      <p>{triggerLabel(trigger)} · {resolved ? "조정 완료" : "해결 필요"}</p>
                      <label className="correction-reason-field">
                        <span>해결 사유</span>
                        <textarea disabled={resolved} maxLength={500} onChange={(event) => setResolutionReasons((current) => ({ ...current, [digest]: event.target.value }))} value={resolutionReasons[digest] ?? ""} />
                      </label>
                      <button className="button button--secondary" disabled={busy || resolved} onClick={() => void resolveTrigger(trigger)} type="button">재검토 사유 해결</button>
                    </li>
                  );
                })}
              </ul>
            </section>
          ) : null}
          {Object.entries(halfSteps).map(([attributeId, item]) => (
            <fieldset className="attribute-card" key={attributeId}>
              <legend>{attributeId} 반 단계 median 조정</legend>
              <p>서버 재검증 대상 exact median: {item.exactMedian}</p>
              {[item.lower, item.upper].map((value) => (
                <label key={value}><input checked={item.selected === value} name={`adjudication-${attributeId}`} onChange={() => setHalfSteps((current) => ({ ...current, [attributeId]: { ...current[attributeId]!, selected: value } }))} type="radio" /> {value}</label>
              ))}
              <label className="correction-reason-field"><span>조정 사유</span><textarea maxLength={500} onChange={(event) => setHalfSteps((current) => ({ ...current, [attributeId]: { ...current[attributeId]!, reason: event.target.value } }))} value={item.reason} /></label>
            </fieldset>
          ))}
          <button className="button button--primary" disabled={!allAccepted || !numericCompleteness(projection) || busy || busyChain !== null} onClick={() => void publishAggregate()} type="button">조정 결과 revision 게시하기</button>
          {labelExport ? (
            <section className="immutable-revision-banner">
              <h2 ref={resultRef} tabIndex={-1}>불변 label export 생성됨</h2>
              <HashBlock label="Export SHA-256" value={labelExport.export_sha256!} />
              <HashBlock label="Accepted revision set SHA-256" value={labelExport.accepted_revision_set_sha256} />
            </section>
          ) : null}
        </>
      ) : null}
    </main>
  );
}
