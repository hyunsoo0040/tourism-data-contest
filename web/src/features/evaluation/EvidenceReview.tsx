import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  EvaluatorApiError,
  createEvidenceReviewClient,
  type EvidenceCandidate,
  type EvidenceDecision,
  type EvidenceLane,
  type EvidenceReviewChain,
  type EvidenceReviewQueue,
  type ReviewedEvidenceManifest,
} from "./api";
import { InternalRoleHeader } from "./EvaluatorWorkspace";

type CandidateDraft = {
  correctionReason: string;
  decision: EvidenceDecision;
  note: string;
  reasonCode: string;
};

const DECISION_COPY: Record<EvidenceDecision, string> = {
  ACCEPT: "관련 근거로 승인",
  REJECT: "관련 없음으로 거절",
  NOT_CURRENT_SITE: "현재 현장 경험 근거가 아님",
};

const REASON_OPTIONS: Record<EvidenceDecision, Array<{ value: string; label: string }>> = {
  ACCEPT: [
    { value: "DIRECT_CURRENT_SITE_EVIDENCE", label: "현재 장소 경험을 직접 뒷받침함" },
    { value: "RELEVANT_CONTEXT_EVIDENCE", label: "현재 장소 경험의 관련 맥락을 뒷받침함" },
  ],
  REJECT: [
    { value: "IRRELEVANT_TO_CANDIDATE", label: "candidate 주장과 관련 없음" },
    { value: "INSUFFICIENT_CONTEXT", label: "문장만으로 관련성을 확인할 수 없음" },
    { value: "DUPLICATE_WITHOUT_ADDED_EVIDENCE", label: "중복이며 추가 근거가 없음" },
  ],
  NOT_CURRENT_SITE: [
    { value: "HISTORICAL_NOT_CURRENT", label: "과거 정보이며 현재 현장 경험이 아님" },
    { value: "OFF_SITE_CONTEXT", label: "현재 장소 밖의 맥락임" },
  ],
};

function defaultDraft(): CandidateDraft {
  return {
    correctionReason: "",
    decision: "ACCEPT",
    note: "",
    reasonCode: REASON_OPTIONS.ACCEPT[0]!.value,
  };
}

function reviewReason(draft: CandidateDraft): string {
  const note = draft.note.trim();
  return note ? `${draft.reasonCode}: ${note}` : draft.reasonCode;
}

function latestChainIsAccepted(chain: EvidenceReviewChain | undefined): boolean {
  return (
    chain !== undefined &&
    chain.accepted_head?.accepted_review_sha256 === chain.tip_review_sha256
  );
}

function HashValue({ label, value }: { label: string; value: string }) {
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

export function LaneReviewCard({
  candidate,
  chain,
  draft,
  busy,
  onDraftChange,
  onReview,
  onSelectHead,
}: {
  candidate: EvidenceCandidate;
  chain?: EvidenceReviewChain;
  draft: CandidateDraft;
  busy: boolean;
  onDraftChange: (next: CandidateDraft) => void;
  onReview: (correction: boolean) => void;
  onSelectHead: () => void;
}) {
  const isCorrection = chain !== undefined;
  const accepted = latestChainIsAccepted(chain);
  const options = REASON_OPTIONS[draft.decision];

  return (
    <article className="attribute-card" data-candidate-id={candidate.candidate_id}>
      <header>
        <p className="eyebrow">{candidate.lane === "DESCRIPTION" ? "Description" : "Odii"}</p>
        <h3>검토 후보 {candidate.original_order + 1}</h3>
        <p>{accepted ? "현재 accepted review head" : isCorrection ? "correction 또는 head 선택 필요" : "검토 필요"}</p>
      </header>

      <section className="source-material" aria-label="변경할 수 없는 후보 원문">
        <h4>공식 원문 후보</h4>
        <blockquote>{candidate.text}</blockquote>
        <dl>
          <div><dt>Source</dt><dd>{candidate.source_id}</dd></div>
          <div><dt>Lane</dt><dd>{candidate.lane}</dd></div>
          <div><dt>문자 위치</dt><dd>{candidate.start_char}–{candidate.end_char}</dd></div>
          <div><dt>바이트 위치</dt><dd>{candidate.start_byte}–{candidate.end_byte}</dd></div>
          <div><dt>중복 cluster</dt><dd>{candidate.dedup_cluster_id}</dd></div>
        </dl>
        <details>
          <summary>불변 candidate provenance 확인</summary>
          <HashValue label="Candidate SHA-256" value={candidate.candidate_sha256} />
          <HashValue label="Source SHA-256" value={candidate.source_sha256} />
          <HashValue label="Slice SHA-256" value={candidate.slice_sha256} />
          <p>Span: {candidate.span_id}</p>
          <p>서버 순서: {candidate.original_order + 1}</p>
          <p>중복 edge: {candidate.dedup_edges.length > 0 ? candidate.dedup_edges.join(", ") : "없음"}</p>
        </details>
      </section>

      <fieldset className="relevance-options" disabled={busy}>
        <legend>근거 관련성 판단</legend>
        {(Object.keys(DECISION_COPY) as EvidenceDecision[]).map((decision) => (
          <label className="relevance-option" key={decision}>
            <input
              checked={draft.decision === decision}
              name={`decision-${candidate.candidate_id}`}
              onChange={() =>
                onDraftChange({
                  ...draft,
                  decision,
                  reasonCode: REASON_OPTIONS[decision][0]!.value,
                })
              }
              type="radio"
            />{" "}
            {DECISION_COPY[decision]}
          </label>
        ))}
      </fieldset>

      <label className="correction-reason-field">
        <span>닫힌 검수 사유</span>
        <select
          disabled={busy}
          onChange={(event) => onDraftChange({ ...draft, reasonCode: event.target.value })}
          value={draft.reasonCode}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
      </label>
      <label className="correction-reason-field">
        <span>추가 메모 (선택, 300자 이하)</span>
        <textarea
          disabled={busy}
          maxLength={300}
          onChange={(event) => onDraftChange({ ...draft, note: event.target.value })}
          value={draft.note}
        />
      </label>

      {isCorrection ? (
        <label className="correction-reason-field">
          <span>correction 사유 (필수)</span>
          <textarea
            disabled={busy}
            maxLength={300}
            minLength={1}
            onChange={(event) =>
              onDraftChange({ ...draft, correctionReason: event.target.value })
            }
            value={draft.correctionReason}
          />
        </label>
      ) : null}

      <div className="dialog-actions">
        <button
          aria-busy={busy}
          className="button button--primary"
          disabled={busy || (isCorrection && draft.correctionReason.trim().length === 0)}
          onClick={() => onReview(isCorrection)}
          type="button"
        >
          {isCorrection ? "correction review 추가하기" : DECISION_COPY[draft.decision]}
        </button>
        {chain && !accepted ? (
          <button
            aria-busy={busy}
            className="button button--secondary"
            disabled={busy}
            onClick={onSelectHead}
            type="button"
          >
            현재 review를 accepted head로 선택
          </button>
        ) : null}
      </div>

      {chain ? (
        <section aria-label="append-only review history" className="immutable-revision-banner">
          <h4>불변 review 이력</h4>
          <ol>
            {chain.revisions.map((revision) => (
              <li key={revision.review_sha256!}>
                <strong>{DECISION_COPY[revision.decision]}</strong> · {revision.reason}
                {revision.correction_reason ? ` · correction: ${revision.correction_reason}` : ""}
                <HashValue label="Review SHA-256" value={revision.review_sha256!} />
              </li>
            ))}
          </ol>
          <HashValue label="Chain SHA-256" value={chain.chain_sha256} />
        </section>
      ) : null}
    </article>
  );
}

export function ReviewedEvidencePreview({ manifest }: { manifest: ReviewedEvidenceManifest }) {
  return (
    <section aria-labelledby="reviewed-manifest-title" className="immutable-revision-banner">
      <h2 id="reviewed-manifest-title">검수 완료 manifest</h2>
      <p>후보 원문이나 모델 target 없이 release 연결용 lane 상태와 전체 hash만 표시합니다.</p>
      <HashValue label="Reviewed manifest SHA-256" value={manifest.manifest_sha256!} />
      <HashValue label="Candidate manifest SHA-256" value={manifest.candidate_manifest_sha256} />
      <HashValue label="Accepted review set SHA-256" value={manifest.accepted_review_set_sha256} />
      <ul>
        {manifest.lanes.map((lane) => (
          <li key={lane.lane}>
            <strong>{lane.lane === "DESCRIPTION" ? "Description" : "Odii"}</strong> ·{" "}
            {lane.status === "MISSING"
              ? "자료 없음 (MISSING) · 검증된 upstream 사유"
              : `승인 근거 ${lane.evidence.length}개 (최대 3개)`}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function EvidenceReview({
  onAuthorizationLost,
}: {
  onAuthorizationLost?: () => void;
} = {}) {
  const [queue, setQueue] = useState<EvidenceReviewQueue | null>(null);
  const [chains, setChains] = useState<Record<string, EvidenceReviewChain>>({});
  const [drafts, setDrafts] = useState<Record<string, CandidateDraft>>({});
  const [manifest, setManifest] = useState<ReviewedEvidenceManifest | null>(null);
  const [busyCandidate, setBusyCandidate] = useState<string | null>(null);
  const [busyFinalize, setBusyFinalize] = useState(false);
  const [accessDenied, setAccessDenied] = useState(false);
  const [message, setMessage] = useState("evidence reviewer 권한과 candidate manifest를 확인하고 있습니다.");
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const resultRef = useRef<HTMLHeadingElement>(null);

  const clearSensitiveState = useCallback(() => {
    setQueue(null);
    setChains({});
    setDrafts({});
    setManifest(null);
    setBusyCandidate(null);
    setBusyFinalize(false);
  }, []);

  const securityBoundary = useCallback(() => {
    clearSensitiveState();
    setAccessDenied(true);
    setError("이 역할은 이 자료를 볼 수 없습니다. 허용된 작업 화면으로 돌아가세요.");
    onAuthorizationLost?.();
  }, [clearSensitiveState, onAuthorizationLost]);

  const client = useMemo(
    () => createEvidenceReviewClient({ onSecurityBoundary: securityBoundary }),
    [securityBoundary],
  );

  const refreshChain = useCallback(
    async (candidateManifestSha256: string, candidateId: string) => {
      const chain = await client.getChain(candidateManifestSha256, candidateId);
      setChains((current) => ({ ...current, [candidateId]: chain }));
      return chain;
    },
    [client],
  );

  useEffect(() => {
    setAccessDenied(false);
    setError(null);
    const load = async () => {
      try {
        const nextQueue = await client.getQueue();
        setQueue(nextQueue);
        setDrafts(
          Object.fromEntries(
            nextQueue.lanes.flatMap((lane) =>
              lane.candidates.map((candidate) => [candidate.candidate_id, defaultDraft()]),
            ),
          ),
        );
        const candidates = nextQueue.lanes.flatMap((lane) => lane.candidates);
        await Promise.all(
          candidates.map(async (candidate) => {
            try {
              await refreshChain(nextQueue.candidate_manifest_sha256, candidate.candidate_id);
            } catch (chainError) {
              if (!(chainError instanceof EvaluatorApiError) || chainError.status !== 404) {
                throw chainError;
              }
            }
          }),
        );
        setMessage("최신 immutable candidate와 own review chain을 확인했습니다.");
        requestAnimationFrame(() => headingRef.current?.focus());
      } catch (loadError) {
        if (
          loadError instanceof EvaluatorApiError &&
          (loadError.status === 401 || loadError.status === 403)
        ) {
          return;
        }
        clearSensitiveState();
        setError("현재 상태를 확인하지 못했습니다. 입력은 변경되지 않았습니다. 다시 시도하기 전에 서버 상태와 최신 receipt를 확인하세요.");
      }
    };
    void load();
    return () => {
      client.clear();
      clearSensitiveState();
    };
  }, [clearSensitiveState, client, refreshChain]);

  useEffect(() => {
    if (manifest === null) return;
    const frame = requestAnimationFrame(() => resultRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [manifest]);

  useEffect(() => {
    if (error === null) return;
    const frame = requestAnimationFrame(() => errorRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [error]);

  const appendReview = useCallback(
    async (candidate: EvidenceCandidate, correction: boolean) => {
      if (!queue) return;
      const draft = drafts[candidate.candidate_id] ?? defaultDraft();
      const chain = chains[candidate.candidate_id];
      setBusyCandidate(candidate.candidate_id);
      setError(null);
      try {
        if (correction && chain) {
          await client.correct(candidate.candidate_id, chain.tip_review_sha256, {
            candidate_manifest_sha256: queue.candidate_manifest_sha256,
            candidate_sha256: candidate.candidate_sha256,
            correction_reason: draft.correctionReason.trim(),
            decision: draft.decision,
            lane: candidate.lane,
            reason: reviewReason(draft),
          });
        } else {
          await client.review(candidate.candidate_id, {
            candidate_manifest_sha256: queue.candidate_manifest_sha256,
            candidate_sha256: candidate.candidate_sha256,
            decision: draft.decision,
            lane: candidate.lane,
            reason: reviewReason(draft),
          });
        }
        await refreshChain(queue.candidate_manifest_sha256, candidate.candidate_id);
        setDrafts((current) => ({ ...current, [candidate.candidate_id]: defaultDraft() }));
        setMessage("append-only review receipt와 최신 chain을 확인했습니다.");
      } catch (reviewError) {
        setError(reviewError instanceof EvaluatorApiError ? reviewError.message : "review를 게시하지 못했습니다.");
      } finally {
        setBusyCandidate(null);
      }
    },
    [chains, client, drafts, queue, refreshChain],
  );

  const selectHead = useCallback(
    async (candidate: EvidenceCandidate) => {
      if (!queue) return;
      const chain = chains[candidate.candidate_id];
      if (!chain) return;
      setBusyCandidate(candidate.candidate_id);
      setError(null);
      try {
        await client.selectAcceptedHead(chain.tip_review_sha256, {
          candidate_id: candidate.candidate_id,
          candidate_manifest_sha256: queue.candidate_manifest_sha256,
          candidate_sha256: candidate.candidate_sha256,
          expected_chain_sha256: chain.chain_sha256,
          lane: candidate.lane,
          selection_reason: "현재 immutable candidate와 review chain tip을 대조해 선택함",
        });
        await refreshChain(queue.candidate_manifest_sha256, candidate.candidate_id);
        setMessage("accepted review head의 append-only receipt를 확인했습니다.");
      } catch (headError) {
        setError(headError instanceof EvaluatorApiError ? headError.message : "accepted head를 선택하지 못했습니다.");
        if (headError instanceof EvaluatorApiError && headError.status === 409) {
          await refreshChain(queue.candidate_manifest_sha256, candidate.candidate_id).catch(
            () => undefined,
          );
        }
      } finally {
        setBusyCandidate(null);
      }
    },
    [chains, client, queue, refreshChain],
  );

  const allCandidatesAccepted =
    queue !== null &&
    queue.lanes.every(
      (lane) =>
        lane.status === "MISSING" ||
        lane.candidates.every((candidate) => latestChainIsAccepted(chains[candidate.candidate_id])),
    );

  const finalize = useCallback(async () => {
    if (!queue) return;
    setBusyFinalize(true);
    setError(null);
    try {
      const nextManifest = await client.finalize({
        candidate_manifest_sha256: queue.candidate_manifest_sha256,
      });
      setManifest(nextManifest);
      setMessage("불변 reviewed-evidence manifest receipt를 확인했습니다.");
    } catch (finalizeError) {
      setError(finalizeError instanceof EvaluatorApiError ? finalizeError.message : "manifest를 만들지 못했습니다.");
    } finally {
      setBusyFinalize(false);
    }
  }, [client, queue]);

  const exitRole = useCallback(() => {
    client.clear();
    clearSensitiveState();
    onAuthorizationLost?.();
  }, [clearSensitiveState, client, onAuthorizationLost]);

  if (accessDenied) {
    return (
      <main className="evaluator-shell evaluator-shell--forbidden">
        <h1 ref={headingRef} tabIndex={-1}>이 역할은 이 자료를 볼 수 없습니다.</h1>
        <p>권한이 바뀌어 candidate, review chain, manifest, 요청, 브라우저 저장소를 모두 지웠습니다.</p>
      </main>
    );
  }

  return (
    <main className="evaluator-shell" data-evaluation-role="evidence-reviewer">
      <InternalRoleHeader
        onExit={onAuthorizationLost === undefined ? undefined : exitRole}
        roleLabel="Evidence reviewer"
      />
      <header className="evaluator-intro">
        <p className="eyebrow">Phase 3 · 모델 후보와 사람 검수 분리</p>
        <h1 ref={headingRef} tabIndex={-1}>Description/Odii 근거 검수</h1>
        <p>동결된 candidate의 관련성만 판단합니다. 원문, 위치, 점수, 순서, provenance는 바꿀 수 없습니다.</p>
      </header>
      <p aria-live="polite" className="async-status" role="status">{message}</p>
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

      {queue ? (
        <>
          <section aria-labelledby="candidate-lineage-title" className="source-material">
            <h2 id="candidate-lineage-title">불변 candidate run provenance</h2>
            <HashValue label="Candidate manifest SHA-256" value={queue.candidate_manifest_sha256} />
            <HashValue label="Candidate output SHA-256" value={queue.provenance.candidate_output_sha256} />
            <HashValue label="Source manifest SHA-256" value={queue.provenance.source_manifest_sha256} />
            <dl>
              <div><dt>Model</dt><dd>{queue.provenance.model_id} @ {queue.provenance.model_revision}</dd></div>
              <div><dt>Data version</dt><dd>{queue.provenance.data_version}</dd></div>
              <div><dt>Prompt/anchor</dt><dd>{queue.provenance.prompt_anchor_version}</dd></div>
              <div><dt>Preprocessing</dt><dd>{queue.provenance.preprocessing_version}</dd></div>
              <div><dt>Scoring</dt><dd>{queue.provenance.scoring_version}</dd></div>
              <div><dt>계산 완료</dt><dd>{queue.provenance.completed_at}</dd></div>
            </dl>
          </section>

          <nav aria-label="근거 검수 단계" className="rubric-anchor-panel">
            <ol>
              {queue.lanes.map((lane) => {
                const complete =
                  lane.status === "MISSING" ||
                  lane.candidates.every((candidate) =>
                    latestChainIsAccepted(chains[candidate.candidate_id]),
                  );
                return (
                  <li key={lane.lane} aria-current={!complete ? "step" : undefined}>
                    <strong>{lane.lane === "DESCRIPTION" ? "Description 검수" : "Odii 검수"}</strong>{" "}
                    {complete ? "완료" : "현재 단계"}
                  </li>
                );
              })}
              <li aria-current={allCandidatesAccepted ? "step" : undefined}>
                <strong>완전성 확인</strong> {manifest ? "완료" : allCandidatesAccepted ? "현재 단계" : "아직 진행할 수 없음"}
              </li>
            </ol>
          </nav>

          {queue.lanes.map((lane) => {
            const reviewed = lane.candidates.filter((candidate) =>
              latestChainIsAccepted(chains[candidate.candidate_id]),
            ).length;
            return (
              <section aria-labelledby={`lane-${lane.lane}`} key={lane.lane}>
                <h2 id={`lane-${lane.lane}`} tabIndex={-1}>
                  {lane.lane === "DESCRIPTION" ? "Description" : "Odii"} lane
                </h2>
                {lane.status === "MISSING" ? (
                  <div className="immutable-revision-banner">
                    <strong>자료 없음 (MISSING)</strong>
                    <p>검증된 upstream source/rights 상태입니다. evidence나 0으로 바꿀 수 없습니다.</p>
                  </div>
                ) : lane.candidates.length === 0 ? (
                  <div className="immutable-revision-banner">
                    <h3>검수할 candidate가 없습니다</h3>
                    <p>라벨 동결과 candidate run 상태를 확인하세요. 완료되지 않은 입력을 임의로 만들지 않습니다.</p>
                  </div>
                ) : (
                  <>
                    <p>검토 완료 {reviewed} · 남음 {lane.candidates.length - reviewed} · 서버 원래 순서 유지</p>
                    <details open>
                      <summary>검토 후보 {lane.candidates.length}개</summary>
                      {lane.candidates.map((candidate) => (
                        <LaneReviewCard
                          busy={busyCandidate !== null}
                          candidate={candidate}
                          chain={chains[candidate.candidate_id]}
                          draft={drafts[candidate.candidate_id] ?? defaultDraft()}
                          key={candidate.candidate_id}
                          onDraftChange={(next) =>
                            setDrafts((current) => ({ ...current, [candidate.candidate_id]: next }))
                          }
                          onReview={(correction) => void appendReview(candidate, correction)}
                          onSelectHead={() => void selectHead(candidate)}
                        />
                      ))}
                    </details>
                  </>
                )}
              </section>
            );
          })}

          <button
            aria-busy={busyFinalize}
            className="button button--primary"
            disabled={!allCandidatesAccepted || busyFinalize || busyCandidate !== null}
            onClick={() => void finalize()}
            type="button"
          >
            현재 lane 검수 완료하기
          </button>
          {!allCandidatesAccepted ? (
            <p>모든 AVAILABLE candidate의 현재 review chain tip을 accepted head로 선택해야 합니다.</p>
          ) : null}
          {manifest ? (
            <div>
              <h2 ref={resultRef} tabIndex={-1}>불변 reviewed-evidence manifest 생성됨</h2>
              <ReviewedEvidencePreview manifest={manifest} />
            </div>
          ) : null}
        </>
      ) : error ? null : (
        <section aria-label="loading" className="source-material">
          <p>candidate manifest를 불러오는 중입니다.</p>
        </section>
      )}
    </main>
  );
}
