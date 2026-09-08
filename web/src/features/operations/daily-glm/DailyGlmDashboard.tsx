"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  createDailyGlmOperationsClient,
  operationsErrorMessage,
  type Execution,
  type ExecutionDetail,
  type Overview,
  type RecollectionCommand,
} from "./api";

const terminalCommands = new Set(["SUCCEEDED", "FAILED", "REJECTED"]);

function displayTime(value: string | null) {
  if (value === null) return "—";
  return new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Seoul",
  }).format(new Date(value));
}

function shortDigest(value: string | null) {
  return value === null ? "없음" : `${value.slice(0, 12)}…`;
}

function displayCount(value: number | null | undefined) {
  return value == null ? "집계 미확인" : `${value}개`;
}

function AvailabilityCounts({ execution }: { execution: Execution | null }) {
  return (
    <dl className="daily-glm-detail-list">
      <div><dt>수집 가능</dt><dd>{displayCount(execution?.available_count)}</dd></div>
      <div><dt>현재 정보 조회 불가</dt><dd>{displayCount(execution?.information_unavailable_count)}</dd></div>
      <div><dt>행사 종료</dt><dd>{displayCount(execution?.event_ended_count)}</dd></div>
    </dl>
  );
}

function RejectedReleaseNotice({ execution }: { execution: Execution | null }) {
  if (execution?.status !== "RELEASE_REJECTED") return null;
  return <p role="note">이 실행은 새 release를 활성화하지 못했습니다. 기존 활성 release 유지 — 이 실행의 제외 판정 미반영.</p>;
}

function newIdempotencyKey(runDate: string) {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return `recollect-${runDate}-${Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

export function DailyGlmDashboard() {
  const client = useMemo(createDailyGlmOperationsClient, []);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [history, setHistory] = useState<Execution[]>([]);
  const [selected, setSelected] = useState<Execution | null>(null);
  const [detail, setDetail] = useState<ExecutionDetail | null>(null);
  const [command, setCommand] = useState<RecollectionCommand | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const refreshRequest = useRef<AbortController | null>(null);
  const recollectionRequest = useRef<AbortController | null>(null);
  const recollectionKey = useRef<{ runDate: string; key: string } | null>(null);

  const refresh = useCallback(async () => {
    if (refreshRequest.current !== null) return;
    const controller = new AbortController();
    refreshRequest.current = controller;
    setRefreshing(true);
    try {
      const [nextOverview, nextHistory] = await Promise.all([
        client.overview(controller.signal),
        client.history(controller.signal),
      ]);
      if (controller.signal.aborted) return;
      setOverview(nextOverview);
      setHistory(nextHistory);
      setCommand((current) => nextOverview.pending_command ?? current);
      setSelected((current) => {
        if (current !== null) {
          return (
            nextHistory.find(
              (row) =>
                row.run_date === current.run_date &&
                row.execution_sequence === current.execution_sequence,
            ) ?? nextHistory[0] ?? null
          );
        }
        return nextHistory[0] ?? null;
      });
      setError(null);
    } catch (error) {
      if (controller.signal.aborted) return;
      setError(operationsErrorMessage(error, "운영 상태를 불러오지 못했습니다. 다시 시도해 주세요."));
      controller.abort();
    } finally {
      if (refreshRequest.current === controller) {
        refreshRequest.current = null;
        setRefreshing(false);
      }
    }
  }, [client]);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), 30_000);
    return () => {
      window.clearInterval(interval);
      refreshRequest.current?.abort();
      refreshRequest.current = null;
      recollectionRequest.current?.abort();
      recollectionRequest.current = null;
    };
  }, [refresh]);

  useEffect(() => {
    setDetail(null);
    setDetailError(null);
    if (selected === null) return;
    const controller = new AbortController();
    void client
      .detail(selected, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setDetail(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted) {
          setDetailError(operationsErrorMessage(error, "선택한 실행의 상세 정보를 불러오지 못했습니다."));
        }
      });
    return () => controller.abort();
  }, [client, selected]);

  const commandId = command?.command_id;
  const commandPending = command !== null && !terminalCommands.has(command.status);
  useEffect(() => {
    if (commandId === undefined || !commandPending) return;
    const controller = new AbortController();
    let timer: number;
    const poll = async () => {
      let finished = false;
      try {
        const value = await client.command(commandId, controller.signal);
        if (controller.signal.aborted) return;
        setCommand(value);
        setCommandError(null);
        finished = terminalCommands.has(value.status);
        if (finished) void refresh();
      } catch (error) {
        if (!controller.signal.aborted) {
          setCommandError(operationsErrorMessage(error, "재수집 진행 상태를 확인하지 못했습니다."));
        }
      } finally {
        if (!controller.signal.aborted && !finished) timer = window.setTimeout(() => void poll(), 3_000);
      }
    };
    timer = window.setTimeout(() => void poll(), 3_000);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [client, commandId, commandPending, refresh]);

  const recollect = async () => {
    const runDate = overview?.latest_execution?.run_date;
    if (runDate === undefined || recollectionRequest.current !== null) return;
    const controller = new AbortController();
    recollectionRequest.current = controller;
    if (recollectionKey.current?.runDate !== runDate) {
      recollectionKey.current = { runDate, key: newIdempotencyKey(runDate) };
    }
    setBusy(true);
    try {
      const created = await client.recollect(runDate, recollectionKey.current.key, controller.signal);
      if (controller.signal.aborted) return;
      recollectionKey.current = null;
      setCommand(created);
      setConfirming(false);
      setCommandError(null);
      await refresh();
    } catch (error) {
      if (!controller.signal.aborted) {
        setCommandError(`${operationsErrorMessage(error, "재수집 요청 결과를 확인하지 못했습니다.")} 서버에서 접수되었을 수 있으므로 상태를 새로고침해 주세요.`);
      }
    } finally {
      if (recollectionRequest.current === controller) {
        recollectionRequest.current = null;
        setBusy(false);
      }
    }
  };

  return (
    <main className="evaluator-shell daily-glm-dashboard">
      <header className="evaluator-intro">
        <p className="eyebrow">IT-DA · daily operations</p>
        <h1 tabIndex={-1}>Daily GLM 관제</h1>
        <p>PUBLIC-100 TourAPI 수집과 GLM 증분 실행 상태를 안전한 운영 정보로 확인합니다.</p>
        <button className="button button--secondary" disabled={refreshing} onClick={() => void refresh()} type="button">
          새로고침
        </button>
      </header>

      <p aria-live="polite" className="daily-glm-live">
        {error ?? commandError ?? detailError ?? (refreshing ? "운영 상태를 불러오는 중입니다." : "운영 상태가 최신입니다.")}
      </p>

      <section aria-label="최신 실행 요약" className="daily-glm-summary">
        <article><span>상태</span><strong>{overview?.latest_execution?.status ?? "실행 없음"}</strong></article>
        <article><span>다음 실행</span><strong>{displayTime(overview?.next_run_at ?? null)}</strong></article>
        <article><span>입력·상태 변경 / GLM 실패</span><strong>{overview?.latest_execution ? `${overview.latest_execution.changed_count} / ${overview.latest_execution.failed_count}` : "— / —"}</strong></article>
        <article><span>GLM 호출</span><strong>{overview?.latest_execution?.call_count ?? 0} / 200</strong></article>
        <article><span>Active release</span><strong title={overview?.active_release_sha256 ?? undefined}>{shortDigest(overview?.active_release_sha256 ?? null)}</strong></article>
      </section>

      <section className="daily-glm-panel" aria-labelledby="availability-heading">
        <h2 id="availability-heading">최신 수집 판정</h2>
        <AvailabilityCounts execution={overview?.latest_execution ?? null} />
        <p>모집단은 PUBLIC 100개로 유지합니다. 현재 정보 조회 불가는 폐업이나 행사 종료의 증거가 아닙니다.</p>
        <p>입력·상태 변경 수에는 제외 판정 변경도 포함되므로 실제 GLM 분석 장소 수와 다를 수 있습니다.</p>
        <RejectedReleaseNotice execution={overview?.latest_execution ?? null} />
      </section>

      <section className="daily-glm-panel" aria-labelledby="recollection-heading">
        <h2 id="recollection-heading">안전한 즉시 재수집</h2>
        <p>{overview?.recollection.safe_reason ?? "상태 확인 중"}</p>
        {command ? <p>최근 command: <strong>{command.status}</strong>{command.safe_reason ? ` · ${command.safe_reason}` : ""}</p> : null}
        {!confirming ? (
          <button
            className="button button--primary"
            disabled={!overview?.recollection.eligible || busy}
            onClick={() => setConfirming(true)}
            type="button"
          >
            즉시 재수집
          </button>
        ) : (
          <div className="inline-actions" role="group" aria-label="재수집 확인">
            <button className="button button--primary" disabled={busy} onClick={() => void recollect()} type="button">
              {busy ? "요청 중" : "이 날짜를 재수집"}
            </button>
            <button className="button button--secondary" disabled={busy} onClick={() => setConfirming(false)} type="button">취소</button>
          </div>
        )}
      </section>

      <div className="daily-glm-columns">
        <section className="daily-glm-panel" aria-labelledby="history-heading">
          <h2 id="history-heading">최근 30일 실행</h2>
          {history.length === 0 ? <p>기록된 실행이 없습니다.</p> : (
            <div className="daily-glm-history">
              {history.map((execution) => {
                const active = selected?.run_date === execution.run_date && selected.execution_sequence === execution.execution_sequence;
                return (
                  <button
                    aria-pressed={active}
                    className="daily-glm-history__item"
                    key={`${execution.run_date}-${execution.execution_sequence}`}
                    onClick={() => setSelected(execution)}
                    type="button"
                  >
                    <strong>{execution.run_date} · #{execution.execution_sequence}</strong>
                    <span>{execution.kind} · {execution.status}</span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <section className="daily-glm-panel" aria-labelledby="detail-heading">
          <h2 id="detail-heading">실행 상세</h2>
          {detail === null ? <p>실행을 선택하면 상세 정보를 표시합니다.</p> : (
            <>
              <dl className="daily-glm-detail-list">
                <div><dt>시작</dt><dd>{displayTime(detail.execution.started_at)}</dd></div>
                <div><dt>종료</dt><dd>{displayTime(detail.execution.finished_at)}</dd></div>
                <div><dt>안전한 사유</dt><dd>{detail.execution.safe_reason ?? "없음"}</dd></div>
              </dl>
              <AvailabilityCounts execution={detail.execution} />
              <RejectedReleaseNotice execution={detail.execution} />
              <h3>수집 제외 판정</h3>
              <p>선택한 실행에서 수집한 판정입니다. 현재 활성 release의 제외 목록과 다를 수 있습니다.</p>
              {detail.excluded == null || detail.execution.available_count == null || detail.execution.information_unavailable_count == null || detail.execution.event_ended_count == null ? <p>제외 상세 미확인</p> : detail.excluded.length === 0 ? <p>이 실행의 제외 장소가 없습니다.</p> : (
                <ul className="daily-glm-records">
                  {detail.excluded.map((place) => (
                    <li key={place.place_id}>
                      <strong>{place.place_name_ko ?? "이름 미확인"}</strong>
                      <span>{place.state === "EVENT_ENDED" ? "행사 종료" : "현재 정보 조회 불가"} · {place.safe_reason}</span>
                      {place.state === "EVENT_ENDED" && place.event_end_date ? <span>공식 종료일: {place.event_end_date}</span> : null}
                      <code>{place.place_id}</code>
                      <span>TourAPI content ID: {place.content_id}</span>
                    </li>
                  ))}
                </ul>
              )}
              <h3>TourAPI 수집 실패</h3>
              {detail.collection_failures.length === 0 ? <p>기록된 수집 실패가 없습니다.</p> : (
                <ul className="daily-glm-records">
                  {detail.collection_failures.map((failure, index) => (
                    <li key={`${failure.place_id}-${failure.operation}-${index}`}>
                      <strong>{failure.operation}</strong>
                      <span>{failure.failure_category} · {failure.failure_code}</span>
                      <code>{failure.place_id}</code>
                    </li>
                  ))}
                </ul>
              )}
              <h3>GLM attempts</h3>
              {detail.attempts.length === 0 ? <p>GLM 호출 기록이 없습니다.</p> : (
                <ul className="daily-glm-records">
                  {detail.attempts.map((attempt) => (
                    <li key={`${attempt.place_id}-${attempt.attempt_number}`}>
                      <strong>#{attempt.attempt_number} · {attempt.status}</strong>
                      <span>{attempt.safe_reason ?? shortDigest(attempt.result_sha256)}</span>
                      <code>{attempt.place_id}</code>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>
      </div>
    </main>
  );
}
