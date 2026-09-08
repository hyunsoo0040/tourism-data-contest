export type Execution = {
  schema_version: "mvp-daily-refresh-execution.v1";
  run_date: string;
  execution_sequence: number;
  kind: "SCHEDULED" | "MANUAL_RECOLLECTION";
  command_id: string | null;
  status: string;
  changed_count: number;
  failed_count: number;
  call_count: number;
  available_count?: number | null;
  information_unavailable_count?: number | null;
  event_ended_count?: number | null;
  active_release_sha256: string | null;
  safe_reason: string | null;
  started_at: string;
  updated_at: string;
  finished_at: string | null;
};

export type RecollectionCommand = {
  command_id: string;
  run_date: string;
  status: "REQUESTED" | "CLAIMED" | "SUCCEEDED" | "FAILED" | "REJECTED";
  execution_sequence: number | null;
  safe_reason: string | null;
  requested_at: string;
  claimed_at: string | null;
  finished_at: string | null;
};

export type Overview = {
  latest_execution: Execution | null;
  next_run_at: string;
  active_release_sha256: string | null;
  recollection: { eligible: boolean; safe_reason: string };
  pending_command: RecollectionCommand | null;
};

export type ExcludedPlace = {
  place_id: string;
  content_id: string;
  state: "INFORMATION_UNAVAILABLE" | "EVENT_ENDED";
  safe_reason: string;
  event_end_date: string | null;
  place_name_ko: string | null;
};

export type ExecutionDetail = {
  execution: Execution;
  excluded?: ExcludedPlace[] | null;
  collection_failures: Array<{
    place_id: string;
    operation: "detailCommon2" | "detailIntro2";
    failure_category: string;
    failure_code: string;
    occurred_at: string;
  }>;
  attempts: Array<{
    place_id: string;
    attempt_number: 1 | 2;
    status: "STARTED" | "SUCCEEDED" | "FAILED";
    safe_reason: string | null;
    result_sha256: string | null;
    reserved_at: string;
    finished_at: string | null;
  }>;
};

export const OPERATIONS_REQUEST_TIMEOUT_MS = 10_000;

export class OperationsApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly reason: "http" | "timeout" | "network" | "response" = "http",
  ) {
    super(message);
  }
}

export function operationsErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof OperationsApiError)) return fallback;
  if (error.reason === "timeout") {
    return "운영 API 응답 시간이 초과되었습니다(10초). 새로고침해 다시 확인해 주세요.";
  }
  if (error.reason === "network") {
    return "운영 API에 연결하지 못했습니다. 네트워크 연결을 확인해 주세요.";
  }
  if (error.reason === "response") {
    return "운영 API 응답 형식이 올바르지 않습니다. 배포 이미지와 라우팅을 확인해 주세요.";
  }
  if (error.status === 401) {
    return "인증이 필요하거나 만료되었습니다(HTTP 401). 페이지를 다시 열어 인증해 주세요.";
  }
  if (error.status === 403) {
    return "접근이 거부되었습니다(HTTP 403). 인증과 접근 설정을 확인해 주세요.";
  }
  if (error.status === 404) {
    return "운영 API를 찾을 수 없습니다(HTTP 404). 배포 이미지와 라우팅을 확인해 주세요.";
  }
  if (error.status === 503) {
    return "운영 API를 사용할 수 없습니다(HTTP 503). backend와 migration 상태를 확인해 주세요.";
  }
  return `${fallback} (HTTP ${error.status})`;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  const signal = init?.signal;
  if (signal?.aborted) controller.abort();
  else signal?.addEventListener("abort", cancel, { once: true });
  const timeout = setTimeout(() => controller.abort(), OPERATIONS_REQUEST_TIMEOUT_MS);
  try {
    if (controller.signal.aborted) throw new DOMException("request cancelled", "AbortError");
    const response = await fetch(path, { ...init, signal: controller.signal, cache: "no-store" });
    if (!response.ok) throw new OperationsApiError(response.status, "operations request failed");
    try {
      return (await response.json()) as T;
    } catch (error) {
      if (controller.signal.aborted) throw error;
      throw new OperationsApiError(response.status, "invalid operations response", "response");
    }
  } catch (error) {
    if (signal?.aborted) throw new DOMException("request cancelled", "AbortError");
    if (controller.signal.aborted) {
      throw new OperationsApiError(0, "operations request timed out", "timeout");
    }
    if (error instanceof OperationsApiError) throw error;
    throw new OperationsApiError(0, "operations connection failed", "network");
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", cancel);
  }
}

export function createDailyGlmOperationsClient() {
  const prefix = "/internal/operations/daily-glm/api";
  return {
    overview: (signal?: AbortSignal) => requestJson<Overview>(`${prefix}/overview`, { signal }),
    history: (signal?: AbortSignal) =>
      requestJson<{ executions: Execution[] }>(`${prefix}/history?days=30`, { signal }).then(
        (response) => response.executions,
      ),
    detail: (execution: Execution, signal?: AbortSignal) =>
      requestJson<ExecutionDetail>(
        `${prefix}/history/${execution.run_date}?execution_sequence=${execution.execution_sequence}`,
        { signal },
      ),
    recollect: (runDate: string, idempotencyKey: string, signal?: AbortSignal) =>
      requestJson<RecollectionCommand>(`${prefix}/commands/recollect`, {
        signal,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          schema_version: "mvp-daily-recollection-command-request.v1",
          run_date: runDate,
          idempotency_key: idempotencyKey,
        }),
      }),
    command: (commandId: string, signal?: AbortSignal) =>
      requestJson<RecollectionCommand>(`${prefix}/commands/${commandId}`, { signal }),
  };
}
