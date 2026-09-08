import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DailyGlmDashboard } from "./DailyGlmDashboard";

const execution = {
  schema_version: "mvp-daily-refresh-execution.v1",
  run_date: "2026-09-06",
  execution_sequence: 0,
  kind: "SCHEDULED",
  command_id: null,
  status: "COLLECTION_INCOMPLETE",
  changed_count: 0,
  failed_count: 0,
  call_count: 0,
  active_release_sha256: null,
  safe_reason: "TOUR_API_COLLECTION_FAILED",
  started_at: "2026-09-05T23:00:00Z",
  updated_at: "2026-09-05T23:01:00Z",
  finished_at: "2026-09-05T23:01:00Z",
};

function response(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

describe("DailyGlmDashboard", () => {
  beforeEach(() => {
    vi.stubGlobal("crypto", { getRandomValues: (bytes: Uint8Array) => bytes.fill(1) });
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders overview, history and safe execution detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const path = String(input);
        if (path.endsWith("/overview")) {
          return response({
            latest_execution: execution,
            next_run_at: "2026-09-06T23:00:00Z",
            active_release_sha256: "a".repeat(64),
            recollection: { eligible: true, safe_reason: "RECOLLECTION_ALLOWED" },
            pending_command: null,
          });
        }
        if (path.includes("/history/2026-09-06")) {
          return response({
            execution,
            collection_failures: [
              {
                place_id: `public:gyeongju:${"1".repeat(64)}`,
                operation: "detailIntro2",
                failure_category: "PROVIDER_TRANSPORT",
                failure_code: "PROVIDER_UNAVAILABLE",
                occurred_at: "2026-09-05T23:01:00Z",
              },
            ],
            attempts: [],
          });
        }
        return response({ executions: [execution] });
      }),
    );

    render(<DailyGlmDashboard />);

    expect(await screen.findByText("COLLECTION_INCOMPLETE")).toBeTruthy();
    expect(screen.getByText("0 / 200")).toBeTruthy();
    expect(
      await screen.findByText("PROVIDER_TRANSPORT · PROVIDER_UNAVAILABLE"),
    ).toBeTruthy();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "즉시 재수집" }).disabled).toBe(false);
  });

  it.each([
    { unknown: undefined, excluded: undefined },
    { unknown: null, excluded: null },
    { unknown: null, excluded: [] },
  ])("keeps missing or null availability counts unknown ($unknown, $excluded)", async ({ unknown, excluded }) => {
    const legacy = {
      ...execution,
      available_count: unknown,
      information_unavailable_count: unknown,
      event_ended_count: unknown,
    };
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/overview")) return response({
        latest_execution: legacy, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: null,
        recollection: { eligible: false, safe_reason: "COLLECTION_INCOMPLETE" }, pending_command: null,
      });
      if (path.includes("/history/")) return response({
        execution: legacy, collection_failures: [], attempts: [], excluded,
      });
      return response({ executions: [legacy] });
    }));
    render(<DailyGlmDashboard />);
    expect(await screen.findByText("제외 상세 미확인")).toBeTruthy();
    const summary = within(screen.getByRole("region", { name: "최신 수집 판정" }));
    expect(summary.getAllByText("집계 미확인")).toHaveLength(3);
    expect(summary.queryByText("0개")).toBeNull();
    expect(screen.queryByText("이 실행의 제외 장소가 없습니다.")).toBeNull();
  });

  it.each(["RELEASE_ACTIVATED", "RELEASE_REJECTED"])("distinguishes exclusions from GLM failures for %s", async (status) => {
    const observed = {
      ...execution, status, safe_reason: status === "RELEASE_REJECTED" ? "INSUFFICIENT_PROFILES" : null,
      changed_count: 3, failed_count: 1, call_count: 2,
      available_count: 98, information_unavailable_count: 1, event_ended_count: 1,
    };
    const excluded = [
      { place_id: `public:gyeongju:${"1".repeat(64)}`, content_id: "101", state: "INFORMATION_UNAVAILABLE",
        safe_reason: "COMMON_INFORMATION_UNAVAILABLE", event_end_date: null, place_name_ko: "합성 조회 불가 장소",
        raw_body: "synthetic-private-body", source_url: "https://example.invalid/?serviceKey=private" },
      { place_id: `public:gyeongju:${"2".repeat(64)}`, content_id: "102", state: "EVENT_ENDED",
        safe_reason: "OFFICIAL_EVENT_END_DATE_PASSED", event_end_date: "2026-09-05", place_name_ko: "합성 종료 행사" },
    ];
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/overview")) return response({
        latest_execution: observed, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: "a".repeat(64),
        recollection: { eligible: false, safe_reason: "SNAPSHOT_ALREADY_RECORDED" }, pending_command: null,
      });
      if (path.includes("/history/")) return response({
        execution: observed, collection_failures: [], attempts: [], excluded,
      });
      return response({ executions: [observed] });
    }));
    render(<DailyGlmDashboard />);
    expect(await screen.findByText("합성 조회 불가 장소")).toBeTruthy();
    expect(screen.getByText("합성 종료 행사")).toBeTruthy();
    expect(screen.getByText("공식 종료일: 2026-09-05")).toBeTruthy();
    const summary = within(screen.getByRole("region", { name: "최신 수집 판정" }));
    expect(summary.getByText("98개")).toBeTruthy();
    expect(summary.getAllByText("1개")).toHaveLength(2);
    expect(screen.getByText("입력·상태 변경 / GLM 실패")).toBeTruthy();
    expect(screen.getByText("3 / 1")).toBeTruthy();
    expect(screen.getByText("2 / 200")).toBeTruthy();
    expect(screen.queryByText(/synthetic-private-body|serviceKey|example.invalid/)).toBeNull();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "즉시 재수집" }).disabled).toBe(true);
    if (status === "RELEASE_REJECTED") {
      expect(summary.getByRole("note").textContent).toContain("제외 판정 미반영");
    } else {
      expect(summary.queryByRole("note")).toBeNull();
    }
  });

  it("shows confirmed zero exclusions without inventing missing counts", async () => {
    const complete = { ...execution, status: "NO_CHANGES", available_count: 100,
      information_unavailable_count: 0, event_ended_count: 0 };
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/overview")) return response({
        latest_execution: complete, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: null,
        recollection: { eligible: false, safe_reason: "NO_CHANGES" }, pending_command: null,
      });
      if (path.includes("/history/")) return response({ execution: complete, excluded: [], collection_failures: [], attempts: [] });
      return response({ executions: [complete] });
    }));
    render(<DailyGlmDashboard />);
    expect(await screen.findByText("이 실행의 제외 장소가 없습니다.")).toBeTruthy();
    const summary = within(screen.getByRole("region", { name: "최신 수집 판정" }));
    expect(summary.getByText("100개")).toBeTruthy();
    expect(summary.getAllByText("0개")).toHaveLength(2);
    expect(summary.queryByText("집계 미확인")).toBeNull();
  });

  it("requires confirmation and sends a bounded recollection request", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/overview")) {
        return response({
          latest_execution: execution,
          next_run_at: "2026-09-06T23:00:00Z",
          active_release_sha256: null,
          recollection: { eligible: true, safe_reason: "RECOLLECTION_ALLOWED" },
          pending_command: null,
        });
      }
      if (path.endsWith("/commands/recollect")) {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toMatchObject({
          schema_version: "mvp-daily-recollection-command-request.v1",
          run_date: "2026-09-06",
        });
        return response({
          command_id: "12345678-1234-4234-9234-123456789abc",
          run_date: "2026-09-06",
          status: "REQUESTED",
          execution_sequence: null,
          safe_reason: null,
          requested_at: "2026-09-06T08:00:00Z",
          claimed_at: null,
          finished_at: null,
        }, 202);
      }
      if (path.includes("/history/2026-09-06")) {
        return response({ execution, collection_failures: [], attempts: [] });
      }
      return response({ executions: [execution] });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<DailyGlmDashboard />);
    fireEvent.click(await screen.findByRole("button", { name: "즉시 재수집" }));
    expect(screen.getByRole("button", { name: "이 날짜를 재수집" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "이 날짜를 재수집" }));

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([path]) => String(path).endsWith("/commands/recollect"))).toBe(true);
    });
  });

  it("disables recollection when the database projection is ineligible", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const path = String(input);
        if (path.endsWith("/overview")) {
          return response({
            latest_execution: execution,
            next_run_at: "2026-09-06T23:00:00Z",
            active_release_sha256: null,
            recollection: {
              eligible: false,
              safe_reason: "MANUAL_RECOLLECTION_LIMIT_REACHED",
            },
            pending_command: null,
          });
        }
        if (path.includes("/history/2026-09-06")) {
          return response({ execution, collection_failures: [], attempts: [] });
        }
        return response({ executions: [execution] });
      }),
    );

    render(<DailyGlmDashboard />);

    expect(await screen.findByText("MANUAL_RECOLLECTION_LIMIT_REACHED")).toBeTruthy();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "즉시 재수집" }).disabled).toBe(true);
  });

  it("ends loading on timeout, prevents duplicate refreshes and allows recovery", async () => {
    vi.useFakeTimers();
    let recovering = false;
    const signals: AbortSignal[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (recovering) {
        return String(input).endsWith("/overview")
          ? response({ latest_execution: null, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: null,
            recollection: { eligible: false, safe_reason: "NO_EXECUTION_AVAILABLE" }, pending_command: null })
          : response({ executions: [] });
      }
      const signal = init?.signal as AbortSignal;
      signals.push(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<DailyGlmDashboard />);
    const refreshButton = screen.getByRole<HTMLButtonElement>("button", { name: "새로고침" });
    expect(refreshButton.disabled).toBe(true);
    fireEvent.click(refreshButton);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(screen.getByText(/응답 시간이 초과되었습니다\(10초\)/)).toBeTruthy();
    expect(screen.queryByText("운영 상태를 불러오는 중입니다.")).toBeNull();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    expect(refreshButton.disabled).toBe(false);
    recovering = true;
    await act(async () => { fireEvent.click(refreshButton); });
    expect(screen.getByText("운영 상태가 최신입니다.")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("shows a bounded HTTP error and cancels the other refresh request", async () => {
    let historySignal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/overview")) return response("synthetic-private-body", 504);
      historySignal = init?.signal as AbortSignal;
      return new Promise<Response>((_resolve, reject) => {
        historySignal?.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
      });
    }));
    render(<DailyGlmDashboard />);
    expect(await screen.findByText(/HTTP 504/)).toBeTruthy();
    expect(historySignal?.aborted).toBe(true);
    expect(screen.queryByText(/synthetic-private-body/)).toBeNull();
  });

  it("cancels pending requests on unmount", () => {
    const signals: AbortSignal[] = [];
    vi.stubGlobal("fetch", vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const signal = init?.signal as AbortSignal;
      signals.push(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
      });
    }));
    const { unmount } = render(<DailyGlmDashboard />);
    unmount();
    expect(signals).toHaveLength(2);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });

  it("polls commands without overlap and recovers from polling errors", async () => {
    vi.useFakeTimers();
    const pendingCommand = {
      command_id: "12345678-1234-4234-9234-123456789abc", run_date: execution.run_date,
      status: "REQUESTED", execution_sequence: null, safe_reason: null,
      requested_at: execution.started_at, claimed_at: null, finished_at: null,
    };
    let resolvePoll!: (value: Response) => void;
    let pollCount = 0;
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/overview")) return response({
        latest_execution: null, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: null,
        recollection: { eligible: false, safe_reason: "COMMAND_ALREADY_PENDING" },
        pending_command: pollCount >= 2 ? null : pendingCommand,
      });
      if (path.includes("/commands/")) {
        pollCount += 1;
        if (pollCount === 1) return new Promise<Response>((resolve) => { resolvePoll = resolve; });
        return response({ ...pendingCommand, status: "REJECTED", safe_reason: "STATE_CHANGED" });
      }
      return response({ executions: [] });
    }));
    await act(async () => { render(<DailyGlmDashboard />); });
    await act(async () => { await vi.advanceTimersByTimeAsync(9_000); });
    expect(pollCount).toBe(1);
    await act(async () => { resolvePoll(new Response("private", { status: 503 })); });
    expect(screen.getByText(/HTTP 503/)).toBeTruthy();
    await act(async () => { await vi.advanceTimersByTimeAsync(3_000); });
    expect(pollCount).toBe(2);
    expect(screen.getByText("REJECTED")).toBeTruthy();
    expect(screen.queryByText(/HTTP 503/)).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(9_000); });
    expect(pollCount).toBe(2);
  });

  it("reuses the same idempotency key when a timed-out recollection is retried", async () => {
    vi.useFakeTimers();
    let randomCalls = 0;
    vi.stubGlobal("crypto", { getRandomValues: (bytes: Uint8Array) => bytes.fill(++randomCalls) });
    const submittedKeys: string[] = [];
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/overview")) return response({
        latest_execution: execution, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: null,
        recollection: { eligible: true, safe_reason: "RECOLLECTION_ALLOWED" }, pending_command: null,
      });
      if (path.endsWith("/commands/recollect")) {
        submittedKeys.push(JSON.parse(String(init?.body)).idempotency_key);
        if (submittedKeys.length === 1) {
          return new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
          });
        }
        return response({
          command_id: "12345678-1234-4234-9234-123456789abc", run_date: execution.run_date,
          status: "REQUESTED", execution_sequence: null, safe_reason: null,
          requested_at: execution.started_at, claimed_at: null, finished_at: null,
        }, 202);
      }
      if (path.includes("/history/")) return response({ execution, collection_failures: [], attempts: [] });
      return response({ executions: [execution] });
    }));
    await act(async () => { render(<DailyGlmDashboard />); });
    fireEvent.click(screen.getByRole("button", { name: "즉시 재수집" }));
    fireEvent.click(screen.getByRole("button", { name: "이 날짜를 재수집" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(screen.getByText(/서버에서 접수되었을 수 있으므로/)).toBeTruthy();
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "이 날짜를 재수집" })); });
    expect(submittedKeys).toHaveLength(2);
    expect(submittedKeys[1]).toBe(submittedKeys[0]);
    expect(randomCalls).toBe(1);
    expect(screen.getByText("REQUESTED")).toBeTruthy();
  });
});
