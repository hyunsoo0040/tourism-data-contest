import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createDailyGlmOperationsClient,
  OPERATIONS_REQUEST_TIMEOUT_MS,
  OperationsApiError,
  operationsErrorMessage,
} from "./api";

function pendingUntilAborted(signal: AbortSignal) {
  return new Promise<never>((_resolve, reject) => {
    signal.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("daily GLM operations client", () => {
  it("aborts an unanswered request after ten seconds", async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | undefined;
    vi.stubGlobal("fetch", vi.fn((_path: string, init: RequestInit) => {
      signal = init.signal as AbortSignal;
      expect(init.cache).toBe("no-store");
      return pendingUntilAborted(signal);
    }));

    const result = createDailyGlmOperationsClient().overview().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(OPERATIONS_REQUEST_TIMEOUT_MS - 1);
    expect(signal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await result).toMatchObject({ status: 0, reason: "timeout" });
    expect(signal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("keeps the timeout active while reading the response body", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn(async (_path: string, init: RequestInit) => ({
      ok: true,
      json: () => pendingUntilAborted(init.signal as AbortSignal),
    })));

    const result = createDailyGlmOperationsClient().overview().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(OPERATIONS_REQUEST_TIMEOUT_MS);
    expect(await result).toMatchObject({ reason: "timeout" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels on caller abort without treating it as a server timeout", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((_path: string, init: RequestInit) => pendingUntilAborted(init.signal as AbortSignal)));
    const controller = new AbortController();
    const result = createDailyGlmOperationsClient().overview(controller.signal).catch((error: unknown) => error);
    controller.abort();
    expect(await result).toMatchObject({ name: "AbortError" });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not start an already cancelled request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();
    controller.abort();
    await expect(createDailyGlmOperationsClient().overview(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([401, 403, 404, 503, 504])("preserves HTTP %i without reading the error body", async (status) => {
    const json = vi.fn();
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status, json })));
    const error = await createDailyGlmOperationsClient().overview().catch((error: unknown) => error);
    expect(error).toBeInstanceOf(OperationsApiError);
    expect(error).toMatchObject({ status, reason: "http" });
    expect(operationsErrorMessage(error, "운영 요청 실패")).toContain(`HTTP ${status}`);
    expect(json).not.toHaveBeenCalled();
  });

  it("redacts transport errors and malformed response bodies", async () => {
    const privateText = "synthetic-private-provider-content";
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new TypeError(privateText)).mockResolvedValueOnce(
      new Response(privateText, { status: 200 }),
    ));
    const client = createDailyGlmOperationsClient();
    const network = await client.overview().catch((error: unknown) => error);
    const response = await client.overview().catch((error: unknown) => error);
    expect(network).toMatchObject({ reason: "network" });
    expect(response).toMatchObject({ reason: "response" });
    expect(String(network) + String(response)).not.toContain(privateText);
  });

  it("clears the timeout after a successful response", async () => {
    vi.useFakeTimers();
    const payload = { executions: [] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(payload))));
    expect(await createDailyGlmOperationsClient().history()).toEqual([]);
    expect(vi.getTimerCount()).toBe(0);
  });
});
