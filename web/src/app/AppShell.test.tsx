import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { JourneyStepper } from "../components/JourneyStepper";
import { AppShell, useJourneyDraft } from "./AppShell";
import {
  DRAFT_STORAGE_KEY,
  PENDING_PROFILE_SUBMISSION_KEY,
  PROFILE_STORAGE_KEY,
  STORAGE_MESSAGES,
  STORAGE_RETENTION_MS,
  clearPendingProfileSubmission,
  createEmptyDraft,
  readDraft,
  readPendingProfileSubmission,
  readProfileReference,
  resetJourneyStorage,
  writeDraft,
  writePendingProfileSubmission,
  writeProfileReference,
} from "./storage";

function DraftProbe() {
  const { state } = useJourneyDraft();
  return <h1 tabIndex={-1}>저장 상태: {state}</h1>;
}

describe("versioned Phase 1 draft storage", () => {
  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
  });

  it("recovers a whitelisted draft at the exact 30-day boundary", () => {
    const savedAt = Date.UTC(2026, 6, 1);
    writeDraft(createEmptyDraft(), window.localStorage, savedAt);

    const result = readDraft(window.localStorage, savedAt + STORAGE_RETENTION_MS);

    expect(result.state).toBe("recovered");
    expect(result.draft?.questionnaire_version).toBe("questionnaire-v2");
  });

  it("expires a draft after 30 days and leaves the profile key untouched", () => {
    const savedAt = Date.UTC(2026, 6, 1);
    writeDraft(createEmptyDraft(), window.localStorage, savedAt);
    window.localStorage.setItem(PROFILE_STORAGE_KEY, "profile-pointer");

    const result = readDraft(window.localStorage, savedAt + STORAGE_RETENTION_MS + 1);

    expect(result.state).toBe("expired");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBe("profile-pointer");
  });

  it("clears only corrupt draft data and rejects non-whitelisted secret fields", () => {
    window.localStorage.setItem(DRAFT_STORAGE_KEY, "{not-json");
    window.localStorage.setItem(PROFILE_STORAGE_KEY, "profile-pointer");

    expect(readDraft().state).toBe("corrupt");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBe("profile-pointer");
    expect(() =>
      writeDraft({ ...createEmptyDraft(), service_key: "never-store-this" } as never),
    ).toThrow();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it("reports unavailable storage and keeps reset scoped to IT-DA keys", () => {
    const unavailableStorage = {
      getItem: () => {
        throw new DOMException("blocked", "SecurityError");
      },
      setItem: () => {
        throw new DOMException("blocked", "QuotaExceededError");
      },
      removeItem: () => {
        throw new DOMException("blocked", "SecurityError");
      },
    };
    expect(readDraft(unavailableStorage).state).toBe("unavailable");

    window.localStorage.setItem(DRAFT_STORAGE_KEY, "draft");
    window.localStorage.setItem(PROFILE_STORAGE_KEY, "profile");
    window.localStorage.setItem(PENDING_PROFILE_SUBMISSION_KEY, "pending");
    window.localStorage.setItem("another-app", "keep");
    expect(resetJourneyStorage().state).toBe("reset");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY)).toBeNull();
    expect(window.localStorage.getItem("another-app")).toBe("keep");
  });

  it("falls back to memory with the exact warning when the localStorage getter throws", () => {
    const descriptor = Object.getOwnPropertyDescriptor(window, "localStorage");
    const originalStorage = window.localStorage;

    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new DOMException("blocked", "SecurityError");
      },
    });

    try {
      const draftWrite = writeDraft(createEmptyDraft());
      expect(draftWrite).toMatchObject({
        state: "unavailable",
        message: STORAGE_MESSAGES.unavailable,
      });
      expect(readDraft()).toMatchObject({
        state: "unavailable",
        message: STORAGE_MESSAGES.unavailable,
        draft: draftWrite.draft,
      });

      const profileWrite = writeProfileReference("profile-security-error");
      expect(profileWrite).toMatchObject({
        state: "memory-fallback",
        message: STORAGE_MESSAGES.unavailable,
      });
      expect(readProfileReference()).toMatchObject({
        state: "unavailable",
        message: STORAGE_MESSAGES.unavailable,
        profile: profileWrite.profile,
      });
      expect(resetJourneyStorage()).toEqual({
        state: "unavailable",
        message: STORAGE_MESSAGES.unavailable,
      });

      render(
        <MemoryRouter initialEntries={["/start"]}>
          <AppShell>
            <DraftProbe />
          </AppShell>
        </MemoryRouter>,
      );
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: DRAFT_STORAGE_KEY,
          newValue: JSON.stringify(draftWrite.draft),
          storageArea: null,
        }),
      );
      expect(screen.getByRole("status")).toHaveProperty(
        "textContent",
        STORAGE_MESSAGES.unavailable,
      );
    } finally {
      Object.defineProperty(
        window,
        "localStorage",
        descriptor ?? { configurable: true, value: originalStorage },
      );
    }
  });
});

describe("typed profile reference storage", () => {
  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
  });

  it("distinguishes empty and valid profile references", () => {
    const savedAt = Date.UTC(2026, 6, 1);

    expect(readProfileReference()).toEqual({ state: "empty", profile: null });

    const writeResult = writeProfileReference("profile-123", window.localStorage, savedAt);
    expect(writeResult).toMatchObject({ state: "persisted", profile: { profile_id: "profile-123" } });
    expect(readProfileReference(window.localStorage, savedAt + STORAGE_RETENTION_MS)).toEqual({
      state: "valid",
      profile: writeResult.profile,
    });
  });

  it("accepts the generated 160-character profile ID limit and rejects 161 characters", () => {
    const maximumId = "p".repeat(160);
    expect(writeProfileReference(maximumId).profile.profile_id).toBe(maximumId);
    expect(() => writeProfileReference("p".repeat(161))).toThrow();
  });

  it.each([
    ["corrupt", "{not-json"],
    ["incompatible", JSON.stringify({ schema_version: "future-storage-v99" })],
  ] as const)("reports %s data, clears only the profile key, and uses the exact notice", (state, raw) => {
    window.localStorage.setItem(DRAFT_STORAGE_KEY, "keep-this-draft");
    window.localStorage.setItem(PROFILE_STORAGE_KEY, raw);

    expect(readProfileReference()).toEqual({
      state,
      profile: null,
      message: STORAGE_MESSAGES.invalid,
    });
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBe("keep-this-draft");
  });

  it("reports an expired profile and leaves the draft key untouched", () => {
    const savedAt = Date.UTC(2026, 6, 1);
    window.localStorage.setItem(DRAFT_STORAGE_KEY, "keep-this-draft");
    writeProfileReference("profile-expired", window.localStorage, savedAt);

    expect(
      readProfileReference(window.localStorage, savedAt + STORAGE_RETENTION_MS + 1),
    ).toEqual({ state: "expired", profile: null, message: STORAGE_MESSAGES.invalid });
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBe("keep-this-draft");
  });

  it("reports unavailable profile persistence while preserving the in-memory reference", () => {
    const unavailableStorage = {
      getItem: () => {
        throw new DOMException("blocked", "SecurityError");
      },
      setItem: () => {
        throw new DOMException("blocked", "QuotaExceededError");
      },
      removeItem: () => {
        throw new DOMException("blocked", "SecurityError");
      },
    };

    const writeResult = writeProfileReference("profile-memory", unavailableStorage);
    expect(writeResult).toMatchObject({
      state: "memory-fallback",
      message: STORAGE_MESSAGES.unavailable,
    });
    expect(readProfileReference(unavailableStorage)).toEqual({
      state: "unavailable",
      profile: writeResult.profile,
      message: STORAGE_MESSAGES.unavailable,
    });
  });

  it("returns the in-memory profile when persistent storage is readable but has no profile key", () => {
    const blockedWriteStorage = {
      getItem: () => null,
      setItem: () => {
        throw new DOMException("quota", "QuotaExceededError");
      },
      removeItem: () => undefined,
    };
    const writeResult = writeProfileReference("profile-memory-empty-key", blockedWriteStorage);
    expect(writeResult.state).toBe("memory-fallback");

    expect(readProfileReference(window.localStorage)).toEqual({
      state: "unavailable",
      profile: writeResult.profile,
      message: STORAGE_MESSAGES.unavailable,
    });
  });

  it("reports unavailable when invalid profile cleanup fails", () => {
    const removedKeys: string[] = [];
    const cleanupBlockedStorage = {
      getItem: () => "{not-json",
      setItem: () => undefined,
      removeItem: (key: string) => {
        removedKeys.push(key);
        throw new DOMException("blocked", "SecurityError");
      },
    };

    expect(readProfileReference(cleanupBlockedStorage)).toEqual({
      state: "unavailable",
      profile: null,
      message: STORAGE_MESSAGES.unavailable,
    });
    expect(removedKeys).toEqual([PROFILE_STORAGE_KEY]);
  });

  it("persists one pending request per canonical payload fingerprint and clears it by request ID", () => {
    const firstFingerprint = "a".repeat(64);
    const secondFingerprint = "b".repeat(64);
    writePendingProfileSubmission(firstFingerprint, "request-one", window.localStorage);

    expect(readPendingProfileSubmission(firstFingerprint, window.localStorage)).toMatchObject({
      request_id: "request-one",
      payload_sha256: firstFingerprint,
    });
    expect(readPendingProfileSubmission(secondFingerprint, window.localStorage)).toBeNull();
    expect(clearPendingProfileSubmission("different-request", window.localStorage)).toBe(false);
    expect(window.localStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY)).not.toBeNull();
    expect(clearPendingProfileSubmission("request-one", window.localStorage)).toBe(true);
    expect(window.localStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY)).toBeNull();
  });
});

function ResetProbe() {
  const { state, resetDraft, reportStorageUnavailable } = useJourneyDraft();
  return (
    <main>
      <h1 tabIndex={-1}>저장 상태: {state}</h1>
      <button onClick={resetDraft}>초기화</button>
      <button onClick={reportStorageUnavailable}>저장 실패</button>
    </main>
  );
}

describe("초기화 성공 알림 수명", () => {
  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    vi.setSystemTime(new Date("2026-09-08T15:30:00Z"));
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  function renderReset() {
    return render(
      <StrictMode>
        <MemoryRouter initialEntries={["/start"]}>
          <AppShell><ResetProbe /></AppShell>
        </MemoryRouter>
      </StrictMode>,
    );
  }

  it("성공 알림만 4초 후 지우고 storage는 다시 만들지 않는다", () => {
    window.sessionStorage.setItem("itda:grounded-trip:v1", JSON.stringify({ visit_date: null,
      visit_time: null, required_facilities: ["wheelchair_rental"] }));
    writeDraft(createEmptyDraft());
    renderReset();
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    act(() => vi.advanceTimersByTime(3_999));
    expect(screen.getByText(STORAGE_MESSAGES.reset)).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByText(STORAGE_MESSAGES.reset)).toBeNull();
    expect(screen.getByRole("heading").textContent).toBe("저장 상태: normal");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect(window.sessionStorage.getItem("itda:grounded-trip:v1")).toBeNull();
  });

  it("반복 초기화는 마지막 성공부터 4초를 센다", () => {
    renderReset();
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    act(() => vi.advanceTimersByTime(3_000));
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    act(() => vi.advanceTimersByTime(3_999));
    expect(screen.getByText(STORAGE_MESSAGES.reset)).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByText(STORAGE_MESSAGES.reset)).toBeNull();
  });

  it("기존 타이머가 새 저장 실패 경고를 지우지 않는다", () => {
    renderReset();
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    act(() => vi.advanceTimersByTime(1_000));
    fireEvent.click(screen.getByRole("button", { name: "저장 실패" }));
    act(() => vi.advanceTimersByTime(10_000));
    fireEvent(document, new Event("visibilitychange"));
    expect(screen.getByText(STORAGE_MESSAGES.unavailable)).toBeTruthy();
  });

  it("백그라운드에서 타이머가 지연돼도 복귀 시 만료 알림을 지운다", () => {
    renderReset();
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    vi.setSystemTime(new Date("2026-09-08T15:31:00Z"));
    fireEvent(document, new Event("visibilitychange"));
    expect(screen.queryByText(STORAGE_MESSAGES.reset)).toBeNull();
  });

  it("초기화 실패 알림은 자동으로 닫지 않는다", () => {
    renderReset();
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("blocked"); });
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    act(() => vi.advanceTimersByTime(10_000));
    expect(screen.getByText(STORAGE_MESSAGES.unavailable)).toBeTruthy();
    expect(screen.queryByText(STORAGE_MESSAGES.reset)).toBeNull();
  });

  it.each(["corrupt", "expired"])("%s 경고는 성공 알림 타이머 대상이 아니다", (kind) => {
    if (kind === "corrupt") window.localStorage.setItem(DRAFT_STORAGE_KEY, "{invalid");
    else writeDraft(createEmptyDraft(), window.localStorage, Date.now() - STORAGE_RETENTION_MS - 1);
    renderReset();
    act(() => vi.advanceTimersByTime(10_000));
    expect(screen.getByText(STORAGE_MESSAGES.invalid)).toBeTruthy();
  });

  it("unmount 시 성공 알림 타이머와 복귀 리스너를 해제한다", () => {
    const { unmount } = renderReset();
    const schedule = vi.spyOn(window, "setTimeout");
    const cancel = vi.spyOn(window, "clearTimeout");
    const listen = vi.spyOn(document, "addEventListener");
    const remove = vi.spyOn(document, "removeEventListener");
    fireEvent.click(screen.getByRole("button", { name: "초기화" }));
    const timerIndex = schedule.mock.calls.findIndex(([, delay]) => delay === 4_000);
    expect(timerIndex).toBeGreaterThanOrEqual(0);
    const timer = schedule.mock.results[timerIndex]!.value;
    const visibilityListener = listen.mock.calls.find(([name]) => name === "visibilitychange")?.[1];
    expect(visibilityListener).toBeDefined();
    unmount();
    expect(cancel).toHaveBeenCalledWith(timer);
    expect(remove).toHaveBeenCalledWith("visibilitychange", visibilityListener);
  });
});

describe("accessible application shell", () => {
  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
  });

  it("keeps only state and accessibility behavior so each upstream page owns its visual shell", async () => {
    render(
      <MemoryRouter initialEntries={["/start"]}>
        <AppShell>
          <DraftProbe />
        </AppShell>
      </MemoryRouter>,
    );

    await screen.findByRole("heading", { name: "저장 상태: normal" });
    expect(screen.queryByRole("banner")).toBeNull();
    expect(screen.queryByRole("navigation", { name: "여행 진행 단계" })).toBeNull();
    expect(screen.queryByText("이번 경주의 기대를 잇다")).toBeNull();
    expect(document.querySelector(".public-app-shell")?.getAttribute("data-storage-state")).toBe(
      "normal",
    );
    expect(document.querySelectorAll("[data-journey-live-region]")).toHaveLength(2);
    await waitFor(() => expect(document.activeElement?.textContent).toBe("저장 상태: normal"));
  });

  it("marks earlier steps complete without making the stepper interactive", () => {
    render(<JourneyStepper pathname="/profile" />);

    expect(screen.getByRole("listitem", { name: "여행 조건, 완료" })).toBeTruthy();
    expect(screen.getByRole("listitem", { name: "취향, 완료" })).toBeTruthy();
    expect(screen.getByRole("listitem", { name: "기대 프로필" }).getAttribute("aria-current")).toBe(
      "step",
    );
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });
});
