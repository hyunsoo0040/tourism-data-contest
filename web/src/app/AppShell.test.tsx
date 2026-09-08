import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

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
