import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ComponentType } from "react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, test, vi } from "vitest";

import type { SavedPlaceProjection } from "../../api/api";

const RED_SENTINEL = "PHASE5_RED_SAVED_PLACE_NOT_IMPLEMENTED";
const RELEASE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OLD_RELEASE = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const controlledRedOnly = (
  globalThis as typeof globalThis & {
    __vitest_worker__?: { config?: { testNamePattern?: RegExp } };
  }
).__vitest_worker__?.config?.testNamePattern?.source === "controlled RED sentinel";

type SavedReference = {
  schema_version: "phase5-saved-place-v1";
  place_id: string;
  release_sha256: string;
  saved_at: string;
};

type SaveToggleComponent = ComponentType<{
  placeId: string;
  placeName: string;
  selected: boolean;
  onToggle: (placeId: string) => void;
}>;

type SavedSectionComponent = ComponentType<{
  references: SavedReference[];
  cleanupNotice?: string;
  onRemove: (reference: SavedReference) => void;
  resolveReference?: (releaseSha256: string, placeId: string) => Promise<SavedPlaceProjection>;
}>;

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    },
    removeItem(key: string) {
      values.delete(key);
    },
  };
}

function importRuntime<T>(moduleName: string): Promise<T> {
  return import(/* @vite-ignore */ moduleName) as Promise<T>;
}

function reference(
  placeId: string,
  releaseSha256 = RELEASE,
  savedAt = "2026-08-11T00:00:00.000Z",
): SavedReference {
  return {
    schema_version: "phase5-saved-place-v1",
    place_id: placeId,
    release_sha256: releaseSha256,
    saved_at: savedAt,
  };
}

beforeEach(() => {
  window.localStorage.clear();
});

if (controlledRedOnly) {
  test("controlled RED sentinel", () => {
    process.stdout.write(`${RED_SENTINEL}\n`);
    throw new Error(RED_SENTINEL);
  });
}

if (!controlledRedOnly) {
  test("save control and storage use place-specific aria-pressed labels and identity-only records", async () => {
    const storageModule = await import("../../app/storage");
    const { SaveToggle } = await importRuntime<{ SaveToggle: SaveToggleComponent }>("./SaveToggle");
    const storage = memoryStorage();
    const now = Date.parse("2026-08-11T00:00:00Z");

    const saved = storageModule.writeSavedPlaceReference(
      { placeId: "place-a", releaseSha256: RELEASE },
      storage,
      now,
    );
    expect(saved.state).toBe("persisted");
    expect(saved.reference).toEqual(reference("place-a"));
    expect(Object.keys(saved.reference).sort()).toEqual([
      "place_id",
      "release_sha256",
      "saved_at",
      "schema_version",
    ]);
    expect(JSON.stringify(saved.reference)).not.toMatch(
      /score|evidence|excerpt|body|html|path|secret|photo/i,
    );

    const savedAgain = storageModule.writeSavedPlaceReference(
      { placeId: "place-a", releaseSha256: RELEASE },
      storage,
      now + 1_000,
    );
    expect(savedAgain.references).toHaveLength(1);
    expect(savedAgain.reference.saved_at).toBe(saved.reference.saved_at);

    const onToggle = vi.fn();
    const { rerender } = render(
      <SaveToggle
        placeId="place-a"
        placeName="동궁과 월지"
        selected={false}
        onToggle={onToggle}
      />,
    );
    const save = screen.getByRole("button", { name: "동궁과 월지 저장" });
    expect(save.getAttribute("aria-pressed")).toBe("false");
    expect(save.textContent).toBe("동궁과 월지 저장");
    fireEvent.click(save);
    expect(onToggle).toHaveBeenCalledWith("place-a");

    rerender(
      <SaveToggle
        placeId="place-a"
        placeName="동궁과 월지"
        selected
        onToggle={onToggle}
      />,
    );
    expect(screen.getByRole("button", { name: "동궁과 월지 저장됨" }).getAttribute("aria-pressed"))
      .toBe("true");
  });

  test("saved section renders current, stale, unavailable, empty, and removable states", async () => {
    const { SavedSection } = await importRuntime<{ SavedSection: SavedSectionComponent }>(
      "./SavedSection",
    );
    const onRemove = vi.fn();
    const refs = [reference("place-current"), reference("place-stale", OLD_RELEASE), reference("place-missing", OLD_RELEASE)];
    const resolveReference = vi.fn(async (releaseSha256: string, placeId: string) => {
      const state = placeId === "place-current" ? "CURRENT" : placeId === "place-stale" ? "STALE" : "UNAVAILABLE";
      return {
        place_id: placeId,
        place_name_ko:
          placeId === "place-current" ? "첨성대" : placeId === "place-stale" ? "대릉원" : "저장된 장소",
        saved_release_sha256: releaseSha256,
        resolved_release_sha256: state === "UNAVAILABLE" ? null : releaseSha256,
        state,
        state_reason: state === "CURRENT" ? null : state === "STALE" ? "SAVED_RELEASE_IS_NOT_ACTIVE" : "SAVED_RELEASE_OR_PLACE_UNAVAILABLE",
      } satisfies SavedPlaceProjection;
    });

    const { rerender } = render(
      <MemoryRouter>
        <SavedSection
          references={refs}
          onRemove={onRemove}
          resolveReference={resolveReference}
        />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: "저장한 장소" })).toBeTruthy();
    expect(await screen.findByText("첨성대")).toBeTruthy();
    expect(screen.getByText("현재 저장 릴리스에서 확인했어요.")).toBeTruthy();
    expect(screen.getByText("저장 당시 릴리스는 현재 공개 기준이 아니에요.")).toBeTruthy();
    expect(screen.getByText("저장 당시 정보를 확인할 수 없어요.")).toBeTruthy();
    expect(resolveReference).toHaveBeenCalledWith(OLD_RELEASE, "place-stale");
    expect(resolveReference).toHaveBeenCalledWith(OLD_RELEASE, "place-missing");

    fireEvent.click(screen.getByRole("button", { name: "대릉원 저장에서 삭제" }));
    expect(onRemove).toHaveBeenCalledWith(refs[1]);

    // The resolver chain settles in microtasks; drain it inside act so the
    // resulting setRows update stays inside React's scheduler under load
    // (same synchronization pattern as the Phase 6 photo suite).
    await act(async () => {});

    rerender(
      <MemoryRouter>
        <SavedSection references={[]} onRemove={onRemove} resolveReference={resolveReference} />
      </MemoryRouter>,
    );
    await act(async () => {});
    expect(screen.getByRole("heading", { name: "아직 저장한 장소가 없어요." })).toBeTruthy();
    expect(screen.getByText("추천 카드에서 저장하면 이 브라우저에서 다시 볼 수 있어요.")).toBeTruthy();
  });

  test("saved section retains references on temporary resolver failure and isolates cleanup notice", async () => {
    const { SavedSection } = await importRuntime<{ SavedSection: SavedSectionComponent }>(
      "./SavedSection",
    );
    const onRemove = vi.fn();
    const kept = reference("place-kept");
    render(
      <MemoryRouter>
        <SavedSection
          references={[kept]}
          cleanupNotice="일부 저장 정보를 읽지 못했어요. 읽을 수 없는 저장 항목만 정리했어요."
          onRemove={onRemove}
          resolveReference={async () => {
            throw new Error("temporary network failure");
          }}
        />
      </MemoryRouter>,
    );

    expect(
      await screen.findByText("지금은 저장 정보를 불러올 수 없어요. 저장 항목은 그대로 유지됩니다."),
    ).toBeTruthy();
    await act(async () => {});
    expect(screen.getByText("일부 저장 정보를 읽지 못했어요. 읽을 수 없는 저장 항목만 정리했어요.")).toBeTruthy();
    expect(onRemove).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "place-kept 저장에서 삭제" })).toBeTruthy();
  });

  test("saved resolver rejects active-pointer rebinding and accepts the exact historical release", async () => {
    const { RecommendationContractError, resolveSavedPlaceReference } = await import("../../api/api");
    const stalePayload = {
      place_id: "place-stale",
      place_name_ko: "대릉원",
      saved_release_sha256: OLD_RELEASE,
      resolved_release_sha256: OLD_RELEASE,
      state: "STALE",
      state_reason: "SAVED_RELEASE_IS_NOT_ACTIVE",
    };
    const accepted = await resolveSavedPlaceReference(OLD_RELEASE, "place-stale", {
      fetchImpl: async () => new Response(JSON.stringify(stalePayload), { status: 200 }),
    });
    expect(accepted).toEqual(stalePayload);

    await expect(
      resolveSavedPlaceReference(OLD_RELEASE, "place-stale", {
        fetchImpl: async () =>
          new Response(
            JSON.stringify({
              ...stalePayload,
              state: "CURRENT",
              resolved_release_sha256: RELEASE,
              state_reason: null,
            }),
            { status: 200 },
          ),
      }),
    ).rejects.toBeInstanceOf(RecommendationContractError);
  });
}
