import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ComponentType } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, expect, test, vi } from "vitest";

const RED_SENTINEL = "PHASE5_RED_COMPARE_NOT_IMPLEMENTED";
const SHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const controlledRedOnly = (
  globalThis as typeof globalThis & {
    __vitest_worker__?: { config?: { testNamePattern?: RegExp } };
  }
).__vitest_worker__?.config?.testNamePattern?.source === "controlled RED sentinel";

type CompareToggleComponent = ComponentType<{
  placeId: string;
  placeName: string;
  selected: boolean;
  disabled: boolean;
  onToggle: (placeId: string) => void;
  maxNoteId: string;
}>;

type CompareTrayComponent = ComponentType<{
  selectedPlaces: Array<{ placeId: string; placeName: string }>;
  announcement: string;
  onRemove: (placeId: string) => void;
  onCompare: () => void;
}>;

type ComparisonTableComponent = ComponentType<{
  placeNames: string[];
  rows: Array<{
    row_id: string;
    label_ko: string;
    values_ko: string[];
    missing_reasons: Array<string | null>;
  }>;
}>;

function memoryStorage() {
  const values = new Map<string, string>();
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
test("selection and tray preserve one bounded same-run release selection", async () => {
  const storageModule = await import("../../app/storage");
  const { CompareToggle } = await importRuntime<{ CompareToggle: CompareToggleComponent }>(
    "./CompareToggle",
  );
  const { CompareTray } = await importRuntime<{ CompareTray: CompareTrayComponent }>(
    "./CompareTray",
  );
  const storage = memoryStorage();
  const now = Date.parse("2026-08-11T00:00:00Z");

  const written = storageModule.writeCompareSelection(
    { runId: "run-current", releaseSha256: SHA, placeIds: ["place-a"] },
    storage,
    now,
  );
  expect(written.state).toBe("persisted");
  expect(storageModule.readCompareSelection("run-current", SHA, storage, now)).toMatchObject({
    state: "valid",
    selection: { place_ids: ["place-a"], run_id: "run-current", release_sha256: SHA },
  });

  const wrongRelease = SHA.replace(/^0/, "1");
  expect(storageModule.readCompareSelection("run-current", wrongRelease, storage, now)).toMatchObject({
    state: "cleared",
    selection: null,
    message: "다른 추천 실행의 비교 선택을 정리했어요.",
  });
  expect(storage.getItem(storageModule.COMPARE_SELECTION_STORAGE_KEY)).toBeNull();

  const onToggle = vi.fn();
  const onRemove = vi.fn();
  const onCompare = vi.fn();
  const { rerender } = render(
    <MemoryRouter>
      <CompareToggle
        placeId="place-a"
        placeName="동궁과 월지"
        selected={false}
        disabled={false}
        onToggle={onToggle}
        maxNoteId="compare-limit-note"
      />
      <CompareTray
        selectedPlaces={[]}
        announcement=""
        onRemove={onRemove}
        onCompare={onCompare}
      />
    </MemoryRouter>,
  );
  expect(
    screen.getByRole("button", { name: "동궁과 월지 비교에 추가" }).getAttribute("aria-pressed"),
  ).toBe("false");
  expect(screen.getByText("비교할 장소 2~3곳을 선택하세요.")).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: "선택한 장소 비교하기" }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "동궁과 월지 비교에 추가" }));
  expect(onToggle).toHaveBeenCalledWith("place-a");

  rerender(
    <MemoryRouter>
      <CompareTray
        selectedPlaces={[{ placeId: "place-a", placeName: "동궁과 월지" }]}
        announcement="동궁과 월지를 비교에 추가했어요."
        onRemove={onRemove}
        onCompare={onCompare}
      />
    </MemoryRouter>,
  );
  expect(screen.getByText("1/3")).toBeTruthy();
  expect(screen.getByText("한 곳을 더 선택하세요.")).toBeTruthy();
  expect(screen.getByRole("status", { name: "비교 선택 알림" }).textContent).toContain(
    "동궁과 월지를 비교에 추가했어요.",
  );

  rerender(
    <MemoryRouter>
      <CompareTray
        selectedPlaces={[
          { placeId: "place-a", placeName: "동궁과 월지" },
          { placeId: "place-b", placeName: "대릉원" },
          { placeId: "place-c", placeName: "첨성대" },
        ]}
        announcement="첨성대를 비교에 추가했어요."
        onRemove={onRemove}
        onCompare={onCompare}
      />
      <CompareToggle
        placeId="place-d"
        placeName="불국사"
        selected={false}
        disabled
        onToggle={onToggle}
        maxNoteId="compare-limit-note"
      />
    </MemoryRouter>,
  );
  expect(screen.getByText("3/3")).toBeTruthy();
  expect(screen.getByText("최대 3곳까지 비교할 수 있어요.").id).toBe("compare-limit-note");
  expect(
    (screen.getByRole("button", { name: "선택한 장소 비교하기" }) as HTMLButtonElement)
      .disabled,
  ).toBe(false);
  const disabledAdd = screen.getByRole("button", { name: "불국사 비교에 추가" });
  expect((disabledAdd as HTMLButtonElement).disabled).toBe(true);
  expect(disabledAdd.getAttribute("aria-describedby")).toBe("compare-limit-note");
  fireEvent.click(screen.getByRole("button", { name: "동궁과 월지 비교에서 빼기" }));
  expect(onRemove).toHaveBeenCalledWith("place-a");
});

test("comparison table uses scoped fixed rows and reasoned missing values", async () => {
  const { ComparisonTable } = await importRuntime<{ ComparisonTable: ComparisonTableComponent }>(
    "./ComparisonTable",
  );
  const rows = [
    { row_id: "fit-score", label_ko: "추천 적합도", values_ko: ["90", "88", "86"], missing_reasons: [null, null, null] },
    {
      row_id: "operating-state",
      label_ko: "운영 정보",
      values_ko: ["정보 없음", "정보 없음", "정보 없음"],
      missing_reasons: [
        "OPERATING_INFORMATION_UNVERIFIED",
        "OPERATING_INFORMATION_UNVERIFIED",
        "OPERATING_INFORMATION_UNVERIFIED",
      ],
    },
  ];
  render(<ComparisonTable placeNames={["동궁과 월지", "대릉원", "첨성대"]} rows={rows} />);

  expect(screen.getByText("선택한 장소 2~3곳 비교", { selector: "caption" })).toBeTruthy();
  expect(screen.getByRole("region", { name: "장소 비교표" }).getAttribute("tabindex")).toBe("0");
  expect(screen.getByRole("columnheader", { name: "동궁과 월지" }).getAttribute("scope")).toBe("col");
  expect(screen.getByRole("columnheader", { name: "첨성대" }).getAttribute("scope")).toBe("col");
  expect(screen.getByRole("rowheader", { name: "추천 적합도" }).getAttribute("scope")).toBe("row");
  expect(screen.getAllByText("정보 없음 — 운영 정보가 확인되지 않았어요.")).toHaveLength(3);
  expect(screen.queryByText(/^-$|^N\/A$|^0$/)).toBeNull();
});

test("compare route rejects an absent or invalid same-run selection with focused recovery", async () => {
  const { ComparePage } = await importRuntime<{ ComparePage: ComponentType }>(
    "../../journey-pages/CompareJourneyPage",
  );
  render(
    <MemoryRouter initialEntries={["/recommendations/run-current/compare"]}>
      <Routes>
        <Route path="/recommendations/:runId/compare" element={<ComparePage />} />
      </Routes>
    </MemoryRouter>,
  );

  const heading = await screen.findByRole("heading", {
    name: "비교할 장소를 다시 선택해 주세요.",
  });
  await waitFor(() => expect(document.activeElement).toBe(heading));
  expect(screen.getByText("같은 추천 실행에서 장소 2~3곳을 다시 선택해 주세요.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "추천 5곳으로 돌아가기" }).getAttribute("href")).toBe(
    "/recommendations/run-current",
  );
});
}
