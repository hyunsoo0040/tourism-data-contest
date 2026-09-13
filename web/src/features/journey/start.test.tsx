import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider, type RouteObject } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TripConditionForm } from "./TripConditionForm";
import { tripConditionsSchema } from "../../app/schemas";

import {
  DRAFT_STORAGE_KEY,
  STORAGE_MESSAGES,
  createEmptyDraft,
  writeDraft,
} from "../../app/storage";

const shellStyles = readFileSync(resolve(process.cwd(), "src/app/styles/internal.css"), "utf8");

async function loadStartRoutes(): Promise<RouteObject[]> {
  try {
    const routeModulePath = "../../app/routes";
    const module = await import(/* @vite-ignore */ routeModulePath);
    return module.appRoutes;
  } catch {
    throw new Error("Expected the /start route and trip-condition form to be implemented");
  }
}

async function renderStart(initialEntry = "/start") {
  const appRoutes = await loadStartRoutes();
  const router = createMemoryRouter(appRoutes, { initialEntries: [initialEntry] });
  render(<RouterProvider router={router} />);
  await screen.findByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" });
  expect(screen.queryByRole("region", { name: "기능 선택" })).toBeNull();
  return router;
}

function completeRequiredChoices() {
  fireEvent.click(screen.getByRole("radio", { name: "아직 미정" }));
  fireEvent.click(screen.getByRole("radio", { name: "혼자" }));
  fireEvent.click(screen.getByRole("radio", { name: "도보·대중교통" }));
  fireEvent.click(screen.getByRole("radio", { name: "30분 이내로 가볍게" }));
  fireEvent.click(screen.getByRole("radio", { name: "상관없어요" }));
  fireEvent.click(screen.getByRole("radio", { name: "조금 피하고 싶어요" }));
}

describe("/start current-trip form", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(2026, 8, 9, 0, 30));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("offers four companion choices for a new trip", async () => {
    await renderStart();
    const companion = screen.getByRole("group", { name: "동행" });
    expect(within(companion).getAllByRole("radio").map((radio) => (radio as HTMLInputElement).value))
      .toEqual(["SOLO", "FRIEND_OR_PARTNER", "FAMILY_WITH_CHILDREN", "WITH_SENIORS"]);
  });

  it("preserves a retired companion selection until the user chooses a current option", async () => {
    writeDraft({ ...createEmptyDraft(), trip_conditions: { companion: "GROUP" }, answers: { q1: 2 } });
    const original = window.localStorage.getItem(DRAFT_STORAGE_KEY);
    await renderStart();
    expect((screen.getByRole("radio", { name: "여럿이 (이전 선택)" }) as HTMLInputElement).checked).toBe(true);
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBe(original);
    fireEvent.click(screen.getByRole("radio", { name: "친구" }));
    expect(screen.queryByRole("radio", { name: "여럿이 (이전 선택)" })).toBeNull();
    expect((screen.getByRole("radio", { name: "친구" }) as HTMLInputElement).checked).toBe(true);
  });

  it("오늘 기본값과 최소 날짜를 저장 없이 표시한다", async () => {
    await renderStart();
    const input = screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement;
    expect(input.value).toBe("2026-09-09");
    expect(input.min).toBe("2026-09-09");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it.each(["/start", "/start?mode=edit"])("%s에서 과거 날짜의 직접 제출을 차단한다", async (entry) => {
    const router = await renderStart(entry);
    const input = screen.getByLabelText("방문 날짜 (선택)");
    fireEvent.change(input, { target: { value: "2026-09-08" } });
    completeRequiredChoices();
    fireEvent.submit(document.getElementById("trip-condition-form")!);
    const summary = await screen.findByRole("alert");
    await waitFor(() => expect(document.activeElement).toBe(input));
    summary.focus();
    fireEvent.click(within(summary).getByRole("link", { name: "오늘 또는 이후 날짜를 선택해 주세요." }));
    await waitFor(() => expect(document.activeElement).toBe(input));
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe("visit_date-error");
    expect(router.state.location.pathname).toBe("/start");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it.each(["2026-09-09", ""])("오늘 또는 명시적으로 지운 날짜 %s를 제출한다", async (value) => {
    const router = await renderStart();
    fireEvent.change(screen.getByLabelText("방문 날짜 (선택)"), { target: { value } });
    completeRequiredChoices();
    fireEvent.submit(document.getElementById("trip-condition-form")!);
    await waitFor(() => expect(router.state.location.pathname).toBe("/quiz"));
    const stored = JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY)!);
    expect(stored.trip_conditions.visit_date).toBe(value || null);
  });

  it.each([
    [null, "2026-09-09"],
    ["2026-09-08", "2026-09-09"],
    ["2026-10-03", "2026-10-03"],
  ])("복원 날짜 %s의 표시만 보정하고 다른 조건과 원문을 보존한다", async (value, expected) => {
    writeDraft({
      ...createEmptyDraft(),
      trip_conditions: { visit_date: value, companion: "SOLO" },
      answers: { q1: 2 },
    });
    const original = window.localStorage.getItem(DRAFT_STORAGE_KEY);
    await renderStart();
    expect((screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement).value).toBe(expected);
    expect((screen.getByRole("radio", { name: "혼자" }) as HTMLInputElement).checked).toBe(true);
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBe(original);
  });

  it("자정을 넘겨 제출할 때 오늘을 다시 검증한다", async () => {
    const router = await renderStart();
    completeRequiredChoices();
    vi.setSystemTime(new Date(2026, 8, 10, 0, 1));
    fireEvent.submit(document.getElementById("trip-condition-form")!);
    await screen.findByRole("alert");
    expect((screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement).min).toBe("2026-09-10");
    expect(router.state.location.pathname).toBe("/start");
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it("창과 탭 복귀 시 최소 날짜만 갱신하고 입력값은 보존한다", async () => {
    await renderStart();
    const input = screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement;
    vi.setSystemTime(new Date(2026, 8, 10, 1));
    fireEvent(window, new Event("focus"));
    expect(input.min).toBe("2026-09-10");
    expect(input.value).toBe("2026-09-09");
    vi.setSystemTime(new Date(2026, 8, 11, 1));
    fireEvent(document, new Event("visibilitychange"));
    expect(input.min).toBe("2026-09-11");
    expect(input.value).toBe("2026-09-09");
  });

  it("announces linked Korean validation errors and stays on /start", async () => {
    const router = await renderStart();

    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));

    const summary = await screen.findByRole("alert");
    expect(within(summary).getByText("방문 시간을 선택해 주세요.")).toBeTruthy();
    expect(within(summary).getByText("동행을 선택해 주세요.")).toBeTruthy();
    for (const link of within(summary).getAllByRole("link")) {
      const targetId = link.getAttribute("href")?.slice(1);
      expect(targetId).toBeTruthy();
      expect(document.getElementById(targetId ?? "")).toBeTruthy();
    }
    expect(router.state.location.pathname).toBe("/start");
  });

  it("persists generated-contract enum values and routes to /quiz with question state", async () => {
    const router = await renderStart();
    fireEvent.change(screen.getByLabelText("방문 날짜 (선택)"), {
      target: { value: "2026-10-03" },
    });
    completeRequiredChoices();

    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));

    await waitFor(() => expect(router.state.location.pathname).toBe("/quiz"));
    expect(router.state.location).toMatchObject({ search: "", hash: "", state: { questionOrdinal: 1 } });
    expect(router.state.location.search).not.toContain("SOLO");
    const stored = JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
      trip_conditions: Record<string, unknown>;
      questionnaire_version: string;
    };
    expect(stored.questionnaire_version).toBe("questionnaire-v2");
    expect(stored.trip_conditions).toEqual({
      visit_date: "2026-10-03",
      visit_time: "UNDECIDED",
      companion: "SOLO",
      transport: "WALK_OR_TRANSIT",
      walking_tolerance: "WITHIN_30_MINUTES",
      indoor_outdoor_preference: "NO_PREFERENCE",
      crowd_avoidance: "MEDIUM",
    });
  });

  it("restores a valid draft and dismisses the recovery notice without clearing values", async () => {
    writeDraft({
      ...createEmptyDraft(),
      trip_conditions: {
        visit_date: null,
        visit_time: "MORNING",
        companion: "FRIEND_OR_PARTNER",
      },
    });

    await renderStart();
    expect(await screen.findByText(STORAGE_MESSAGES.recovered)).toBeTruthy();
    expect((screen.getByRole("radio", { name: "오전" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("radio", { name: "친구" }) as HTMLInputElement).checked).toBe(
      true,
    );

    fireEvent.click(screen.getByRole("button", { name: "계속 작성하기" }));

    expect(screen.queryByText(STORAGE_MESSAGES.recovered)).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).not.toBeNull();
  });

  it("announces corrupt storage recovery without exposing the malformed payload", async () => {
    window.localStorage.setItem(DRAFT_STORAGE_KEY, "{secret-looking-corrupt-data");

    await renderStart();

    expect(await screen.findByRole("status")).toHaveProperty(
      "textContent",
      STORAGE_MESSAGES.invalid,
    );
    expect(screen.queryByText("secret-looking-corrupt-data")).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it("keeps restored data on cancel and clears it only after reset confirmation", async () => {
    writeDraft({
      ...createEmptyDraft(),
      trip_conditions: { visit_time: "DAYTIME", companion: "SOLO" },
    });
    await renderStart();

    const resetTrigger = screen.getByRole("button", { name: "처음부터 시작하기" });
    fireEvent.click(resetTrigger);
    expect(screen.getByRole("dialog", { name: "작성한 내용을 지울까요?" })).toBeTruthy();
    expect(document.activeElement?.textContent).toBe("계속 작성하기");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).not.toBeNull();
    expect(document.activeElement).toBe(resetTrigger);

    fireEvent.click(resetTrigger);
    fireEvent.click(screen.getByRole("button", { name: "모두 지우고 새로 시작하기" }));

    await screen.findByText(STORAGE_MESSAGES.reset);
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect((screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement).value).toBe("2026-09-09");
  });
});

describe("날짜 폼 경계", () => {
  const conditions = {
    visit_date: "2026-09-09", visit_time: "UNDECIDED", companion: "SOLO",
    transport: "WALK_OR_TRANSIT", walking_tolerance: "WITHIN_30_MINUTES",
    indoor_outdoor_preference: "NO_PREFERENCE", crowd_avoidance: "MEDIUM",
  } as const;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 8, 9, 23, 59, 59));
  });
  afterEach(() => vi.useRealTimers());

  function renderForm(visit_date = conditions.visit_date as string) {
    const onSubmit = vi.fn();
    const view = render(<TripConditionForm
      defaultValues={{ ...conditions, visit_date }} recovered={false}
      onDismissRecovery={vi.fn()} onReset={() => true} onSubmit={onSubmit}
    />);
    return { ...view, onSubmit };
  }

  it("열린 폼의 자정 최소 날짜를 갱신하고 unmount에서 타이머를 정리한다", () => {
    const { unmount } = renderForm();
    const input = screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement;
    expect(input.min).toBe("2026-09-09");
    act(() => vi.advanceTimersByTime(1_000));
    expect(input.min).toBe("2026-09-10");
    expect(input.value).toBe("2026-09-09");
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("잘못된 날짜 형식도 resolver 오류로 반환한다", async () => {
    const { onSubmit } = renderForm("invalid-date");
    await act(async () => fireEvent.submit(document.getElementById("trip-condition-form")!));
    expect(screen.getByRole("alert").textContent).toContain("올바른 방문 날짜를 입력해 주세요.");
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("저장된 과거 여행 조건은 여전히 읽을 수 있다", () => {
    expect(tripConditionsSchema.safeParse({ ...conditions, visit_date: "2020-01-01" }).success).toBe(true);
  });
});

describe("mobile action and error-summary CSS contracts", () => {
  it("keeps the primary action fixed at 320x568 with safe-area and document clearance", () => {
    expect(shellStyles).toMatch(
      /\.start-action-bar\s*\{[^}]*position:\s*fixed[^}]*right:\s*0[^}]*bottom:\s*0[^}]*left:\s*0[^}]*\}/s,
    );
    expect(shellStyles).toMatch(
      /\.start-action-bar\s*\{[^}]*env\(safe-area-inset-bottom\)[^}]*\}/s,
    );
    expect(shellStyles).toMatch(
      /\.start-page\s*\{[^}]*padding-bottom:\s*calc\([^}]*safe-area-inset-bottom[^}]*\)[^}]*\}/s,
    );
    expect(shellStyles).not.toMatch(/overflow-x:\s*(?:clip|hidden)/);
    expect(shellStyles).toMatch(/\*\s*\{[^}]*box-sizing:\s*border-box[^}]*\}/s);
    expect(shellStyles).toMatch(
      /\.start-action-bar \.button\s*\{[^}]*width:\s*100%[^}]*max-width:\s*720px[^}]*margin-inline:\s*auto[^}]*\}/s,
    );
  });

  it("returns the action to document flow for constrained-height or zoomed layouts", () => {
    expect(shellStyles).toMatch(
      /@media\s*\(min-width:\s*768px\),\s*\(max-height:\s*480px\)[\s\S]*?\.start-action-bar\s*\{[^}]*position:\s*static[^}]*\}/,
    );
  });

  it("gives every error-summary anchor a 44px target", () => {
    expect(shellStyles).toMatch(
      /\.error-summary a\s*\{[^}]*display:\s*inline-flex[^}]*min-height:\s*44px[^}]*align-items:\s*center[^}]*\}/s,
    );
  });
});
