import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ComponentType, ReactNode } from "react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import { afterEach, expect, test, vi } from "vitest";

const RED_SENTINEL = "PHASE5_RED_RECOVERY_ACCESSIBILITY_NOT_IMPLEMENTED";
const controlledRedOnly = (
  globalThis as typeof globalThis & {
    __vitest_worker__?: { config?: { testNamePattern?: RegExp } };
  }
).__vitest_worker__?.config?.testNamePattern?.source === "controlled RED sentinel";

type StatePageComponent = ComponentType<{
  state: string;
  onPrimary?: () => void;
}>;

type JourneyStepperComponent = ComponentType<{ pathname: string }>;

type AppShellComponent = ComponentType<{ children?: ReactNode }>;

type JourneyAnnouncements = {
  announcePage: (message: string) => void;
  announceInteraction: (message: string) => void;
};

function importRuntime<T>(moduleName: string): Promise<T> {
  return import(/* @vite-ignore */ moduleName) as Promise<T>;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

if (controlledRedOnly) {
  test("controlled RED sentinel", () => {
    process.stdout.write(`${RED_SENTINEL}\n`);
    throw new Error(RED_SENTINEL);
  });
}

if (!controlledRedOnly) {
  test("closed recommendation states preserve exact code copy action role and unknown fallback", async () => {
    const { RecommendationStatePage } = await importRuntime<{
      RecommendationStatePage: StatePageComponent;
    }>("./RecommendationStatePage");
    const onPrimary = vi.fn();
    const matrix = [
      [
        "loading",
        "내 취향에 맞는 여행지 5곳을 고르고 있어요.",
        null,
        "status",
      ],
      [
        "NO_ACTIVE_SCORED_RELEASE",
        "추천 준비가 아직 끝나지 않았어요.",
        "추천 준비 다시 확인",
        "status",
      ],
      [
        "INSUFFICIENT_ELIGIBLE_CANDIDATES",
        "추천 5곳을 만들지 못했어요.",
        "추천 준비 다시 확인",
        "status",
      ],
      [
        "RECOVERABLE_API_FAILURE",
        "추천을 불러오지 못했어요.",
        "다시 시도하기",
        "alert",
      ],
      [
        "RECOMMENDATION_RUN_NOT_FOUND",
        "이 추천 결과를 다시 확인할 수 없어요.",
        "기대 프로필로 돌아가기",
        "status",
      ],
      [
        "RECOMMENDATION_PIN_INVALID",
        "이 추천 결과를 다시 확인할 수 없어요.",
        "기대 프로필로 돌아가기",
        "status",
      ],
      [
        "RECOMMENDATION_PLACE_UNAVAILABLE",
        "이 추천 결과를 다시 확인할 수 없어요.",
        "기대 프로필로 돌아가기",
        "status",
      ],
      [
        "COMPARE_SELECTION_INVALID",
        "비교할 장소를 다시 선택해 주세요.",
        "추천 5곳으로 돌아가기",
        "status",
      ],
      [
        "COMPARE_API_FAILURE",
        "비교 정보를 불러오지 못했어요.",
        "다시 시도하기",
        "alert",
      ],
      [
        "SERVER_ADDED_UNKNOWN_STATE",
        "추천 상태를 확인하지 못했어요.",
        "다시 시도하기",
        "alert",
      ],
    ] as const;

    const view = render(
      <RecommendationStatePage state={matrix[0][0]} onPrimary={onPrimary} />,
    );
    for (const [state, heading, action, liveRole] of matrix) {
      view.rerender(
        <RecommendationStatePage state={state} onPrimary={onPrimary} />,
      );
      const headingNode = screen.getByRole("heading", { name: heading });
      await waitFor(() => expect(document.activeElement).toBe(headingNode));
      const article = headingNode.closest("article");
      expect(article?.getAttribute("data-status")).toBe(
        state === "SERVER_ADDED_UNKNOWN_STATE" ? "UNKNOWN_RECOMMENDATION_STATE" : state,
      );
      if (liveRole === "alert") {
        expect(article?.getAttribute("role")).toBe("alert");
      } else {
        expect(article?.getAttribute("role")).toBeNull();
        expect(screen.getByRole("status")).toBeTruthy();
      }
      if (action === null) {
        expect(screen.queryByRole("button")).toBeNull();
      } else {
        const button = screen.getByRole("button", { name: action });
        fireEvent.click(button);
      }
    }
    expect(onPrimary).toHaveBeenCalledTimes(9);
    expect(document.querySelectorAll("[data-recommendation-card]")).toHaveLength(0);
  });

  test("all recommendation child routes map to the fourth non-interactive journey step", async () => {
    const { JourneyStepper } = await importRuntime<{
      JourneyStepper: JourneyStepperComponent;
    }>("../../components/JourneyStepper");
    const routes = [
      "/recommendations/run-current",
      "/recommendations/run-current/places/place-current",
      "/recommendations/run-current/compare",
    ];
    const view = render(<JourneyStepper pathname={routes[0]} />);
    for (const pathname of routes) {
      view.rerender(<JourneyStepper pathname={pathname} />);
      const steps = screen.getAllByRole("listitem");
      expect(steps).toHaveLength(4);
      expect(screen.getByRole("listitem", { name: "여행 조건, 완료" })).toBeTruthy();
      expect(screen.getByRole("listitem", { name: "취향, 완료" })).toBeTruthy();
      expect(screen.getByRole("listitem", { name: "기대 프로필, 완료" })).toBeTruthy();
      expect(screen.getByRole("listitem", { name: "추천" }).getAttribute("aria-current")).toBe(
        "step",
      );
      expect(screen.queryAllByRole("link")).toHaveLength(0);
    }
  });

  test("public route changes focus h1 and expose only two bounded live sentences", async () => {
    const { AppShell, useJourneyAnnouncements } = await importRuntime<{
      AppShell: AppShellComponent;
      useJourneyAnnouncements: () => JourneyAnnouncements | null;
    }>("../../app/AppShell");

    function Probe() {
      const navigate = useNavigate();
      const announcements = useJourneyAnnouncements();
      return (
        <main>
          <article>
            <h1 tabIndex={-1}>첫 추천 결과</h1>
            <button
              type="button"
              onClick={() => {
                announcements?.announcePage("새 상세 정보를 준비했어요.");
                announcements?.announceInteraction("동궁과 월지를 저장했어요.");
                navigate("/recommendations/run-current/places/place-current");
              }}
            >
              상세로 이동
            </button>
          </article>
        </main>
      );
    }

    render(
      <MemoryRouter initialEntries={["/recommendations/run-current"]}>
        <Routes>
          <Route path="*" element={<AppShell><Probe /></AppShell>} />
        </Routes>
      </MemoryRouter>,
    );
    const firstHeading = await screen.findByRole("heading", { name: "첫 추천 결과" });
    await waitFor(() => expect(document.activeElement).toBe(firstHeading));
    fireEvent.click(screen.getByRole("button", { name: "상세로 이동" }));
    await waitFor(() => expect(document.activeElement).toBe(firstHeading));
    const regions = document.querySelectorAll("[data-journey-live-region]");
    expect(regions).toHaveLength(2);
    expect(regions[0]?.textContent).toBe("새 상세 정보를 준비했어요.");
    expect(regions[1]?.textContent).toBe("동궁과 월지를 저장했어요.");
    expect(regions[0]?.getAttribute("aria-atomic")).toBe("true");
    expect(regions[1]?.getAttribute("aria-atomic")).toBe("true");
  });

  test("compare invalid recovery is focused and does not create success output", async () => {
    const { ComparePage } = await importRuntime<{
      ComparePage: ComponentType;
    }>("../../journey-pages/CompareJourneyPage");
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
    expect(heading.closest("[data-status]")?.getAttribute("data-status")).toBe(
      "COMPARE_SELECTION_INVALID",
    );
    expect(screen.getByRole("link", { name: "추천 5곳으로 돌아가기" })).toBeTruthy();
    expect(document.querySelector("[data-status='success']")).toBeNull();
  });

  test.each([
    "RECOMMENDATION_RUN_NOT_FOUND",
    "RECOMMENDATION_PIN_INVALID",
  ] as const)("compare treats %s as terminal recovery", async (code) => {
    const storageModule = await importRuntime<typeof import("../../app/storage")>(
      "../../app/storage",
    );
    const releaseSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    storageModule.writeCompareSelection({
      runId: "run-terminal",
      releaseSha256,
      placeIds: ["place-a", "place-b"],
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            detail: {
              code,
              message_ko: "terminal",
              preference_profile_id: "profile-terminal",
              release_id: "release-terminal",
              request_id: "request-terminal",
            },
          }),
          { status: 404, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const { ComparePage } = await importRuntime<{
      ComparePage: ComponentType;
    }>("../../journey-pages/CompareJourneyPage");
    render(
      <MemoryRouter initialEntries={["/recommendations/run-terminal/compare"]}>
        <Routes>
          <Route path="/recommendations/:runId/compare" element={<ComparePage />} />
          <Route path="/profile" element={<p>profile recovery</p>} />
        </Routes>
      </MemoryRouter>,
    );

    const heading = await screen.findByRole("heading", {
      name: "이 추천 결과를 다시 확인할 수 없어요.",
    });
    expect(heading.closest("[data-status]")?.getAttribute("data-status")).toBe(code);
    expect(screen.getByRole("button", { name: "기대 프로필로 돌아가기" })).toBeTruthy();
    expect(window.localStorage.getItem(storageModule.COMPARE_SELECTION_STORAGE_KEY)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "기대 프로필로 돌아가기" }));
    expect(await screen.findByText("profile recovery")).toBeTruthy();
  });

  test("focus target motion target and narrow comparison contracts stay explicit in CSS", async () => {
    const { readFileSync } = await import("node:fs");
    const { resolve } = await import("node:path");
    const css = readFileSync(resolve(process.cwd(), "src/app/styles/internal.css"), "utf8");
    expect(css).toMatch(/body\s*\{[\s\S]*?min-width:\s*320px/);
    expect(css).toMatch(/button,[\s\S]*?min-height:\s*44px/);
    expect(css).toMatch(/:focus-visible\s*\{[\s\S]*?outline:\s*3px solid var\(--focus\)/);
    expect(css).toMatch(/\.recommendation-list\s*\{[\s\S]*?display:\s*grid/);
    expect(css).toMatch(/\.comparison-table-region\s*\{[\s\S]*?overflow-x:\s*auto/);
    expect(css).toMatch(/overflow-wrap:\s*anywhere/);
    expect(css).toMatch(/@media \(prefers-reduced-motion:\s*reduce\)[\s\S]*?transition-duration:\s*0\.01ms/);
  });
}
