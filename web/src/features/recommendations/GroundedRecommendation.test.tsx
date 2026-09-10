import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../../fixtures/grounded-synthetic-v5.json";
import tourismFixture from "../../../fixtures/tourism-synthetic-v2.json";
import { RecommendationsPage } from "../../journey-pages/RecommendationsJourneyPage";
import { PlaceDetailPage } from "../../journey-pages/PlaceDetailJourneyPage";
import { ComparePage } from "../../journey-pages/CompareJourneyPage";
import { readSavedPlaceReferences } from "../../app/storage";

const run = fixture.results.run;
beforeEach(() => { window.localStorage.clear(); window.sessionStorage.clear(); });
afterEach(() => vi.unstubAllGlobals());

function response(payload: unknown, status = 200) { return new Response(JSON.stringify(payload), { status }); }
function setup(options: { unavailable?: boolean } = {}) {
  const fetchImpl = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    if (url.pathname.endsWith("/tourism-context")) return Promise.resolve(options.unavailable ? response({}, 503) : response(tourismFixture.grounded_context));
    if (url.pathname.endsWith("/comparison")) return Promise.resolve(response(fixture.comparison));
    if (url.pathname.includes("/places/")) return Promise.resolve(response(fixture.details.find((detail) => detail.item.place_id === decodeURIComponent(url.pathname.split("/").at(-1)!))));
    if (url.pathname.includes("/saved-place-references/")) {
      const id = decodeURIComponent(url.pathname.split("/").at(-1)!);
      return Promise.resolve(response({ place_id: id, place_name_ko: run.items.find((item) => item.place_id === id)!.place_name_ko,
        resolved_release_sha256: run.authority.candidate_sha256, saved_release_sha256: run.authority.candidate_sha256, state: "CURRENT", state_reason: null }));
    }
    return Promise.resolve(response(fixture.results));
  });
  vi.stubGlobal("fetch", fetchImpl);
  const router = createMemoryRouter([
    { path: "/recommendations/:runId", element: <RecommendationsPage /> },
    { path: "/recommendations/:runId/places/:placeId", element: <PlaceDetailPage /> },
    { path: "/recommendations/:runId/compare", element: <ComparePage /> },
  ], { initialEntries: [`/recommendations/${encodeURIComponent(run.run_id)}`] });
  render(<RouterProvider router={router} />);
  return { router, fetchImpl };
}

describe("grounded result journey", () => {
  it("shows matched quiz similarities and leaves unsupported axes unscored", async () => {
    const { fetchImpl } = setup();
    await screen.findByRole("heading", { name: "이번 여행에 맞는 5곳" });
    const cards = within(screen.getByRole("list", { name: "추천 5곳" })).getAllByRole("listitem");
    expect(cards).toHaveLength(5);
    expect(within(cards[0]!).getAllByRole("meter")).toHaveLength(2);
    expect(within(cards[0]!).getByText("비교 어려움")).toBeTruthy();
    expect(within(cards[0]!).getByRole("meter", { name: "감성·이미지 취향 유사도 100%" })).toBeTruthy();
    expect(within(cards[0]!).getByRole("meter", { name: "휴식·몰입 취향 유사도 100%" })).toBeTruthy();
    expect(within(cards[0]!).queryByText("50%")).toBeNull();
    await waitFor(() => expect(screen.getByText(/방문 날짜 2026-09-10 · 새로 조회한 참고 정보/)).toBeTruthy());
    fireEvent.click(within(cards[0]!).getByText("방문 참고 정보", { exact: true }));
    expect(within(cards[0]!).getByRole("heading", { name: "방문 집중 예측" })).toBeTruthy();
    expect(within(cards[0]!).getByText(/상대 지수/)).toBeTruthy();
    expect(within(cards[0]!).getByText(/실시간 인원이나 장소 간 혼잡 비교 수치가 아닙니다/)).toBeTruthy();
    expect(within(cards[0]!).getAllByText("경주시 권역 걷기 코스")).toHaveLength(5);
    fireEvent.click(screen.getByText("경주시 방문자 추이", { exact: true }));
    expect(screen.getByRole("table", { name: "날짜·방문자 구분별 추정치" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "공식 여행 자료 제공 상태" })).toBeNull();
    expect(screen.queryByRole("region", { name: "경주시 관광 체류와 소비 지표" })).toBeNull();
    expect(screen.queryByText("현재 이 자료를 조회할 수 없어요.")).toBeNull();
    expect(fetchImpl.mock.calls.filter(([url]) => String(url).endsWith("/tourism-context"))).toHaveLength(1);
  });

  it("preserves preference similarity and saved references across detail, comparison and refresh", async () => {
    const { router, fetchImpl } = setup();
    await screen.findByRole("heading", { name: "이번 여행에 맞는 5곳" });
    fireEvent.click(screen.getByRole("button", { name: `${run.items[0]!.place_name_ko} 저장` }));
    expect(readSavedPlaceReferences().references[0]?.place_id).toBe(run.items[0]!.place_id);
    expect(readSavedPlaceReferences().references[0]?.release_sha256).toBe(run.authority.candidate_sha256);
    fireEvent.click(screen.getByRole("button", { name: `${run.items[0]!.place_name_ko} 비교에 추가` }));
    fireEvent.click(screen.getByRole("button", { name: `${run.items[1]!.place_name_ko} 비교에 추가` }));
    fireEvent.click(screen.getByRole("button", { name: "선택한 장소 비교하기" }));
    await screen.findByRole("heading", { name: "선택한 장소 비교" });
    const table = screen.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
    expect(table.textContent).toContain("비교 어려움");
    expect(table.textContent).toContain("100%");
    expect(table.textContent).not.toContain("100점");
    fireEvent.click(screen.getByRole("link", { name: "추천 5곳으로 돌아가기" }));
    await screen.findByRole("heading", { name: "이번 여행에 맞는 5곳" });
    fireEvent.click(screen.getByRole("link", { name: `${run.items[0]!.place_name_ko} 상세 보기` }));
    await screen.findByRole("heading", { name: run.items[0]!.place_name_ko, level: 1 });
    expect(document.querySelector('[data-grounded-trait="M3"]')?.textContent).toContain("비교 어려움");
    expect(screen.getByText("분위기를 확인한 사진이 없어요.")).toBeTruthy();
    await waitFor(() => expect(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toHaveProperty("disabled", false));
    const before = document.querySelector("[data-preference-similarity]")?.textContent;
    expect(before).toContain("내 취향과 100% 유사");
    const original = router.state.location.pathname;
    fireEvent.click(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toHaveProperty("disabled", false));
    expect(document.querySelector("[data-preference-similarity]")?.textContent).toBe(before);
    expect(router.state.location.pathname).toBe(original);
    expect(fetchImpl.mock.calls.every(([, init]) => !init || (init as RequestInit).method !== "POST")).toBe(true);
    await act(async () => { await router.navigate(`/recommendations/${encodeURIComponent(run.run_id)}`); });
    await screen.findByRole("heading", { name: "이번 여행에 맞는 5곳" });
    expect(document.querySelector("[data-preference-similarity]")?.textContent).toBe(before);
    expect(screen.getByRole("button", { name: `${run.items[0]!.place_name_ko} 저장됨` })).toHaveProperty("ariaPressed", "true");
  });

  it("keeps saved results readable when all context services are unavailable", async () => {
    setup({ unavailable: true });
    await screen.findByRole("heading", { name: "이번 여행에 맞는 5곳" });
    await waitFor(() => expect(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toHaveProperty("disabled", false));
    expect(within(screen.getByRole("list", { name: "추천 5곳" })).getAllByRole("listitem")).toHaveLength(5);
    expect(screen.queryByText(/상대 지수/)).toBeNull();
    expect(screen.queryByText("여행 정보를 불러오지 못했어요. 저장된 추천은 그대로 확인할 수 있어요.")).toBeNull();
    expect(document.querySelector("[data-tourism-place]")).toBeNull();
  });
});
