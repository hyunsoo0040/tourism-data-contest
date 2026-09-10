import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import fixture from "../../../fixtures/grounded-synthetic-v5.json";
import type { GroundedDetail } from "../../api/grounded-detail";
import type { GroundedFitTrace, GroundedItem, GroundedResults } from "../../api/grounded-recommendation";
import { GroundedAxes, GroundedComparisonView, GroundedDetailView, GroundedResultsView } from "./GroundedRecommendationViews";
import { SimilaritySummary } from "./PreferenceSimilarity";

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("{}", { status: 503 }))));
});
afterEach(() => vi.unstubAllGlobals());

type Component = GroundedFitTrace["components"][number];
function comparison(key: string, expected: number | null, actual: number | null, fit: number | null): Component {
  return { key, expected, actual, fit, compared: fit !== null, difference: fit === null ? null : 100 - fit,
    weight: fit === null ? 0 : 1, evidence_ids: actual === null ? [] : [`evidence:${key}`],
    exclusion_reason: fit !== null ? null : expected === null ? "USER_UNSPECIFIED" : "PLACE_UNSUPPORTED" };
}

function setAxes(item: GroundedItem, components: Component[], overall: number) {
  item.contribution.experience = { components, score: overall,
    compared_keys: components.filter((row) => row.compared).map((row) => row.key),
    numerator: components.reduce((sum, row) => sum + (row.fit ?? 0) * row.weight, 0),
    denominator: components.reduce((sum, row) => sum + row.weight, 0) };
  item.axis_scores = item.axis_scores.map((axis) => {
    const row = components.find((component) => component.key === axis.key)!;
    return { ...axis, value: row.actual, state: row.actual === null ? "UNKNOWN" : "SUPPORTED_INFERENCE" };
  });
  item.supported_axes = components.filter((row) => row.compared).length;
}

// Direct display fixtures avoid changing or rehashing the sealed API fixtures.
function presentation() {
  const results = structuredClone(fixture.results) as unknown as GroundedResults;
  const details = structuredClone(fixture.details) as unknown as GroundedDetail[];
  const item = results.run.items[0]!;
  // Wire order is E,H,R, deliberately different from the display's H,E,R order.
  setAxes(item, [comparison("E", 90, 10, 20), comparison("H", 50, 50, 100), comparison("R", 25, 50, 75)], 65);
  item.fit_score = 92;
  item.contribution.effective_relevance = 92;
  details[0]!.item = item;
  return { results, details, item };
}

describe("preference similarity display", () => {
  it("shows expected 50 and actual 50 as 100%, mapping asymmetric components by key", () => {
    const { item } = presentation();
    const { container } = render(<GroundedAxes item={item} />);
    const history = screen.getByRole("meter", { name: "역사·전통 취향 유사도 100%" });
    const emotion = screen.getByRole("meter", { name: "감성·이미지 취향 유사도 20%" });
    const rest = screen.getByRole("meter", { name: "휴식·몰입 취향 유사도 75%" });
    expect(history.getAttribute("aria-valuenow")).toBe("100");
    expect(history.getAttribute("aria-valuetext")).toBe("내 취향과 100% 유사");
    expect(emotion.getAttribute("aria-valuenow")).toBe("20");
    expect(rest.getAttribute("aria-valuenow")).toBe("75");
    expect(screen.queryByText("50%")).toBeNull();
    expect(container.textContent).not.toMatch(/50점|10점|\/ 100점/);
  });

  it("leaves unsupported axes without a meter while preserving a real 0% similarity", () => {
    const { item } = presentation();
    setAxes(item, [comparison("E", 90, null, null), comparison("H", 0, 100, 0), comparison("R", 25, 50, 75)], 38);
    const { container } = render(<GroundedAxes item={item} />);
    expect(screen.getAllByRole("meter")).toHaveLength(2);
    expect(screen.getByRole("meter", { name: "역사·전통 취향 유사도 0%" }).getAttribute("aria-valuenow")).toBe("0");
    const unknown = container.querySelector('[data-supported-axis="E"]') as HTMLElement;
    expect(within(unknown).getByText("비교 어려움")).toBeTruthy();
    expect(within(unknown).queryByRole("meter")).toBeNull();
    expect(unknown.textContent).not.toContain("0%");
  });

  it("does not invent an aggregate percentage when comparison evidence is absent", () => {
    const { container } = render(<SimilaritySummary value={null} />);
    expect(screen.getByText("내 취향과 비교할 근거가 부족해요")).toBeTruthy();
    expect(container.textContent).not.toContain("0%");
    expect(container.querySelector("[data-preference-similarity]")?.getAttribute("data-preference-similarity")).toBe("unknown");
  });

  it("uses pure experience similarity in the result headline without changing rank order", () => {
    const { results } = presentation();
    const { container } = render(<MemoryRouter><GroundedResultsView results={results} /></MemoryRouter>);
    const cards = Array.from(container.querySelectorAll<HTMLElement>("[data-grounded-item]"));
    expect(cards.map((card) => card.dataset.groundedItem)).toEqual(results.run.items.map((item) => item.place_id));
    expect(cards[0]!.querySelector(".recommendation-fit")?.textContent).toBe("내 취향과 65% 유사");
    expect(cards[0]!.querySelector(".recommendation-fit")?.textContent).not.toContain("92");
    expect(screen.getByText(/추천 순서는 여행 조건과 사진 분위기, 장소의 다양성도 함께 고려/)).toBeTruthy();
  });

  it("retains detail reasons while replacing raw subordinate and trait ratings with similarities", () => {
    const { results, details, item } = presentation();
    const detail = details[0]!;
    detail.assessment.dimensions.E1!.reason = "확인된 전망의 형태와 색을 설명하는 근거예요.";
    detail.assessment.dimensions.E1!.value = 3;
    item.mismatch_traits[0]!.value = 10;
    item.mismatch_traits[0]!.reason = "현대적인 실내 공간을 설명하는 근거예요.";
    item.contribution.traits.components[0] = comparison("M1", 90, 10, 20);
    item.mismatch_traits[1]!.value = 72;
    item.contribution.traits.components[1] = comparison("M2", null, 72, null);
    const { container } = render(<MemoryRouter><GroundedDetailView results={results} detail={detail} /></MemoryRouter>);
    expect(container.querySelector("[data-preference-similarity]")?.textContent).toBe("내 취향과 65% 유사");
    expect(screen.getByText("확인된 전망의 형태와 색을 설명하는 근거예요.")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "여행 방식 유사도" })).toBeTruthy();
    const trait = container.querySelector('[data-grounded-trait="M1"]') as HTMLElement;
    expect(within(trait).getByText("20%", { exact: true })).toBeTruthy();
    expect(within(trait).getByText("현대적인 실내 공간을 설명하는 근거예요.")).toBeTruthy();
    expect(container.querySelector('[data-grounded-trait="M2"]')?.textContent).toContain("선택하지 않은 항목");
    expect(container.querySelector('[data-grounded-trait="M3"]')?.textContent).toContain("비교 어려움");
    expect(container.textContent).not.toMatch(/3 \/ 4|2 \/ 4|10점|72점|92점/);
  });

  it("shows pure experience and per-axis/trait fit percentages in comparison, not place intensities", () => {
    const { results, details, item } = presentation();
    item.contribution.traits.components[0] = comparison("M1", 90, 10, 20);
    item.mismatch_traits[0]!.value = 10;
    item.contribution.traits.components[1] = comparison("M2", null, 72, null);
    item.mismatch_traits[1]!.value = 72;
    render(<MemoryRouter><GroundedComparisonView results={results} details={[details[0]!]} /></MemoryRouter>);
    const table = screen.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
    const cell = (heading: string) => within(table).getByRole("rowheader", { name: heading }).parentElement!.querySelector("td")!.textContent;
    expect(cell("내 취향과의 유사도")).toBe("65%");
    expect(cell("역사·전통 유사도")).toBe("100%");
    expect(cell("감성·이미지 유사도")).toBe("20%");
    expect(cell("휴식·몰입 유사도")).toBe("75%");
    expect(cell("공간 성격 유사도")).toBe("20%");
    expect(cell("방문객 성격 유사도")).toBe("선택하지 않은 항목");
    expect(cell("현장 밀도 유사도")).toBe("비교 어려움");
    expect(table.textContent).not.toMatch(/50%|10점|72점|92%/);
  });
});
