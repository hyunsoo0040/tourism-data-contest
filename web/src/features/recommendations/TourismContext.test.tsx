import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import fixture from "../../../fixtures/tourism-synthetic-v2.json";
import type { TourismContext } from "../../api/tourism-context";
import { ForecastPanel, TourismPlacePanel, TourismRegionalPanel } from "./TourismContext";

// These direct presentation fixtures do not pass through the API hash parser.
function contextFixture(): TourismContext {
  return structuredClone(fixture.context) as unknown as TourismContext;
}

function emptyContext(): TourismContext {
  const context = contextFixture();
  for (const place of context.places) {
    place.accessibility.state = "UNAVAILABLE";
    place.accessibility.facts = [];
    place.camping.state = "UNKNOWN";
    place.camping.facts = {};
    place.camping.booking_url = null;
    place.walking.state = "UNKNOWN";
    place.walking.courses = [];
    place.related.state = "UNKNOWN";
    place.related.suggestions = [];
  }
  for (const forecast of context.temporal.forecasts) {
    forecast.state = "UNKNOWN";
    forecast.value = null;
    forecast.alternatives = [];
  }
  context.temporal.visitors.state = "UNKNOWN";
  context.temporal.visitors.points = [];
  return context;
}

function demandContext(stayValue: string, spendValue = "77.92"): TourismContext {
  const context = emptyContext();
  context.temporal.demand = context.temporal.demand.map((row, index): TourismContext["temporal"]["demand"][number] => {
    const stay = row.measure_kind === "REGIONAL_STAY_INTENSITY";
    const code = stay ? "21" : "22";
    const value = stay ? stayValue : spendValue;
    return { ...row, state: "AVAILABLE", reason: "NONE", source_snapshot_sha256: String(index + 1).repeat(64),
      retrieved_at: "2026-09-09T00:00:00Z", expires_at: "2026-09-09T06:00:00Z", provider_result_code: "0000",
      measures: [{ indicator_code: code, indicator_name: stay ? "관광체류강도" : "관광소비강도",
        value, raw_value: value, state: "AVAILABLE", reason: "NONE", unit: "TOURISM_DEMAND_INDEX" }],
      receipts: [{ schema_version: "source-receipt.v1", service: "AreaTarDemDsService",
        operation: stay ? "areaTarSjrnDsList" : "areaTarExpDsList", dataset_id: "15151868",
        request_scope: { baseYm: row.base_month!, areaCd: "47", signguCd: "47130",
          [stay ? "tarSjrnDsIxCd" : "tarExpDsIxCd"]: code },
        retrieved_at: "2026-09-09T00:00:00Z", source_modified_at: null, reference_date: null,
        status: "AVAILABLE", http_status: 200, response_sha256: String(index + 3).repeat(64), reason: "합성 정상 응답" }],
    };
  });
  return context;
}

function renderPlace(context?: TourismContext) {
  return render(<TourismPlacePanel context={context} placeId={fixture.context.places[0]!.place_id}
    runId="run:display-test" rankedPlaceIds={[]} />);
}

function openPlace() {
  fireEvent.click(screen.getByText("방문 참고 정보", { exact: true }));
}

describe("optional place tourism information", () => {
  it("does not render a disclosure before context arrives", () => {
    const { container } = renderPlace();
    expect(container.querySelector("details")).toBeNull();
    expect(container.textContent).toBe("");
  });

  it("omits the whole disclosure when nonempty source payloads contain only unknown data", () => {
    const context = emptyContext();
    const place = context.places[0]!;
    const original = contextFixture().places[0]!;
    place.accessibility.state = "PARTIAL";
    place.accessibility.facts = original.accessibility.facts.map((fact) => ({ ...fact, state: "UNKNOWN", value: null }));
    place.camping.state = "PARTIAL";
    place.camping.facts = Object.fromEntries(Object.entries(original.camping.facts)
      .map(([key, fact]) => [key, { ...fact, state: "UNKNOWN", value: null }]));
    place.walking.state = "PARTIAL";
    place.walking.courses = original.walking.courses.map((course) => ({ ...course, state: "UNKNOWN",
      distance_km: null, duration_minutes: null, difficulty_code: null, difficulty_label_ko: null }));
    place.related.suggestions = original.related.suggestions;
    const { container } = renderPlace(context);
    expect(container.querySelector("details")).toBeNull();
    expect(container.textContent).toBe("");
  });

  it("keeps a real zero forecast without adding empty source categories", () => {
    const context = emptyContext();
    context.temporal.forecasts[0] = { ...contextFixture().temporal.forecasts[0]!, value: "0" };
    const { container } = renderPlace(context);
    openPlace();
    const forecast = within(screen.getByRole("region", { name: "방문 집중 예측" }));
    expect(forecast.getByText("0", { exact: true })).toBeTruthy();
    expect(forecast.getByText(/실시간 인원이나 장소 간 혼잡 비교 수치가 아닙니다/)).toBeTruthy();
    expect(container.querySelector("summary")?.textContent).toBe("방문 참고 정보방문 예측");
    expect(screen.queryByRole("heading", { name: "편의시설" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "캠핑장 공식 안내" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "연결된 걷기 코스" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "함께 둘러볼 장소" })).toBeNull();
  });

  it("shows mixed confirmed facts, zero counts and courses while hiding unknown rows", () => {
    const context = emptyContext();
    const place = context.places[0]!;
    const original = contextFixture().places[0]!;
    const supported = original.accessibility.facts.find((fact) => fact.state === "SUPPORTED_FACT")!;
    place.accessibility = { ...original.accessibility, state: "PARTIAL", facts: [
      { ...supported, key: "wheelchair_rental", value: false },
      { ...supported, key: "stroller_rental", state: "UNKNOWN", value: null },
    ] };
    place.camping = { ...original.camping, state: "PARTIAL", facts: {
      toilet_count: original.camping.facts.toilet_count!,
      shower_count: original.camping.facts.shower_count!,
      published_operating_days: { ...original.camping.facts.published_operating_days!, value: " " },
    } };
    place.walking = { ...original.walking, state: "PARTIAL", courses: [
      { ...original.walking.courses[0]!, name_ko: "확인된 해파랑 코스", distance_from_place_meters: 0, source_modified_date: null },
      { ...original.walking.courses[1]!, name_ko: "미확인 코스", state: "UNKNOWN",
        distance_km: null, duration_minutes: null, difficulty_code: null, difficulty_label_ko: null },
    ] };
    place.related = { ...original.related, state: "PARTIAL", suggestions: [
      { ...original.related.suggestions[0]!, place_name_ko: "확인된 연관 장소" },
    ] };
    renderPlace(context);
    openPlace();
    expect(within(screen.getByRole("region", { name: "편의시설" })).getByText("없음")).toBeTruthy();
    const camping = within(screen.getByRole("region", { name: "캠핑장 공식 안내" }));
    expect(camping.getByText("화장실 수")).toBeTruthy();
    expect(camping.getByText(/^0 ·/)).toBeTruthy();
    expect(camping.queryByText("샤워실 수")).toBeNull();
    expect(camping.queryByText("안내된 운영 요일")).toBeNull();
    expect(screen.getByText("확인된 해파랑 코스")).toBeTruthy();
    expect(screen.getByText("장소에서 코스까지 직선거리 약 0m")).toBeTruthy();
    expect(screen.queryByText("미확인 코스")).toBeNull();
    expect(screen.queryByText(/거리 미확인|시간 미확인|코스 수정일 미확인/)).toBeNull();
    expect(screen.getByText("확인된 연관 장소")).toBeTruthy();
    expect(screen.queryByText("미확인", { exact: true })).toBeNull();
  });

  it("keeps a safe official booking link as useful camping information on its own", () => {
    const context = emptyContext();
    context.places[0]!.camping.state = "PARTIAL";
    context.places[0]!.camping.booking_url = "https://www.gocamping.or.kr/booking";
    renderPlace(context);
    openPlace();
    expect(screen.getByRole("link", { name: /공식 예약 안내 확인/ }).getAttribute("href"))
      .toBe("https://www.gocamping.or.kr/booking");
    expect(screen.getByRole("heading", { name: "캠핑장 공식 안내" })).toBeTruthy();
  });

  it.each(["javascript:alert(1)", "https://name:password@example.invalid", "   "])(
    "does not keep an empty disclosure alive for an unsafe or blank booking URL: %s", (url) => {
      const context = emptyContext();
      context.places[0]!.camping.state = "PARTIAL";
      context.places[0]!.camping.booking_url = url;
      const { container } = renderPlace(context);
      expect(container.querySelector("details")).toBeNull();
    },
  );

  it("hides a standalone unknown forecast", () => {
    const { container } = render(<ForecastPanel forecast={emptyContext().temporal.forecasts[0]} />);
    expect(container.textContent).toBe("");
  });
});

describe("optional regional tourism information", () => {
  it("labels each national result's regional indices independently and hides unavailable regions", () => {
    const context = demandContext("102.99");
    context.temporal.regional_demand = [...context.temporal.demand,
      ...context.temporal.demand.map((row) => ({ ...row, region_code: "11110", region_name: "서울특별시 종로구" })),
      ...contextFixture().temporal.demand.map((row) => ({ ...row, region_code: "26110", region_name: "부산광역시 중구" }))];
    render(<TourismRegionalPanel state={{ kind: "resolved", context }} onRefresh={vi.fn()} />);
    expect(screen.getByText("경주시 관광 수요 지수", { exact: true })).toBeTruthy();
    fireEvent.click(screen.getByText("서울특별시 종로구 관광 수요 지수", { exact: true }));
    expect(within(screen.getByRole("region", { name: "서울특별시 종로구 관광 수요 지수" }))
      .getByText("2026-07 기준 · 서울특별시 종로구 전체")).toBeTruthy();
    expect(screen.queryByText("부산광역시 중구 관광 수요 지수", { exact: true })).toBeNull();
  });

  it.each(["102.99", "150.25", "0", "-2.5", "1e999", "1e-999"])("shows regional demand value %s as an index with no physical unit or 100-point scale", (value) => {
    render(<TourismRegionalPanel state={{ kind: "resolved", context: demandContext(value) }} onRefresh={vi.fn()} />);
    fireEvent.click(screen.getByText("경주시 관광 수요 지수", { exact: true }));
    const region = screen.getByRole("region", { name: "경주시 관광 수요 지수" });
    const panel = within(region);
    expect(panel.getByText(value, { selector: "strong" })).toBeTruthy();
    expect(panel.getByText("77.92", { selector: "strong" })).toBeTruthy();
    expect(panel.getByText("관광 체류 강도")).toBeTruthy();
    expect(panel.getByText("관광 소비 강도")).toBeTruthy();
    expect(panel.getByText("2026-07 기준 · 경주시 전체")).toBeTruthy();
    expect(panel.getByText(/기준월마다 척도가 달라질 수 있어요/)).toBeTruthy();
    expect(panel.getByRole("link", { name: "한국관광공사 지역 관광 수요" }).getAttribute("href"))
      .toBe("https://www.data.go.kr/data/15151868/openapi.do");
    expect(panel.queryByRole("meter")).toBeNull();
    const values = Array.from(region.querySelectorAll("dd"), (element) => element.textContent);
    expect(values).toEqual([`${value} 지수`, "77.92 지수"]);
    expect(values.join(" ")).not.toMatch(/%|\/\s*100|[0-9]\s*(?:원|명)/);
  });

  it("shows the one verified demand family while leaving archived unknown values hidden", () => {
    const context = demandContext("102.99");
    context.temporal.demand[1] = contextFixture().temporal.demand[1]!;
    render(<TourismRegionalPanel state={{ kind: "resolved", context }} onRefresh={vi.fn()} />);
    fireEvent.click(screen.getByText("경주시 관광 수요 지수", { exact: true }));
    const panel = within(screen.getByRole("region", { name: "경주시 관광 수요 지수" }));
    expect(panel.getByText("관광 체류 강도")).toBeTruthy();
    expect(panel.queryByText("관광 소비 강도")).toBeNull();
    expect(panel.queryByText(/미확인|조회할 수 없어요|77.92/)).toBeNull();
  });

  it("does not display demand child values under an unknown parent", () => {
    const context = demandContext("102.99");
    for (const row of context.temporal.demand) row.state = "UNKNOWN";
    const { container } = render(<TourismRegionalPanel state={{ kind: "resolved", context }} onRefresh={vi.fn()} />);
    expect(screen.queryByText("경주시 관광 수요 지수", { exact: true })).toBeNull();
    expect(container.querySelector("details")).toBeNull();
    expect(screen.queryByText("102.99")).toBeNull();
  });

  it("keeps only confirmed visitor rows in a partial series, including zero", () => {
    const context = contextFixture();
    context.temporal.visitors.state = "PARTIAL";
    context.temporal.visitors.points = context.temporal.visitors.points.map((point, index) => ({
      ...point, category_name: index === 1 ? "미확인 구분" : point.category_name,
      state: index === 1 ? "UNKNOWN" : "AVAILABLE", value: index === 1 ? null : index === 0 ? "0" : "42",
    }));
    render(<TourismRegionalPanel state={{ kind: "resolved", context }} onRefresh={vi.fn()} />);
    fireEvent.click(screen.getByText("경주시 방문자 추이", { exact: true }));
    const table = within(screen.getByRole("table", { name: "날짜·방문자 구분별 추정치" }));
    expect(table.getAllByRole("row")).toHaveLength(3);
    expect(table.getByText("0명 (추정)")).toBeTruthy();
    expect(table.getByText("42명 (추정)")).toBeTruthy();
    expect(table.queryByText("미확인 구분")).toBeNull();
    expect(screen.queryByRole("region", { name: "공식 여행 자료 제공 상태" })).toBeNull();
  });

  it("hides empty regional details and raw demand measures with unverified units", () => {
    const context = emptyContext();
    context.temporal.demand[0]!.reason = "UNIT_UNVERIFIED";
    context.temporal.demand[0]!.measures = [{ indicator_code: "UNVERIFIED", indicator_name: "표시하면 안 되는 지표",
      raw_value: "99999", value: null, state: "UNKNOWN", reason: "UNIT_UNVERIFIED", unit: "UNVERIFIED_PROVIDER_UNIT" }];
    const { container } = render(<TourismRegionalPanel state={{ kind: "resolved", context }} onRefresh={vi.fn()} />);
    expect(screen.getByText(/방문 날짜 2026-09-10/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toBeTruthy();
    expect(container.querySelector("details")).toBeNull();
    expect(screen.queryByText("표시하면 안 되는 지표")).toBeNull();
    expect(screen.queryByText(/단위 미확인|자료 제공 상태|현재 이 자료를 조회할 수 없어요/)).toBeNull();
  });

  it("keeps refresh usable after failure without presenting an unavailable-data notice", () => {
    const refresh = vi.fn();
    const { container } = render(<TourismRegionalPanel state={{ kind: "unavailable" }} onRefresh={refresh} />);
    fireEvent.click(screen.getByRole("button", { name: "방문 참고 정보 다시 확인" }));
    expect(refresh).toHaveBeenCalledOnce();
    expect(container.querySelector("details")).toBeNull();
    expect(screen.queryByText(/불러오지 못했어요|미확인|자료 없음/)).toBeNull();
  });
});
