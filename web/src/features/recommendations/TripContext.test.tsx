import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import qualityFixture from "../../../../fixtures/quality-integration-v4.json";

import type { SourceObservation, TripContextPlace } from "../../api/trip-context";
import { TripContext } from "./TripContext";
import { useTripContext } from "./useTripContext";
import { RecommendationsPage } from "../../journey-pages/RecommendationsJourneyPage";

afterEach(() => vi.unstubAllGlobals());

function place(facts: SourceObservation[]): TripContextPlace {
  return { place_id: "place:test", place_name_ko: "경주 관광지", source_snapshot_sha256: "a".repeat(64),
    state: "PARTIAL", reason_ko: "확인된 항목과 미확인 항목이 있어요.", facts };
}

const evidence: SourceObservation["evidence"] = [{
  evidence_id: "evidence:test", scope: "PLACE", modality: "STRUCTURED", source_field: "restroom",
  image_sha256: null, image_license: null,
  excerpt: "장애인 화장실 있음", quote: "있음",
  receipt: { schema_version: "source-receipt.v1", service: "KorWithService2", operation: "detailWithTour2",
    dataset_id: "15101897", request_scope: {}, retrieved_at: "2026-09-09T01:00:00Z", source_modified_at: null,
    reference_date: "2026-09-08", status: "AVAILABLE", http_status: 200, response_sha256: "b".repeat(64), reason: "정상 응답" },
  place_match: { place_id: "place:test", service: "KorWithService2", provider_entity_id: "123", state: "MATCHED",
    method: "EXACT_NAME_AND_LOCATION", region_code: "47130", evidence: ["이름과 좌표 일치"], distance_meters: 0 },
}];

function observation(key: string, value: boolean | number | string | null): SourceObservation {
  return { key, claim: "FACILITY", state: value === null ? "UNKNOWN" : "SUPPORTED_FACT", value,
    reference_date: value === null ? null : "2026-09-08", evidence: value === null ? [] : evidence,
    reason: value === null ? "공식 자료에서 확인되지 않았어요." : "공식 시설 안내를 확인했어요." };
}

describe("TripContext", () => {
  it("keeps confirmed presence and absence with provenance while hiding unknown facilities", () => {
    const { container } = render(<TripContext loading={false} place={place([
      observation("accessible_toilet", true), observation("wheelchair_rental", false), observation("stroller_rental", null),
    ])} checkedAt="2026-09-09T01:00:00Z" mode="PINNED" />);
    expect(screen.getByText("장애인 화장실")).toBeTruthy();
    expect(screen.getByText("있음")).toBeTruthy();
    expect(screen.getByText("없음")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "편의시설" })).toBeTruthy();
    expect(screen.queryByText("유아차 대여")).toBeNull();
    expect(container.querySelector('[data-trip-fact="stroller_rental"]')).toBeNull();
    expect(screen.queryByText("미확인")).toBeNull();
    expect(screen.getAllByRole("link", { name: "한국관광공사 무장애 여행 정보" })[0]?.getAttribute("href"))
      .toBe("https://www.data.go.kr/data/15101897/openapi.do");
    expect(screen.getAllByText(/2026-09-08 기준/)).toHaveLength(2);
    expect(screen.getByText(/추천 당시 확인한 정보/)).toBeTruthy();
    expect(container.textContent).not.toContain("이용 가능");
  });

  it("suppresses loading and unavailable facility panels while keeping additional children", () => {
    const { container, rerender } = render(<TripContext loading />);
    expect(container.textContent).toBe("");
    rerender(<TripContext loading={false}><p>방문 집중 예측</p></TripContext>);
    expect(screen.queryByRole("heading", { name: "편의시설" })).toBeNull();
    expect(screen.queryByText(/여행 조건 정보를 불러오지 못했어요/)).toBeNull();
    expect(screen.queryByText("없음")).toBeNull();
    expect(screen.getByText("방문 집중 예측")).toBeTruthy();
  });

  it("keeps confirmed numeric zero and hides blank values or unsupported claims", () => {
    const { container } = render(<TripContext loading={false} place={place([
      observation("accessible_toilet", 0), observation("wheelchair_rental", false),
      observation("stroller_rental", "  "), observation("unknown_facility_key", true),
    ])} />);
    expect(screen.getByText("0")).toBeTruthy();
    expect(screen.getByText("없음")).toBeTruthy();
    expect(container.querySelectorAll("[data-trip-fact]")).toHaveLength(2);
    expect(container.textContent).not.toContain("unknown_facility_key");
  });

  it.each([{ name: "empty", facts: [] }, { name: "unknown", facts: [observation("accessible_toilet", null)] }])(
    "omits the whole facility section when no supported facts remain ($name)", ({ facts }) => {
      const { container } = render(<TripContext loading={false} place={place(facts)} />);
      expect(container.textContent).toBe("");
      expect(container.querySelector("section")).toBeNull();
    },
  );

  it("renders source text as inert data and does not promote unrelated claims into facility rows", () => {
    const fact = observation("accessible_toilet", true);
    fact.reason = '<img src=x onerror="alert(1)">';
    const mood = { ...observation("visual_mood", null), claim: "VISUAL_MOOD" as const };
    const { container } = render(<TripContext loading={false} place={place([fact, mood])} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x");
    expect(container.textContent).not.toContain("visual_mood");
  });
});

describe("trip context request ownership", () => {
  it("requests one pinned context for all five result cards and renders the matching place fact", async () => {
    const payload = qualityFixture.no_photo;
    const context = {
      schema_version: "itda.trip-context.v1", recommendation_run_id: payload.run.run_id,
      trip_input: { visit_date: null, visit_time: null, required_facilities: ["accessible_toilet"] },
      checked_at: "2026-09-09T01:00:00Z", mode: "PINNED",
      places: payload.run.items.map((item, index) => {
        const fact = observation("accessible_toilet", index === 0 ? true : null);
        fact.evidence = fact.evidence.map((entry) => ({ ...entry,
          place_match: { ...entry.place_match!, place_id: item.place_id } }));
        return { ...place([fact]), place_id: item.place_id, place_name_ko: item.place_name_ko };
      }),
    };
    const fetchImpl = vi.fn().mockImplementation((url: string) => Promise.resolve(new Response(JSON.stringify(
      url.endsWith("/trip-context") ? context : url.includes("/operating-information") ? {} : payload,
    ), { status: url.includes("/operating-information") ? 503 : 200 })));
    vi.stubGlobal("fetch", fetchImpl);
    const router = createMemoryRouter([{ path: "/recommendations/:runId", element: <RecommendationsPage /> }], {
      initialEntries: [`/recommendations/${encodeURIComponent(payload.run.run_id)}`],
    });
    render(<RouterProvider router={router} />);
    await screen.findByRole("link", { name: "한국관광공사 무장애 여행 정보" });
    expect(screen.getAllByText("장애인 화장실")).toHaveLength(1);
    expect(screen.getAllByText("있음")).toHaveLength(1);
    expect(document.querySelectorAll('[data-support-state="UNKNOWN"]')).toHaveLength(0);
    expect(fetchImpl.mock.calls.filter(([url]) => url.endsWith("/trip-context"))).toHaveLength(1);
  });

  it("does not issue a request while disabled", () => {
    const fetchImpl = vi.fn();
    vi.stubGlobal("fetch", fetchImpl);
    const { result } = renderHook(() => useTripContext("run:test", false));
    expect(result.current.kind).toBe("idle");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("aborts an obsolete run and never shows its source facts in the new run", async () => {
    const requests: Array<{ resolve: (response: Response) => void; signal: AbortSignal }> = [];
    vi.stubGlobal("fetch", vi.fn((_url: string, options: RequestInit) => new Promise<Response>((resolve) => {
      requests.push({ resolve, signal: options.signal as AbortSignal });
    })));
    const { result, rerender } = renderHook(({ runId }) => useTripContext(runId), {
      initialProps: { runId: "run:old" },
    });
    rerender({ runId: "run:new" });
    expect(requests[0]?.signal.aborted).toBe(true);
    expect(result.current.kind).toBe("loading");
    function response(runId: string) {
      return new Response(JSON.stringify({ schema_version: "itda.trip-context.v1", recommendation_run_id: runId,
        trip_input: { visit_date: null, visit_time: null, required_facilities: [] },
        checked_at: "2026-09-09T01:00:00Z", mode: "PINNED", places: [place([])] }));
    }
    await act(async () => requests[0]?.resolve(response("run:old")));
    expect(result.current.kind).toBe("loading");
    await act(async () => requests[1]?.resolve(response("run:new")));
    await waitFor(() => expect(result.current.kind).toBe("resolved"));
    if (result.current.kind === "resolved") expect(result.current.response.recommendation_run_id).toBe("run:new");
  });
});
