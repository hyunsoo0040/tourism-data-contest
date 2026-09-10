import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiRequestError, RecommendationContractError, createRecommendationRun } from "./api";
import { fetchTripContext, parseTripContextResponse } from "./trip-context";
import { writeGroundedTripInput } from "../features/journey/groundedTrip";

beforeEach(() => window.sessionStorage.clear());

function responseFixture() {
  return {
    schema_version: "itda.trip-context.v1",
    recommendation_run_id: "run:grounded",
    trip_input: { visit_date: "2026-10-03", visit_time: null, required_facilities: ["accessible_toilet"] },
    checked_at: "2026-09-09T01:00:00Z", mode: "PINNED",
    places: [{ place_id: "place:gyeongju", place_name_ko: "경주 관광지", source_snapshot_sha256: "a".repeat(64),
      state: "AVAILABLE", reason_ko: "선택한 시설 정보를 확인했어요.", facts: [{
        key: "accessible_toilet", claim: "FACILITY", state: "SUPPORTED_FACT", value: false,
        reference_date: "2026-09-09", reason: "공식 자료에 장애인 화장실이 없다고 안내되어 있어요.",
        evidence: [{ evidence_id: "evidence:access", scope: "PLACE", modality: "STRUCTURED",
          image_sha256: null, image_license: null,
          source_field: "restroom", excerpt: "장애인 화장실 없음", quote: "없음",
          receipt: { schema_version: "source-receipt.v1", service: "KorWithService2", operation: "detailWithTour2",
            dataset_id: "15101897", request_scope: { contentId: "123" }, retrieved_at: "2026-09-09T01:00:00Z",
            source_modified_at: null, reference_date: "2026-09-09", status: "AVAILABLE", http_status: 200,
            response_sha256: "b".repeat(64), reason: "정상 응답" },
          place_match: { place_id: "place:gyeongju", service: "KorWithService2", provider_entity_id: "123",
            state: "MATCHED", method: "EXACT_NAME_AND_LOCATION", region_code: "47130",
            evidence: ["이름과 좌표 일치"], distance_meters: 3 },
        }],
      }] }],
  };
}

describe("source-bound trip context API", () => {
  it("adds staged context to both photo and no-photo calls only for explicit needs", async () => {
    const request = { request_id: "request:new", preference_profile_id: "profile:test" };
    const fetchImpl = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({
      schema_version: "itda.recommendation-run-created.v1", recommendation_run_id: "run:new",
      ...request, preference_input_sha256: "c".repeat(64),
    }))));
    writeGroundedTripInput({ visit_date: "2026-10-03", visit_time: null, required_facilities: [] });
    await createRecommendationRun(request, { fetchImpl });
    expect(JSON.parse(fetchImpl.mock.calls[0]![1].body)).toEqual(request);
    const grounded = { visit_date: "2026-10-03", visit_time: null, required_facilities: ["accessible_toilet" as const] };
    writeGroundedTripInput(grounded);
    await createRecommendationRun(request, { fetchImpl });
    expect(JSON.parse(fetchImpl.mock.calls[1]![1].body)).toEqual({ ...request, grounded_input: grounded });
    await createRecommendationRun({ ...request, photo_job_id: "d".repeat(64) }, { fetchImpl });
    expect(JSON.parse(fetchImpl.mock.calls[2]![1].body)).toEqual({ ...request, photo_job_id: "d".repeat(64), grounded_input: grounded });
    await createRecommendationRun({ ...request, grounded_input: null }, { fetchImpl });
    expect(JSON.parse(fetchImpl.mock.calls[3]![1].body)).toEqual(request);
  });

  it("requests the encoded run with same-origin session credentials and decodes false distinctly", async () => {
    const payload = responseFixture();
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    const controller = new AbortController();
    const response = await fetchTripContext("run:grounded", { fetchImpl, signal: controller.signal });
    expect(fetchImpl).toHaveBeenCalledWith("/v1/recommendation-runs/run%3Agrounded/trip-context", {
      credentials: "same-origin", signal: controller.signal,
    });
    expect(response.places[0]?.facts[0]?.value).toBe(false);
  });

  it("accepts explicit unknown without claiming absent facilities", () => {
    const payload = responseFixture();
    Object.assign(payload.places[0]!.facts[0]!, { state: "UNKNOWN", value: null, evidence: [], reference_date: null });
    expect(parseTripContextResponse(payload).places[0]?.facts[0]?.value).toBeNull();
  });

  it.each([
    ["wrong run", (row: ReturnType<typeof responseFixture>) => { row.recommendation_run_id = "run:other"; }],
    ["unknown false", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.state = "UNKNOWN"; }],
    ["inferred facility", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.state = "SUPPORTED_INFERENCE"; }],
    ["pixels as facility", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.evidence[0]!.modality = "IMAGE_PIXELS"; }],
    ["another place", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.evidence[0]!.place_match.place_id = "place:other"; }],
    ["unbound quote", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.evidence[0]!.quote = "있음"; }],
    ["wrong dataset", (row: ReturnType<typeof responseFixture>) => { row.places[0]!.facts[0]!.evidence[0]!.receipt.dataset_id = "15101971"; }],
    ["secret parameter", (row: ReturnType<typeof responseFixture>) => { Object.assign(row.places[0]!.facts[0]!.evidence[0]!.receipt.request_scope, { serviceKey: "must-not-appear" }); }],
    ["no reference date", (row: ReturnType<typeof responseFixture>) => { Object.assign(row.places[0]!.facts[0]!, { reference_date: null }); }],
    ["extra authority", (row: ReturnType<typeof responseFixture>) => { Object.assign(row, { confidence: 100 }); }],
  ])("rejects %s before rendering", (_name, mutate) => {
    const payload = responseFixture();
    mutate(payload);
    expect(() => parseTripContextResponse(payload, "run:grounded")).toThrow(RecommendationContractError);
  });

  it("keeps an authentication failure distinct from a missing facility", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response("{}", { status: 401 }));
    await expect(fetchTripContext("run:grounded", { fetchImpl })).rejects.toMatchObject({ status: 401 });
    const offline = vi.fn().mockRejectedValue(new TypeError("offline"));
    await expect(fetchTripContext("run:grounded", { fetchImpl: offline })).rejects.toBeInstanceOf(ApiRequestError);
  });
});
