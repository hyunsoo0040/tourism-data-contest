import { describe, expect, it, vi } from "vitest";
import fixture from "../../fixtures/grounded-synthetic-v5.json";
import oldFixture from "../../../fixtures/quality-integration-v4.json";
import { parseGroundedResults, fetchRecommendationEnvelope } from "./grounded-recommendation";
import { canonicalHash, without } from "./grounded-core";
import { parseGroundedDetail } from "./grounded-detail";

type Json = Record<string, any>;
async function reseal(payload: Json) {
  const run = payload.run;
  run.input_digest = await canonicalHash({ preference: run.preference, authority: run.authority });
  run.canonical_sha256 = await canonicalHash(without(run, ["run_id", "created_at", "canonical_sha256"]));
  run.run_id = `recommendation-run:${run.canonical_sha256.slice(0, 32)}`;
}

describe("grounded v5 receipt", () => {
  it("binds national location labels and a region filter without inventing a confidence score", async () => {
    const payload: Json = structuredClone(fixture.results);
    payload.run.preference.trip_input.region_code = "11";
    for (const item of payload.run.items) {
      item.region_code = "11110";
      item.region_name = "서울특별시 종로구";
      item.address_ko = "서울특별시 종로구 합성 검증 주소";
      item.overall_confidence = null;
      item.mismatch.state = "SUPPRESSED_LOW_CONFIDENCE";
      item.mismatch.message_ko = null;
    }
    await reseal(payload);
    const result = await parseGroundedResults(payload);
    expect(result.run.items[0]).toMatchObject({ region_code: "11110", region_name: "서울특별시 종로구", overall_confidence: null });
    payload.run.items[0].region_code = "47130";
    await reseal(payload);
    await expect(parseGroundedResults(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it("keeps detail scores and nullable evidence identical to the pinned result", async () => {
    const results = await parseGroundedResults(fixture.results);
    const detail = await parseGroundedDetail(fixture.details[0], results, results.run.items[0]!.place_id);
    expect(detail.item).toEqual(results.run.items[0]);
    const altered = structuredClone(fixture.details[0]!);
    altered.item.fit_score = 1;
    await expect(parseGroundedDetail(altered, results, results.run.items[0]!.place_id)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
  it("decodes the actual Python-validated sparse-axis fixture without zero filling", async () => {
    const response = await parseGroundedResults(fixture.results, fixture.results.run.run_id);
    expect(response.run.items[0]!.axis_scores[0]!.value).toBeNull();
    expect(response.run.items[0]!.contribution.mood_weight).toBe(0);
    expect(response.run.items[0]!.mismatch_traits[2]!.value).toBeNull();
  });
  it.each([
    ["invented zero", (p: Json) => { p.run.items[0].axis_scores[0].value = 0; }],
    ["wrong support mask", (p: Json) => { p.run.items[0].contribution.experience.compared_keys.push("H"); }],
    ["unsupported fit", (p: Json) => { p.run.items[0].contribution.traits.components[0].fit = 100; }],
    ["changed target", (p: Json) => { p.run.items[0].contribution.traits.components[0].expected = 100; }],
    ["mood exceeds cap", (p: Json) => { p.run.items[0].contribution.mood_weight = 3500; }],
    ["wrong novelty", (p: Json) => { p.run.items[1].contribution.novelty_pairs[0].shared_traits = ["M3"]; }],
    ["unsupported mismatch", (p: Json) => { p.run.items[0].mismatch.important_floor_applied = true; }],
    ["foreign assessment", (p: Json) => { p.run.items[0].assessment_bundle_sha256 = "f".repeat(64); }],
    ["unlisted candidate", (p: Json) => { p.run.eligible_place_ids = p.run.eligible_place_ids.slice(1); }],
    ["unknown policy", (p: Json) => { p.run.authority.config_sha256 = "f".repeat(64); p.release_disclosure.config_sha256 = "f".repeat(64); }],
  ] as const)("rejects resealed %s", async (_name, mutate) => {
    const payload: Json = structuredClone(fixture.results);
    mutate(payload);
    await reseal(payload);
    await expect(parseGroundedResults(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
  it.each([fixture.results, oldFixture.no_photo, oldFixture.photo])("fetches and decodes a supported generation in one HTTP call", async (payload) => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    const decoded = await fetchRecommendationEnvelope(payload.run.run_id, { fetchImpl });
    expect(decoded.run.run_id).toBe(payload.run.run_id);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
  it("rejects an altered sealed body and mismatched route run identity", async () => {
    const payload = structuredClone(fixture.results);
    payload.run.preference.purpose = "FOOD";
    await expect(parseGroundedResults(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
    await expect(parseGroundedResults(fixture.results, "run:other")).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
});
