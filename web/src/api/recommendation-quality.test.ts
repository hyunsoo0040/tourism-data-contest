import { describe, expect, it, vi } from "vitest";

import fixture from "../../../fixtures/quality-integration-v4.json";
import { fetchRecommendationResults } from "./api";

type JsonObject = Record<string, any>;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function hash(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value)));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function reseal(payload: JsonObject): Promise<void> {
  const run = payload.run as JsonObject;
  run.input_digest = await hash({ preference: run.preference, authority: run.authority });
  run.canonical_sha256 = await hash(Object.fromEntries(Object.entries(run)
    .filter(([key]) => !["canonical_sha256", "created_at", "run_id"].includes(key))));
  run.run_id = `recommendation-run:${run.canonical_sha256.slice(0, 32)}`;
}

function decode(payload: JsonObject) {
  return fetchRecommendationResults(payload.run.run_id, {
    fetchImpl: vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), {
      headers: { "Content-Type": "application/json" },
    })),
  });
}

function rescorePhoto(payload: JsonObject, index: number): void {
  const score = payload.run.photo_scores[index];
  const traits = score.trait_components.filter((trait: JsonObject) => score.observed_traits.includes(trait.trait_id));
  for (const trait of traits) trait.fit = 100 - Math.abs(trait.expected - trait.actual);
  score.photo_trait_fit = Math.floor((traits.reduce((sum: number, trait: JsonObject) => sum + trait.fit, 0) * 2 + traits.length) / (traits.length * 2));
  score.effective_relevance = Math.floor((score.base_relevance * 6_500 + score.photo_trait_fit * 3_500 + 5_000) / 10_000);
  payload.run.items[index].fit_score = score.effective_relevance;
}

describe("quality kernel v4 contract", () => {
  const grounding = {
    schema_version: "grounded-input-authority.v1", trip_input_sha256: "a".repeat(64),
    source_release_sha256: "b".repeat(64), source_snapshot_sha256: ["c".repeat(64), "d".repeat(64)],
    assessment_bundle_sha256: [],
  };

  it("accepts separately bound grounding without changing the original profile input hash", async () => {
    const payload: JsonObject = structuredClone(fixture.no_photo);
    payload.run.preference.quality_context.grounding = structuredClone(grounding);
    await reseal(payload);
    const decoded = await decode(payload);
    expect("preference" in decoded.run).toBe(true);
    if ("preference" in decoded.run) {
      expect(decoded.run.preference.input_sha256).toBe(fixture.no_photo.run.preference.input_sha256);
      expect(decoded.run.preference.quality_context).toMatchObject({ grounding });
    }
    payload.run.preference.quality_context.grounding.trip_input_sha256 = "e".repeat(64);
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each([
    ["nullable marker", (_row: JsonObject): null => null],
    ["unknown field", (row: JsonObject) => ({ ...row, confidence: 100 })],
    ["unknown version", (row: JsonObject) => ({ ...row, schema_version: "grounded-input-authority.v99" })],
    ["missing required digest", (row: JsonObject) => { delete row.trip_input_sha256; return row; }],
    ["duplicate snapshot", (row: JsonObject) => ({ ...row, source_snapshot_sha256: ["c".repeat(64), "c".repeat(64)] })],
    ["unordered snapshots", (row: JsonObject) => ({ ...row, source_snapshot_sha256: ["d".repeat(64), "c".repeat(64)] })],
    ["malformed assessment digest", (row: JsonObject) => ({ ...row, assessment_bundle_sha256: ["not-a-hash"] })],
  ] as const)("rejects resealed grounding with %s", async (_name, mutate) => {
    const payload: JsonObject = structuredClone(fixture.no_photo);
    payload.run.preference.quality_context.grounding = mutate(structuredClone(grounding));
    await reseal(payload);
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each(["no_photo", "photo"] as const)("decodes the actual backend %s receipt with unknown conditions", async (mode) => {
    const result = await decode(fixture[mode]);
    expect(result.run.items).toHaveLength(5);
    expect(result.run.items[0]!.contribution.condition_components.some((row) => row.place_value === null)).toBe(true);
  });

  it("keeps only observed semantic photo traits in the photo fit average", async () => {
    const result = await decode(fixture.photo);
    expect(result.run).toMatchObject({ photo_scores: [expect.objectContaining({ observed_traits: ["M1", "M5"] }),
      ...Array.from({ length: 4 }, () => expect.any(Object))] });
  });

  it("renormalizes observed condition weights with stable largest-remainder ties", async () => {
    const payload: JsonObject = structuredClone(fixture.no_photo);
    const item = payload.run.items[0];
    const contribution = item.contribution;
    const weights = [727, 637, 636, 0, 0, 0];
    for (let index = 0; index < 3; index += 1) {
      const row = contribution.condition_components[index];
      Object.assign(row, { place_value: row.expected_value, absolute_difference: 0,
        fit_score: 100, total_score_weight_bp: weights[index], weighted_numerator: weights[index]! * 100 });
    }
    contribution.travel_condition_fit_score = 100;
    contribution.relevance_numerator = contribution.experience_fit_score * 8_000 + 200_000;
    contribution.relevance_score = Math.floor((contribution.relevance_numerator + 5_000) / 10_000);
    contribution.rerank_numerator = contribution.relevance_score * 8_500 + contribution.diversity_novelty_score * 1_500;
    contribution.rerank_score = Math.floor((contribution.rerank_numerator + 5_000) / 10_000);
    item.fit_score = contribution.relevance_score;
    await reseal(payload);
    await expect(decode(payload)).resolves.toMatchObject({ run: { items: expect.any(Array) } });
    // The two equal remainders are resolved in canonical condition order.
    contribution.condition_components[1].total_score_weight_bp = 636;
    contribution.condition_components[1].weighted_numerator = 63_600;
    contribution.condition_components[2].total_score_weight_bp = 637;
    contribution.condition_components[2].weighted_numerator = 63_700;
    await reseal(payload);
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it("rejects a purpose change without a new input hash", async () => {
    const payload = structuredClone(fixture.no_photo);
    payload.run.preference.quality_context.purpose = "FOOD";
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each([
    ["unknown config hash", (payload: JsonObject) => {
      payload.run.authority.config_sha256 = "0".repeat(64);
      payload.release_disclosure.config_sha256 = "0".repeat(64);
    }],
    ["legacy config hash under quality kernel", (payload: JsonObject) => {
      const legacyHash = "f94bcaa2b895f9a19e94a5f54ba6af640e9a1226fce03b942ba023e0bd2e9c19";
      payload.run.authority.config_sha256 = legacyHash;
      payload.release_disclosure.config_sha256 = legacyHash;
    }],
    ["legacy kernel with new context", (payload: JsonObject) => { payload.run.authority.kernel_version = "recommendation-kernel-v3"; }],
    ["missing quality context", (payload: JsonObject) => { delete payload.run.preference.quality_context; }],
    ["invented zero fit for unknown conditions", (payload: JsonObject) => {
      const row = payload.run.items[0].contribution.condition_components.find((entry: JsonObject) => entry.place_value === null);
      row.fit_score = 0;
    }],
    ["weight assigned to unobserved conditions", (payload: JsonObject) => {
      const row = payload.run.items[0].contribution.condition_components.find((entry: JsonObject) => entry.place_value === null);
      row.total_score_weight_bp = 350;
    }],
    ["selected place outside purpose eligibility", (payload: JsonObject) => {
      payload.run.preference.quality_context.eligible_place_ids = [];
    }],
    ["unknown context key", (payload: JsonObject) => { payload.run.preference.quality_context.extra = true; }],
  ] as const)("rejects resealed %s", async (_label, mutate) => {
    const payload: JsonObject = structuredClone(fixture.no_photo);
    mutate(payload);
    await reseal(payload);
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each([
    ["unknown photo config hash", (payload: JsonObject) => {
      payload.run.authority.config_sha256 = "0".repeat(64);
      payload.release_disclosure.config_sha256 = "0".repeat(64);
    }],
    ["different observed mask for one place", (payload: JsonObject) => {
      payload.run.photo_scores[0].observed_traits = ["M1"];
      rescorePhoto(payload, 0);
    }],
    ["different observed expectation for one place", (payload: JsonObject) => {
      const trait = payload.run.photo_scores[0].trait_components.find((row: JsonObject) => row.trait_id === "M1");
      trait.expected = trait.expected === 100 ? 99 : trait.expected + 1;
      rescorePhoto(payload, 0);
    }],
    ["semantic fields under legacy projection", (payload: JsonObject) => { payload.run.authority.photo_projection_version = "photo-projection-v1"; }],
    ["missing observed traits", (payload: JsonObject) => { delete payload.run.photo_scores[0].observed_traits; }],
    ["duplicate observed traits", (payload: JsonObject) => { payload.run.photo_scores[0].observed_traits = ["M1", "M1"]; }],
    ["altered photo fit", (payload: JsonObject) => { payload.run.photo_scores[0].photo_trait_fit -= 1; }],
  ] as const)("rejects resealed %s", async (_label, mutate) => {
    const payload: JsonObject = structuredClone(fixture.photo);
    mutate(payload);
    await reseal(payload);
    await expect(decode(payload)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
});
