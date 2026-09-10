import { describe, expect, it } from "vitest";
import fixture from "../../fixtures/tourism-synthetic-v2.json";
import { parseTourismContext } from "./tourism-context";
import { canonicalHash, without } from "./grounded-core";

type Json = Record<string, any>;

async function resealContext(context: Json): Promise<Json> {
  context.temporal.source_snapshot_sha256 = [...new Set([
    ...context.temporal.forecasts, context.temporal.visitors, ...context.temporal.demand,
    ...(context.temporal.regional_visitors ?? []), ...(context.temporal.regional_demand ?? []),
  ].flatMap((source: Json) => source.source_snapshot_sha256 ? [source.source_snapshot_sha256] : []))].sort();
  context.temporal.context_sha256 = await canonicalHash(without(context.temporal, ["context_sha256"]));
  const hashes = new Set<string>(context.temporal.source_snapshot_sha256);
  for (const place of context.places) {
    if (place.accessibility.source_snapshot_sha256) hashes.add(place.accessibility.source_snapshot_sha256);
    for (const key of ["camping", "walking", "related"]) {
      place[key].source_snapshot_sha256.forEach((hash: string) => hashes.add(hash));
      place[key].context_sha256 = await canonicalHash(without(place[key], ["context_sha256"]));
    }
  }
  context.source_snapshot_sha256 = [...hashes].sort();
  context.context_sha256 = await canonicalHash(without(context, ["context_sha256"]));
  return context;
}

async function availableDemandContext(stayValue = "102.99", spendValue = "77.92"): Promise<Json> {
  const context: Json = structuredClone(fixture.context);
  context.temporal.demand = context.temporal.demand.map((row: Json, index: number) => {
    const stay = row.measure_kind === "REGIONAL_STAY_INTENSITY";
    const code = stay ? "21" : "22";
    const value = stay ? stayValue : spendValue;
    return { ...row, state: "AVAILABLE", reason: "NONE", source_snapshot_sha256: String(index + 1).repeat(64),
      retrieved_at: "2026-09-09T00:00:00Z", expires_at: "2026-09-09T06:00:00Z", provider_result_code: "0000",
      measures: [{ indicator_code: code, indicator_name: stay ? "관광체류강도" : "관광소비강도",
        value, raw_value: value, state: "AVAILABLE", reason: "NONE", unit: "TOURISM_DEMAND_INDEX" }],
      receipts: [{ schema_version: "source-receipt.v1", service: "AreaTarDemDsService",
        operation: stay ? "areaTarSjrnDsList" : "areaTarExpDsList", dataset_id: "15151868",
        request_scope: { baseYm: row.base_month, areaCd: "47", signguCd: "47130",
          [stay ? "tarSjrnDsIxCd" : "tarExpDsIxCd"]: code },
        retrieved_at: "2026-09-09T00:00:00Z", source_modified_at: null, reference_date: null,
        status: "AVAILABLE", http_status: 200, response_sha256: String(index + 3).repeat(64), reason: "합성 정상 응답" }],
    };
  });
  return resealContext(context);
}

describe("seven-source tourism context", () => {
  it("decodes real production normalizers with synthetic provider transports and preserves decimal strings", async () => {
    const context = await parseTourismContext(fixture.context, "run:registry");
    expect(context.source_health).toHaveLength(7);
    expect(typeof context.temporal.forecasts[0]!.value).toBe("string");
    expect(context.temporal.ranking_effect).toBe("NONE");
    expect(context.temporal.demand[0]!.state).toBe("UNKNOWN");
  });
  it.each([
    ["physical density unit", (c: Json) => { c.temporal.forecasts[0].unit = "PEOPLE_PER_SQUARE_METER"; }],
    ["other forecast date", (c: Json) => { c.temporal.forecasts[0].target_date = "2026-09-12"; }],
    ["missing consumer", (c: Json) => { c.source_health.pop(); }],
    ["region converted to crowd", (c: Json) => { c.temporal.visitors.scope = "PLACE"; }],
    ["raw demand as score", (c: Json) => { c.temporal.demand[0].state = "AVAILABLE"; }],
    ["course affects place score", (c: Json) => { c.places[0].walking.courses[0].applies_to_place_walking_score = true; }],
    ["related popularity bonus", (c: Json) => { c.places[0].related.suggestions[0].affinity_effect = "BONUS"; }],
  ] as const)("rejects a resealed %s", async (_name, mutate) => {
    const context: Json = structuredClone(fixture.context);
    mutate(context);
    context.temporal.context_sha256 = await canonicalHash(without(context.temporal, ["context_sha256"]));
    for (const place of context.places) for (const key of ["camping", "walking", "related"]) place[key].context_sha256 = await canonicalHash(without(place[key], ["context_sha256"]));
    context.context_sha256 = await canonicalHash(without(context, ["context_sha256"]));
    await expect(parseTourismContext(context)).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
});

describe("documented regional demand indices", () => {
  it("validates independent regional visitor and demand sources for a nationwide result", async () => {
    const context = await availableDemandContext();
    const seoulVisitors = { ...structuredClone(context.temporal.visitors), region_code: "11110", region_name: "서울특별시 종로구" };
    const seoulDemand = context.temporal.demand.map((row: Json) => ({ ...structuredClone(row), region_code: "11110", region_name: "서울특별시 종로구",
      receipts: row.receipts.map((receipt: Json) => ({ ...receipt, request_scope: { ...receipt.request_scope, areaCd: "11", signguCd: "11110" } })) }));
    context.temporal.regional_visitors = [context.temporal.visitors, seoulVisitors];
    context.temporal.regional_demand = [...context.temporal.demand, ...seoulDemand];
    const parsed = await parseTourismContext(await resealContext(context));
    expect(parsed.temporal.regional_visitors?.map((row) => row.region_name)).toEqual(["경주시", "서울특별시 종로구"]);
    expect(parsed.temporal.regional_demand).toHaveLength(4);
    context.temporal.regional_demand[2].receipts[0].request_scope.signguCd = "47130";
    await expect(parseTourismContext(await resealContext(context))).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });

  it.each(["102.99", "150.25", "0", "-2.5", "1e999", "1e-999"])("accepts source-bound finite index %s without a 0–100 limit", async (value) => {
    const context = await parseTourismContext(await availableDemandContext(value), "run:registry");
    const [stay, spend] = context.temporal.demand;
    expect(stay!.state).toBe("AVAILABLE");
    expect(stay!.reason).toBe("NONE");
    expect(stay!.measures[0]).toMatchObject({ indicator_code: "21", indicator_name: "관광체류강도",
      value, raw_value: value, state: "AVAILABLE", reason: "NONE", unit: "TOURISM_DEMAND_INDEX" });
    expect(spend!.measures[0]).toMatchObject({ indicator_code: "22", indicator_name: "관광소비강도",
      value: "77.92", state: "AVAILABLE", unit: "TOURISM_DEMAND_INDEX" });
    expect(stay!.receipts[0]!.request_scope).toMatchObject({ baseYm: stay!.base_month,
      areaCd: "47", signguCd: "47130", tarSjrnDsIxCd: "21" });
    expect(context.temporal.ranking_effect).toBe("NONE");
  });

  it.each([
    ["102.9900", "1.0299e2"],
    [".5", "5e-1"],
    ["1.", "+1.000"],
    ["-0.0", "0e999"],
  ])("accepts exactly equivalent decimal spellings %s and %s without losing their text", async (value, raw) => {
    const context = await availableDemandContext(value);
    context.temporal.demand[0].measures[0].raw_value = raw;
    const parsed = await parseTourismContext(await resealContext(context));
    expect(parsed.temporal.demand[0]!.measures[0]).toMatchObject({ value, raw_value: raw });
  });

  it("retains archived unknown measures without claiming verified units", async () => {
    const context = await availableDemandContext();
    for (const row of context.temporal.demand) {
      row.state = "UNKNOWN";
      row.reason = "UNIT_UNVERIFIED";
      row.measures = row.measures.map((measure: Json) => ({ ...measure, state: "UNKNOWN", value: null,
        reason: "UNIT_UNVERIFIED", unit: "UNVERIFIED_PROVIDER_UNIT" }));
    }
    const parsed = await parseTourismContext(await resealContext(context));
    expect(parsed.temporal.demand.every((row) => row.state === "UNKNOWN" && row.measures[0]!.value === null)).toBe(true);
  });

  it.each([
    ["raw numeric mismatch", (row: Json) => { row.measures[0].raw_value = "102.98"; }],
    ["binary-float precision collision", (row: Json) => { row.measures[0].value = "102.99000000000000000001"; row.measures[0].raw_value = "102.99"; }],
    ["binary-float underflow collision", (row: Json) => { row.measures[0].value = "1e-999"; row.measures[0].raw_value = "0"; }],
    ["percentage unit", (row: Json) => { row.measures[0].unit = "PERCENT"; }],
    ["money unit", (row: Json) => { row.measures[0].unit = "KRW"; }],
    ["other service", (row: Json) => { Object.assign(row.receipts[0], { service: "KorService2", dataset_id: "15101578", operation: "detailCommon2" }); }],
    ["other operation", (row: Json) => { row.receipts[0].operation = "areaTarExpDsList"; }],
    ["sub-indicator instead of aggregate", (row: Json) => { row.measures[0].indicator_code = "2101"; }],
    ["other official label", (row: Json) => { row.measures[0].indicator_name = "외지인 소비액"; }],
    ["request index code missing", (row: Json) => { delete row.receipts[0].request_scope.tarSjrnDsIxCd; }],
    ["request index code mismatched", (row: Json) => { row.receipts[0].request_scope.tarSjrnDsIxCd = "22"; }],
    ["other reference month", (row: Json) => { row.receipts[0].request_scope.baseYm = "202509"; }],
    ["TourAPI area code", (row: Json) => { row.receipts[0].request_scope.areaCd = "35"; }],
    ["other municipality", (row: Json) => { row.receipts[0].request_scope.signguCd = "11530"; }],
    ["missing source hash", (row: Json) => { row.source_snapshot_sha256 = null; }],
    ["missing receipt", (row: Json) => { row.receipts = []; }],
    ["unavailable receipt", (row: Json) => { row.receipts[0].status = "UNAVAILABLE"; }],
    ["missing retrieval time", (row: Json) => { row.retrieved_at = null; }],
    ["nonpositive cache lifetime", (row: Json) => { row.expires_at = row.retrieved_at; }],
    ["NaN", (row: Json) => { row.measures[0].value = row.measures[0].raw_value = "NaN"; }],
    ["infinity", (row: Json) => { row.measures[0].value = row.measures[0].raw_value = "Infinity"; }],
    ["unknown parent with available child", (row: Json) => { row.state = "UNKNOWN"; row.reason = "UNIT_UNVERIFIED"; }],
  ] as const)("rejects a resealed %s", async (_name, mutate) => {
    const context = await availableDemandContext();
    mutate(context.temporal.demand[0]);
    await expect(parseTourismContext(await resealContext(context))).rejects.toMatchObject({ code: "INVALID_RECOMMENDATION_OUTPUT" });
  });
});
