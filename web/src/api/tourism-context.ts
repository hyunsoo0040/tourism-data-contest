import { z } from "zod";
import { RecommendationContractError } from "./api";
import { canonicalHash, ordered, same, without, nonnegative } from "./grounded-core";
import { getGroundedJson } from "./grounded-recommendation";
import { digest, isoDate, placeMatch, sourceObservationSchema, sourceReceipt, stableId, tripContextPlace, utcDateTime } from "./trip-context";
import { parseGroundedTripInput, type GroundedTripInput } from "../features/journey/groundedTrip";

const decimal = z.string().regex(/^\d+(?:\.\d+)?(?:[Ee][+-]?\d+)?$/).refine((value) => Number.isFinite(Number(value)) && Number(value) >= 0);
const forecastValue = decimal.refine((value) => Number(value) <= 100);
const temporalState = z.enum(["AVAILABLE", "PARTIAL", "UNKNOWN"]);
const reason = z.enum(["NONE", "NOT_REQUESTED", "EMPTY", "SOURCE_UNAVAILABLE", "AUTHORIZATION_UNAVAILABLE", "PARTIAL_SERIES", "STALE",
  "OUT_OF_WINDOW", "PLACE_NOT_MATCHED", "AMBIGUOUS_MATCH", "INVALID_VALUE", "UNIT_UNVERIFIED", "FUTURE_OBSERVATION", "UNSUPPORTED_REGION"]);
const month = z.string().regex(/^\d{4}(0[1-9]|1[0-2])$/);
const receipts = z.array(sourceReceipt);
const hashes = z.array(digest).refine(ordered);
const temporalMeta = { source_snapshot_sha256: digest.nullable(), receipts, retrieved_at: utcDateTime.nullable(), expires_at: utcDateTime.nullable(), warning_ko: z.string() };
const regionCode = z.string().regex(/^\d{5}$/);
const regionName = z.string().min(1).max(160);
const forecastSchema = z.strictObject({
  place_id: stableId, provider_name: z.string().nullable(), match_method: z.enum(["EXACT_NAME_AND_REGION", "CURATED_NAME_AND_REGION"]).nullable(),
  region_code: regionCode, scope: z.literal("PLACE_RELATIVE_FORECAST"), state: temporalState, reason,
  target_date: isoDate, provider_issue_date: z.null(), issue_date_status: z.literal("NOT_PROVIDED_BY_API"),
  window_start: isoDate.nullable(), window_end: isoDate.nullable(), value: forecastValue.nullable(),
  unit: z.literal("WITHIN_PLACE_RELATIVE_INDEX_0_100"), alternatives: z.array(z.strictObject({ target_date: isoDate, value: forecastValue })), ...temporalMeta,
}).refine((row) => row.receipts.every((receipt) => receipt.service === "TatsCnctrRateService" && receipt.operation === "tatsCnctrRatedList") &&
  (row.state !== "AVAILABLE" ? row.value === null && row.alternatives.length === 0 : row.value !== null && row.source_snapshot_sha256 !== null &&
    row.provider_name !== null && row.match_method !== null && row.receipts.length > 0 && row.window_start !== null && row.window_end !== null &&
    row.window_start <= row.target_date && row.target_date <= row.window_end && new Set(row.alternatives.map((a) => a.target_date)).size === row.alternatives.length &&
    row.alternatives.every((a) => Number(a.value) < Number(row.value) && a.target_date !== row.target_date && row.window_start! <= a.target_date && a.target_date <= row.window_end!)));
const visitorPoint = z.strictObject({ measurement_date: isoDate, category_code: z.enum(["1", "2", "3"]), category_name: z.string(),
  state: temporalState, reason, value: decimal.nullable(), raw_value: z.string().nullable() })
  .refine((row) => (row.state === "AVAILABLE") === (row.value !== null) && (row.value === null || (row.raw_value !== null && Number(row.raw_value) === Number(row.value))));
const visitorsSchema = z.strictObject({ scope: z.literal("REGION"), region_code: regionCode, region_name: regionName,
  unit: z.literal("ESTIMATED_VISITOR_COUNT"), state: temporalState, reason, period_start: isoDate.nullable(), period_end: isoDate.nullable(),
  provider_issue_date: z.null(), points: z.array(visitorPoint), ...temporalMeta })
  .refine((row) => {
    if (row.receipts.some((receipt) => receipt.service !== "DataLabService" || receipt.operation !== "locgoRegnVisitrDDList") ||
      new Set(row.points.map((point) => `${point.measurement_date}:${point.category_code}`)).size !== row.points.length) return false;
    if (row.points.length && (row.period_start === null || row.period_end === null || row.points.some((point) => point.measurement_date < row.period_start! || point.measurement_date > row.period_end!))) return false;
    if (row.state !== "AVAILABLE") return true;
    return row.points.length > 0 && row.period_start !== null && row.period_end !== null && row.receipts.length > 0 && row.source_snapshot_sha256 !== null &&
      row.points.length === ((Date.parse(row.period_end) - Date.parse(row.period_start)) / 86400000 + 1) * 3 && row.points.every((point) => point.state === "AVAILABLE");
  });
function decimalIdentity(value: string): string | null {
  const match = /^([+-]?)(\d*)(?:\.(\d*))?(?:[Ee]([+-]?\d+))?$/.exec(value);
  if (!match || !(match[2] || match[3])) return null;
  const fraction = match[3] ?? "";
  const digits = `${match[2]}${fraction}`.replace(/^0+/, "");
  if (!digits) return "0";
  const significant = digits.replace(/0+$/, "");
  const exponent = BigInt(match[4] ?? "0") - BigInt(fraction.length) + BigInt(digits.length - significant.length);
  return `${match[1] === "-" ? "-" : ""}${significant}e${exponent}`;
}
const demandIndex = z.string().refine((value) => decimalIdentity(value) !== null);
const demandMeasure = z.strictObject({ indicator_code: z.string(), indicator_name: z.string(), raw_value: z.string(), value: demandIndex.nullable(),
  state: z.enum(["AVAILABLE", "UNKNOWN"]), reason: z.enum(["NONE", "UNIT_UNVERIFIED"]), unit: z.enum(["TOURISM_DEMAND_INDEX", "UNVERIFIED_PROVIDER_UNIT"]) })
  .refine((row) => row.state === "AVAILABLE"
    ? row.value !== null && row.reason === "NONE" && row.unit === "TOURISM_DEMAND_INDEX"
      && decimalIdentity(row.value) === decimalIdentity(row.raw_value.trim())
    : row.value === null && row.reason === "UNIT_UNVERIFIED" && row.unit === "UNVERIFIED_PROVIDER_UNIT");
const demandSchema = z.strictObject({ scope: z.literal("REGION"), region_code: regionCode, region_name: regionName,
  measure_kind: z.enum(["REGIONAL_STAY_INTENSITY", "REGIONAL_SPENDING_INTENSITY"]), state: z.enum(["AVAILABLE", "UNKNOWN"]), reason, base_month: month.nullable(), provider_issue_date: z.null(),
  measures: z.array(demandMeasure), provider_result_code: z.string().nullable(), ...temporalMeta })
  .refine((row) => {
    const stay = row.measure_kind === "REGIONAL_STAY_INTENSITY";
    if (row.receipts.some((receipt) => receipt.service !== "AreaTarDemDsService" || receipt.operation !==
      (stay ? "areaTarSjrnDsList" : "areaTarExpDsList"))) return false;
    if (row.state === "UNKNOWN") return row.measures.every((measure) => measure.state === "UNKNOWN") &&
      (row.measures.length === 0 || (row.source_snapshot_sha256 !== null && row.receipts.length > 0 && row.reason === "UNIT_UNVERIFIED"));
    const measure = row.measures[0], code = stay ? "21" : "22";
    return row.reason === "NONE" && row.base_month !== null && row.measures.length === 1 && measure?.state === "AVAILABLE" &&
      measure.indicator_code === code && measure.indicator_name === (stay ? "관광체류강도" : "관광소비강도") &&
      row.source_snapshot_sha256 !== null && row.receipts.length > 0 && row.retrieved_at !== null && row.expires_at !== null &&
      Date.parse(row.expires_at) > Date.parse(row.retrieved_at) && row.receipts.every((receipt) => receipt.status === "AVAILABLE" &&
        receipt.request_scope.baseYm === row.base_month && receipt.request_scope.areaCd === row.region_code.slice(0, 2) && receipt.request_scope.signguCd === row.region_code &&
        receipt.request_scope[stay ? "tarSjrnDsIxCd" : "tarExpDsIxCd"] === code);
  });
const temporalSchema = z.strictObject({ schema_version: z.literal("trip-temporal-context.v1"), policy_version: z.literal("temporal-context-v1"),
  usage: z.literal("INFORMATION_ONLY"), ranking_effect: z.literal("NONE"), trip_date: isoDate, checked_at: utcDateTime,
  forecasts: z.array(forecastSchema), visitors: visitorsSchema, demand: z.array(demandSchema).length(2),
  regional_visitors: z.array(visitorsSchema).min(1).max(5).optional(), regional_demand: z.array(demandSchema).min(2).max(10).optional(),
  source_snapshot_sha256: hashes, context_sha256: digest });

const enrichmentFields = { place_id: stableId, state: temporalState, reason: z.string(), source_snapshot_sha256: hashes, receipts,
  retrieved_at: utcDateTime, expires_at: utcDateTime, context_sha256: digest };
const campingSchema = z.strictObject({ ...enrichmentFields, schema_version: z.literal("camping-context.v1"), match: placeMatch,
  facts: z.record(z.string(), sourceObservationSchema), source_modified_date: isoDate.nullable(), booking_url: z.string().nullable(), warning_ko: z.string() })
  .refine((row) => row.match.place_id === row.place_id && row.match.service === "GoCamping" && row.receipts.every((r) => r.service === "GoCamping") &&
    Object.entries(row.facts).every(([key, fact]) => key === fact.key && fact.evidence.every((e) => same(e.place_match, row.match)) &&
      (row.state !== "UNKNOWN" || fact.state === "UNKNOWN")));
const walkingCourseSchema = z.strictObject({ course_id: stableId, route_id: stableId, name_ko: z.string(), scope: z.literal("COURSE"),
  link_kind: z.enum(["EXACT_CANONICAL_COURSE", "MENTIONED_ON_COURSE", "REGIONAL_COURSE", "VERIFIED_NEARBY_COURSE"]), state: z.enum(["AVAILABLE", "UNKNOWN"]),
  reason: z.string(), distance_km: decimal.refine((value) => Number(value) > 0).nullable(), duration_minutes: z.number().int().positive().nullable(),
  difficulty_code: z.enum(["1", "2", "3"]).nullable(), difficulty_label_ko: z.string().nullable(), unit_authority: z.literal("DURUNUBI_MANUAL_4_1"),
  unit_authority_sha256: z.literal("2f164f46748a4f64b2d11b672f8001b9f844c6435449bc97e1ee1bfb5ed4ea08"), exact_match_review_sha256: digest.nullable(),
  source_modified_date: isoDate.nullable(), source_field_values: z.record(z.string(), z.string()), gpx_url: z.string().nullable(), geometry_sha256: digest.nullable(),
  distance_from_place_meters: z.number().nonnegative().nullable(), distance_method: z.literal("LOCAL_PROJECTED_STRAIGHT_LINE"),
  applies_to_place_walking_score: z.literal(false), scope_label_ko: z.string() })
  .refine((row) => (row.state === "AVAILABLE" ? [row.distance_km, row.duration_minutes, row.difficulty_code].every((v) => v !== null)
    : [row.distance_km, row.duration_minutes, row.difficulty_code].every((v) => v === null)) &&
    (row.link_kind !== "VERIFIED_NEARBY_COURSE" || (row.geometry_sha256 !== null && row.distance_from_place_meters !== null)) &&
    (row.link_kind === "EXACT_CANONICAL_COURSE") === (row.exact_match_review_sha256 !== null));
const walkingSchema = z.strictObject({ ...enrichmentFields, schema_version: z.literal("walking-context.v1"), courses: z.array(walkingCourseSchema).max(5), warning_ko: z.string() });
const relatedSchema = z.strictObject({ ...enrichmentFields, schema_version: z.literal("related-destinations-context.v1"), base_month: month,
  suggestions: z.array(z.strictObject({ place_id: stableId, place_name_ko: z.string(), provider_entity_id: stableId, source_provider_entity_id: stableId,
    provider_rank: z.number().int().positive(), match_method: z.literal("EXACT_NAME_AND_REGION"), relation_kind: z.literal("NAVIGATION_ASSOCIATION"), affinity_effect: z.literal("NONE") })).max(5),
  eligibility_sha256: digest, filtered_count: nonnegative, provider_result_code: z.string().nullable(), warning_ko: z.string() });
const placeSchema = z.strictObject({ place_id: stableId, place_name_ko: z.string(), accessibility: tripContextPlace,
  camping: campingSchema, walking: walkingSchema, related: relatedSchema })
  .refine((row) => [row.accessibility, row.camping, row.walking, row.related].every((context) => context.place_id === row.place_id));
const CONSUMERS = { KorWithService2: "places.accessibility", TatsCnctrRateService: "temporal.forecasts", DataLabService: "temporal.visitors",
  AreaTarDemDsService: "temporal.demand", GoCamping: "places.camping", Durunubi: "places.walking", TarRlteTarService1: "places.related" } as const;
const healthSchema = z.strictObject({ service: z.enum(Object.keys(CONSUMERS) as [keyof typeof CONSUMERS, ...Array<keyof typeof CONSUMERS>]), consumer: z.string(),
  state: z.enum(["AVAILABLE", "PARTIAL", "EMPTY", "UNAVAILABLE"]), reason: z.string(), receipt_count: nonnegative, http_attempt_count: nonnegative,
  http_latency_ms: nonnegative, provider_result_codes: z.array(z.string()), retrieved_at: utcDateTime.nullable() })
  .refine((row) => row.consumer === CONSUMERS[row.service] && (row.state === "UNAVAILABLE" || row.receipt_count > 0));
const tourismSchema = z.strictObject({ schema_version: z.literal("itda.tourism-context.v2"), recommendation_run_id: stableId,
  trip_input: z.custom<GroundedTripInput>((value) => parseGroundedTripInput(value) !== null), mode: z.enum(["REFRESHED", "PINNED"]), checked_at: utcDateTime,
  reference_periods: z.strictObject({ policy: z.literal("EXPLICIT_OR_LAGGED_CALENDAR_PERIOD_V1"), visitor_start: isoDate, visitor_end: isoDate,
    demand_month: month, related_month: month, lag_months: z.number().int(), availability_claim: z.literal("REQUESTED_PERIOD_NOT_LATEST_GUARANTEE") }),
  places: z.array(placeSchema).max(5), temporal: temporalSchema, source_health: z.array(healthSchema).length(7), source_snapshot_sha256: hashes, context_sha256: digest });

export type TourismContext = z.infer<typeof tourismSchema>;
export type TourismPlace = z.infer<typeof placeSchema>;
export type ConcentrationForecast = z.infer<typeof forecastSchema>;

export async function parseTourismContext(payload: unknown, runId?: string): Promise<TourismContext> {
  const parsed = tourismSchema.safeParse(payload);
  const invalid = () => { throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT"); };
  if (!parsed.success) return invalid();
  const context = parsed.data, temporal = context.temporal;
  const visitors = temporal.regional_visitors ?? [temporal.visitors];
  const demand = temporal.regional_demand ?? temporal.demand;
  const ids = context.places.map((place) => place.place_id);
  if ((runId !== undefined && context.recommendation_run_id !== runId) || new Set(ids).size !== ids.length ||
    !same([...ids].sort(), temporal.forecasts.map((forecast) => forecast.place_id).sort()) ||
    !same(context.source_health.map((health) => health.service).sort(), Object.keys(CONSUMERS).sort()) ||
    (context.trip_input.visit_date !== null && context.trip_input.visit_date !== temporal.trip_date) ||
    temporal.forecasts.some((forecast) => forecast.target_date !== temporal.trip_date) ||
    visitors.some((row) => row.period_start !== context.reference_periods.visitor_start || row.period_end !== context.reference_periods.visitor_end) ||
    demand.some((row) => row.base_month !== context.reference_periods.demand_month) ||
    !same(temporal.demand.map((d) => d.measure_kind).sort(), ["REGIONAL_SPENDING_INTENSITY", "REGIONAL_STAY_INTENSITY"])) return invalid();
  if (new Set(visitors.map((row) => row.region_code)).size !== visitors.length ||
    new Set(demand.map((row) => `${row.region_code}:${row.measure_kind}`)).size !== demand.length ||
    (temporal.regional_visitors && !same(temporal.visitors, visitors[0])) ||
    (temporal.regional_demand && !same(temporal.demand, demand.filter((row) => row.region_code === temporal.visitors.region_code))) ||
    visitors.some((visitor) => !same(demand.filter((row) => row.region_code === visitor.region_code).map((row) => row.measure_kind).sort(),
      ["REGIONAL_SPENDING_INTENSITY", "REGIONAL_STAY_INTENSITY"]))) return invalid();
  const temporalHashes = [...new Set([...temporal.forecasts, temporal.visitors, ...temporal.demand, ...visitors, ...demand].flatMap((source) => source.source_snapshot_sha256 ? [source.source_snapshot_sha256] : []))].sort();
  if (!same(temporal.source_snapshot_sha256, temporalHashes) || temporal.context_sha256 !== await canonicalHash(without(temporal, ["context_sha256"]))) return invalid();
  const allHashes = new Set(temporalHashes);
  for (const place of context.places) {
    if (place.accessibility.source_snapshot_sha256) allHashes.add(place.accessibility.source_snapshot_sha256);
    if (place.related.base_month !== context.reference_periods.related_month) return invalid();
    for (const source of [place.camping, place.walking, place.related]) {
      if (Date.parse(source.expires_at) <= Date.parse(source.retrieved_at) || source.context_sha256 !== await canonicalHash(without(source, ["context_sha256"]))) return invalid();
      source.source_snapshot_sha256.forEach((hash) => allHashes.add(hash));
    }
  }
  if (!same(context.source_snapshot_sha256, [...allHashes].sort()) || context.context_sha256 !== await canonicalHash(without(context, ["context_sha256"]))) return invalid();
  return context;
}

export async function fetchTourismContext(runId: string, options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {}): Promise<TourismContext> {
  if (!stableId.safeParse(runId).success) throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  return parseTourismContext(await getGroundedJson(`/v1/recommendation-runs/${encodeURIComponent(runId)}/tourism-context`, options), runId);
}
