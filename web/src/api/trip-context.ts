import { z } from "zod";

import { isIsoDate, parseGroundedTripInput, type GroundedTripInput } from "../features/journey/groundedTrip";
import { ApiRequestError, RecommendationContractError } from "./api";

export const stableId = z.string().min(1).max(160).refine((value) => value.trim().length > 0);
export const digest = z.string().regex(/^[0-9a-f]{64}$/);
export const isoDate = z.string().refine(isIsoDate);
export const utcDateTime = z.string().refine((value) =>
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/.test(value) &&
  isIsoDate(value.slice(0, 10)) && Number.isFinite(Date.parse(value)));

const SERVICES = ["KorService2", "Odii", "PhotoGalleryService1", "KorWithService2", "GoCamping",
  "Durunubi", "TatsCnctrRateService", "DataLabService", "TarRlteTarService1", "AreaTarDemDsService"] as const;
const service = z.enum(SERVICES);
type SourceService = z.infer<typeof service>;
const CLAIMS = ["EXPERIENCE", "NARRATIVE", "HERITAGE", "FACILITY", "OPERATING", "WALKING_ROUTE", "CROWD",
  "VISUAL_MOOD", "CONCENTRATION_FORECAST", "REGIONAL_VISITORS", "REGIONAL_DEMAND", "RELATED_PLACE"] as const;
type ClaimKind = typeof CLAIMS[number];

const SOURCES: Record<SourceService, { dataset: string; label: string; operations: string[]; claims: ClaimKind[] }> = {
  KorService2: { dataset: "15101578", label: "한국관광공사 관광정보", operations: ["detailCommon2", "detailIntro2", "detailInfo2", "detailImage2", "searchKeyword2", "areaBasedList2"], claims: ["EXPERIENCE", "NARRATIVE", "HERITAGE", "FACILITY", "OPERATING"] },
  Odii: { dataset: "15101971", label: "한국관광공사 관광 해설", operations: ["themeSearchList", "themeBasedList", "storyBasedList", "storySearchList"], claims: ["EXPERIENCE", "NARRATIVE"] },
  PhotoGalleryService1: { dataset: "15101914", label: "한국관광공사 관광사진", operations: ["gallerySearchList1", "galleryDetailList1"], claims: [] },
  KorWithService2: { dataset: "15101897", label: "한국관광공사 무장애 여행 정보", operations: ["searchKeyword2", "areaBasedList2", "detailCommon2", "detailWithTour2"], claims: ["FACILITY"] },
  GoCamping: { dataset: "15101933", label: "한국관광공사 고캠핑", operations: ["basedList", "basedSyncList", "searchList", "locationBasedList", "imageList"], claims: ["EXPERIENCE", "FACILITY", "OPERATING"] },
  Durunubi: { dataset: "15101974", label: "한국관광공사 두루누비", operations: ["courseList", "routeList"], claims: ["WALKING_ROUTE"] },
  TatsCnctrRateService: { dataset: "15128555", label: "한국관광공사 방문 집중 예측", operations: ["tatsCnctrRatedList"], claims: ["CONCENTRATION_FORECAST"] },
  DataLabService: { dataset: "15101972", label: "한국관광공사 지역별 방문자수", operations: ["locgoRegnVisitrDDList", "metcoRegnVisitrDDList"], claims: ["REGIONAL_VISITORS"] },
  TarRlteTarService1: { dataset: "15128560", label: "한국관광공사 연관 관광지", operations: ["areaBasedList1", "searchKeyword1"], claims: ["RELATED_PLACE"] },
  AreaTarDemDsService: { dataset: "15151868", label: "한국관광공사 지역 관광 수요", operations: ["areaTarSjrnDsList", "areaTarExpDsList"], claims: ["REGIONAL_DEMAND"] },
};

export const sourceReceipt = z.strictObject({
  schema_version: z.literal("source-receipt.v1"), service,
  operation: z.string().min(1).max(80), dataset_id: z.string().regex(/^\d{8}$/),
  request_scope: z.record(z.string(), z.string()), retrieved_at: utcDateTime,
  source_modified_at: utcDateTime.nullable(), reference_date: isoDate.nullable(),
  status: z.enum(["AVAILABLE", "EMPTY", "UNAVAILABLE"]), http_status: z.number().int().min(100).max(599).nullable(),
  response_sha256: digest.nullable(), reason: z.string().min(1).max(300),
}).refine((row) => {
  const source = SOURCES[row.service];
  return row.dataset_id === source.dataset && source.operations.includes(row.operation) &&
    !Object.keys(row.request_scope).some((key) => /servicekey|apikey|authorization|secret|token/i.test(key.replaceAll("_", ""))) &&
    (row.status === "UNAVAILABLE" || (row.http_status === 200 && row.response_sha256 !== null));
});

export const placeMatch = z.strictObject({
  place_id: stableId, service, provider_entity_id: stableId.nullable(),
  state: z.enum(["MATCHED", "NOT_MATCHED", "AMBIGUOUS"]),
  method: z.enum(["EXACT_ID_AND_LOCATION", "EXACT_NAME_AND_LOCATION", "EXACT_NAME_AND_OFFICIAL_LOCATION", "CURATED_CROSSWALK"]).nullable(),
  region_code: z.string().regex(/^\d{2,5}$/), evidence: z.array(z.string().min(1).max(500)),
  distance_meters: z.number().nonnegative().nullable(),
}).refine((row) => row.state === "MATCHED"
  ? row.provider_entity_id !== null && row.method !== null && row.evidence.length > 0
  : row.method === null);

export const sourceEvidence = z.strictObject({
  evidence_id: stableId, receipt: sourceReceipt, place_match: placeMatch.nullable(),
  scope: z.enum(["PLACE", "ROUTE", "REGION"]), modality: z.enum(["STRUCTURED", "TEXT", "IMAGE_PIXELS"]),
  source_field: z.string().min(1).max(100), excerpt: z.string().min(1).max(8_000), quote: z.string().min(1).max(4_000),
  image_sha256: digest.nullable(), image_license: z.literal("KOGL_TYPE_1").nullable(),
}).refine((row) => row.receipt.status === "AVAILABLE" && row.excerpt.includes(row.quote) &&
  (row.scope !== "PLACE" || row.place_match?.state === "MATCHED") &&
  (row.place_match === null || row.place_match.service === row.receipt.service) &&
  (row.modality === "IMAGE_PIXELS"
    ? ["KorService2", "PhotoGalleryService1", "GoCamping"].includes(row.receipt.service) && row.image_sha256 !== null && row.image_license !== null
    : row.image_sha256 === null && row.image_license === null));

export const sourceObservationSchema = z.strictObject({
  key: z.string().min(1).max(100), claim: z.enum(CLAIMS),
  state: z.enum(["SUPPORTED_FACT", "SUPPORTED_INFERENCE", "UNKNOWN"]),
  value: z.union([z.boolean(), z.number(), z.string(), z.null()]),
  evidence: z.array(sourceEvidence), reference_date: isoDate.nullable(), reason: z.string().min(1).max(1_000),
}).refine((row) => {
  if (row.state === "UNKNOWN") return row.value === null;
  if (row.value === null || !row.evidence.length || row.reference_date === null) return false;
  if (["FACILITY", "OPERATING", "HERITAGE", "CROWD"].includes(row.claim) && row.state !== "SUPPORTED_FACT") return false;
  return row.evidence.every((evidence) => {
    if (["REGIONAL_VISITORS", "REGIONAL_DEMAND"].includes(row.claim) && evidence.scope !== "REGION") return false;
    if (row.claim === "WALKING_ROUTE" && evidence.scope !== "ROUTE") return false;
    if (!["REGIONAL_VISITORS", "REGIONAL_DEMAND", "WALKING_ROUTE"].includes(row.claim) && evidence.scope !== "PLACE") return false;
    if (evidence.modality === "IMAGE_PIXELS") return row.claim === "VISUAL_MOOD";
    const receipt = evidence.receipt;
    if (!SOURCES[receipt.service].claims.includes(row.claim)) return false;
    if (receipt.service === "KorService2" && (receipt.operation === "detailImage2" ||
      (row.claim === "OPERATING" && receipt.operation !== "detailIntro2"))) return false;
    return receipt.service !== "KorWithService2" || receipt.operation === "detailWithTour2";
  });
});

export const tripContextPlace = z.strictObject({
  place_id: stableId, place_name_ko: z.string().min(1).max(240), facts: z.array(sourceObservationSchema),
  source_snapshot_sha256: digest.nullable(), state: z.enum(["AVAILABLE", "PARTIAL", "UNAVAILABLE"]),
  reason_ko: z.string().min(1).max(500),
}).refine((place) => new Set(place.facts.map((fact) => fact.key)).size === place.facts.length &&
  place.facts.every((fact) => fact.evidence.every((evidence) => evidence.place_match === null || evidence.place_match.place_id === place.place_id)));

const tripContextResponse = z.strictObject({
  schema_version: z.literal("itda.trip-context.v1"), recommendation_run_id: stableId,
  trip_input: z.custom<GroundedTripInput>((value) => parseGroundedTripInput(value) !== null),
  checked_at: utcDateTime, mode: z.enum(["PINNED", "REFRESHED"]), places: z.array(tripContextPlace),
}).refine((row) => new Set(row.places.map((place) => place.place_id)).size === row.places.length);

export type SourceObservation = z.infer<typeof sourceObservationSchema>;
export type TripContextPlace = z.infer<typeof tripContextPlace>;
export type TripContextResponse = z.infer<typeof tripContextResponse>;

export function sourceAttribution(source: SourceService): { label: string; url: string } {
  return { label: SOURCES[source].label, url: `https://www.data.go.kr/data/${SOURCES[source].dataset}/openapi.do` };
}

export function parseTripContextResponse(payload: unknown, expectedRunId?: string): TripContextResponse {
  const parsed = tripContextResponse.safeParse(payload);
  if (!parsed.success || (expectedRunId !== undefined && parsed.data.recommendation_run_id !== expectedRunId)) {
    throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  }
  return parsed.data;
}

export async function fetchTripContext(
  runId: string,
  options: { signal?: AbortSignal; fetchImpl?: typeof fetch } = {},
): Promise<TripContextResponse> {
  if (!stableId.safeParse(runId).success) throw new RecommendationContractError("INVALID_RECOMMENDATION_OUTPUT");
  let response: Response;
  try {
    response = await (options.fetchImpl ?? fetch)(`/v1/recommendation-runs/${encodeURIComponent(runId)}/trip-context`, {
      credentials: "same-origin", signal: options.signal,
    });
  } catch {
    throw new ApiRequestError("여행 조건 정보를 불러오지 못했어요.", null);
  }
  let payload: unknown;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new ApiRequestError("여행 조건 정보를 불러오지 못했어요.", response.status);
  return parseTripContextResponse(payload, runId);
}
