import { useEffect, useState } from "react";
import { z } from "zod";

const regionsSchema = z.strictObject({ candidate_sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(), regions: z.array(z.strictObject({
  region_code: z.string().regex(/^\d{2}$/), region_name: z.string().min(1).max(160), place_count: z.number().int().positive(),
})).refine((rows) => new Set(rows.map((row) => row.region_code)).size === rows.length) });
export type TravelRegion = z.infer<typeof regionsSchema>["regions"][number];
type RegionState = { kind: "loading" | "unavailable"; regions: TravelRegion[] } | { kind: "resolved"; regions: TravelRegion[] };

export function parseRecommendationRegions(payload: unknown): TravelRegion[] {
  return regionsSchema.parse(payload).regions;
}

/** Region names and codes come from the current published catalogue. */
export function useTravelRegions(enabled = true) {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<RegionState>({ kind: "loading", regions: [] });
  useEffect(() => {
    if (!enabled) { setState({ kind: "resolved", regions: [] }); return; }
    const controller = new AbortController();
    setState({ kind: "loading", regions: [] });
    void fetch("/v1/recommendation-regions", { signal: controller.signal, credentials: "same-origin" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Regions unavailable");
        const regions = parseRecommendationRegions(await response.json());
        if (!controller.signal.aborted) setState({ kind: "resolved", regions });
      }).catch(() => { if (!controller.signal.aborted) setState({ kind: "unavailable", regions: [] }); });
    return () => controller.abort();
  }, [attempt, enabled]);
  return { ...state, refresh: () => setAttempt((current) => current + 1) };
}

export function travelRegionName(code: string | null | undefined, regions: TravelRegion[]): string {
  return code == null ? "전국" : regions.find((region) => region.region_code === code)?.region_name ?? "선택한 지역";
}
