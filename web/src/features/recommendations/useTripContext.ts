import { useEffect, useState } from "react";

import { fetchTripContext, type TripContextPlace, type TripContextResponse } from "../../api/trip-context";

export type TripContextState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "resolved"; response: TripContextResponse; places: Map<string, TripContextPlace> };

export function useTripContext(runId: string | null, enabled = true): TripContextState {
  const [resolved, setResolved] = useState<{ runId: string; state: TripContextState } | null>(null);
  useEffect(() => {
    if (!enabled || !runId) return;
    const controller = new AbortController();
    setResolved({ runId, state: { kind: "loading" } });
    void fetchTripContext(runId, { signal: controller.signal }).then((response) => {
      if (!controller.signal.aborted) setResolved({ runId, state: {
        kind: "resolved", response, places: new Map(response.places.map((place) => [place.place_id, place])),
      } });
    }).catch(() => {
      if (!controller.signal.aborted) setResolved({ runId, state: { kind: "unavailable" } });
    });
    return () => controller.abort();
  }, [runId, enabled]);
  if (!enabled || !runId) return { kind: "idle" };
  return resolved?.runId === runId ? resolved.state : { kind: "loading" };
}
