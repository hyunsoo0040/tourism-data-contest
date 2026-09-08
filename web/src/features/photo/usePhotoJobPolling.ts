import { useEffect, useRef, useState } from "react";

import { PHOTO_STATUS_COPY, type PhotoJobPublicState } from "./PhotoJobStatus";

/**
 * Bounded photo-job polling.
 *
 * Frozen cadence: one immediate check, then 1.5s intervals for the first ten
 * checks, then 3s. One request in flight at any time. Hidden pages pause and
 * visibility resumes with an immediate check. Unmount aborts the in-flight
 * request and stops the cadence. A 60s deadline trips onTimeout exactly once
 * and stops all further requests. Announcements fire once per meaningful
 * state transition, never once per poll.
 */

export type PhotoJobSnapshotLike = {
  job_id: string;
  state: PhotoJobPublicState | string;
  uploaded_count?: number;
  selected_count?: number;
  trait_candidates?: unknown;
  deletion?: { residue_verified: boolean; ledger_recorded: boolean } | null;
  cleanup_pending?: boolean;
};

const FIRST_INTERVAL_MS = 1_500;
const STEADY_INTERVAL_MS = 3_000;
const FAST_CHECKS = 10;
const DEADLINE_MS = 60_000;

const TERMINAL_STATES: ReadonlySet<string> = new Set([
  "succeeded",
  "failed",
  "expired",
  "deleted",
]);

function announcementFor(state: PhotoJobPublicState | string): string | null {
  if (typeof state !== "string" || !Object.hasOwn(PHOTO_STATUS_COPY, state)) return null;
  const copy = PHOTO_STATUS_COPY[state as PhotoJobPublicState];
  // The full sentence pair carries the meaningful transition words; it is
  // announced once per transition, never once per poll.
  return copy.body === "" ? copy.heading : `${copy.heading} ${copy.body}`;
}

export function usePhotoJobPolling({
  jobId,
  fetchJobState,
  onAnnounce,
  onTimeout,
  onMalformed,
  onError,
  enabled = true,
}: {
  jobId: string;
  fetchJobState: (signal: AbortSignal) => Promise<PhotoJobSnapshotLike>;
  onAnnounce: (message: string) => void;
  onTimeout: () => void;
  onMalformed?: () => void;
  onError?: () => void;
  /** No request may exist before a durable job identity is present. */
  enabled?: boolean;
}): PhotoJobSnapshotLike | null {
  const [snapshot, setSnapshot] = useState<PhotoJobSnapshotLike | null>(null);
  const snapshotRef = useRef<PhotoJobSnapshotLike | null>(null);
  const checkCountRef = useRef(0);
  const timerRef = useRef<number | null>(null);
  const deadlineRef = useRef<number | null>(null);
  const controllerRef = useRef<AbortController | null>(null);
  const inFlightRef = useRef(false);
  const doneRef = useRef(false);
  const hiddenRef = useRef(false);
  const lastAnnouncedRef = useRef<string | null>(null);
  const fetchRef = useRef(fetchJobState);
  const announceRef = useRef(onAnnounce);
  const timeoutRef = useRef(onTimeout);
  const onMalformedRef = useRef(onMalformed ?? (() => undefined));
  const onErrorRef = useRef(onError ?? (() => undefined));
  fetchRef.current = fetchJobState;
  announceRef.current = onAnnounce;
  timeoutRef.current = onTimeout;
  onMalformedRef.current = onMalformed ?? (() => undefined);
  onErrorRef.current = onError ?? (() => undefined);

  useEffect(() => {
    if (!enabled || jobId === "") return;
    doneRef.current = false;
    checkCountRef.current = 0;
    lastAnnouncedRef.current = null;

    const stop = () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      if (deadlineRef.current !== null) {
        window.clearTimeout(deadlineRef.current);
        deadlineRef.current = null;
      }
    };

    const schedule = (delay: number) => {
      if (doneRef.current || hiddenRef.current || inFlightRef.current) return;
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null;
        void check();
      }, delay);
    };

    const check = async () => {
      if (doneRef.current || hiddenRef.current || inFlightRef.current) return;
      inFlightRef.current = true;
      const controller = new AbortController();
      controllerRef.current = controller;
      let nextDelay: number | null = null;
      try {
        const next = await fetchRef.current(controller.signal);
        if (doneRef.current || controller.signal.aborted) return;
        // Ownership check: a snapshot naming any other job is treated as
        // malformed — polling stops permanently and onMalformed fires once.
        if (typeof next?.job_id === "string" && next.job_id !== jobId) {
          const mismatch = new Error("ownership mismatch") as Error & {
            malformed?: boolean;
          };
          mismatch.malformed = true;
          throw mismatch;
        }
        checkCountRef.current += 1;
        snapshotRef.current = next;
        setSnapshot(next);
        if (next.state !== lastAnnouncedRef.current) {
          lastAnnouncedRef.current = next.state;
          const message = announcementFor(next.state);
          if (message !== null) announceRef.current(message);
        }
        if (TERMINAL_STATES.has(next.state)) {
          doneRef.current = true;
          stop();
          return;
        }
        nextDelay =
          checkCountRef.current < FAST_CHECKS ? FIRST_INTERVAL_MS : STEADY_INTERVAL_MS;
      } catch (error) {
        if (doneRef.current || controller.signal.aborted) return;
        const malformed =
          error instanceof Error && (error as Error & { malformed?: boolean }).malformed === true;
        if (malformed) {
          // Unknown/malformed state: stop all requests and surface the
          // bounded fallback without rendering partial results.
          doneRef.current = true;
          stop();
          onMalformedRef.current();
          return;
        }
        doneRef.current = true;
        stop();
        onErrorRef.current();
        return;
      } finally {
        if (controllerRef.current === controller) controllerRef.current = null;
        inFlightRef.current = false;
      }
      // Scheduling happens after the in-flight flag clears so the guard in
      // schedule() cannot swallow the next tick.
      if (nextDelay !== null) schedule(nextDelay);
    };

    deadlineRef.current = window.setTimeout(() => {
      if (doneRef.current) return;
      doneRef.current = true;
      stop();
      controllerRef.current?.abort();
      timeoutRef.current();
    }, DEADLINE_MS);

    void check();

    const handleVisibility = () => {
      hiddenRef.current = document.visibilityState === "hidden";
      if (hiddenRef.current) {
        if (timerRef.current !== null) {
          window.clearTimeout(timerRef.current);
          timerRef.current = null;
        }
        return;
      }
      if (!doneRef.current && !inFlightRef.current) void check();
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      doneRef.current = true;
      stop();
      document.removeEventListener("visibilitychange", handleVisibility);
      controllerRef.current?.abort();
      controllerRef.current = null;
    };
  }, [jobId, enabled]);

  return snapshot;
}
