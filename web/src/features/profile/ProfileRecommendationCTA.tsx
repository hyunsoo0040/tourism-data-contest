import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  ApiRequestError,
  createRecommendationRun,
  profileSubmissionFingerprint,
  recommendationErrorCode,
  type PreferenceProfile,
} from "../../api/api";
import { useJourneyAnnouncements } from "../../app/AppShell";

type PendingRecommendation = {
  schema_version: "phase5-pending-recommendation-v2";
  request_id: string;
  preference_profile_id: string;
  preference_input_sha256: string;
  photo_job_id: string | null;
};

type CurrentRecommendation = {
  schema_version: "phase5-current-recommendation-v2";
  recommendation_run_id: string;
  preference_profile_id: string;
  preference_input_sha256: string;
  photo_job_id: string | null;
};

type CTAState = "idle" | "loading" | "unavailable" | "error";

const PENDING_KEY = "itda:phase5:pending-recommendation:v2";
const CURRENT_KEY = "itda:phase5:current-recommendation:v2";
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
let memoryPending: PendingRecommendation | null = null;
let memoryCurrent: CurrentRecommendation | null = null;

function exactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function parsePending(value: string | null): PendingRecommendation | null {
  if (value === null || value.length > 1_024) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      !exactKeys(parsed as Record<string, unknown>, [
        "photo_job_id",
        "preference_input_sha256",
        "preference_profile_id",
        "request_id",
        "schema_version",
      ])
    ) {
      return null;
    }
    const pending = parsed as Record<string, unknown>;
    return pending.schema_version === "phase5-pending-recommendation-v2" &&
      typeof pending.request_id === "string" &&
      pending.request_id.length > 0 &&
      pending.request_id.length <= 160 &&
      typeof pending.preference_profile_id === "string" &&
      pending.preference_profile_id.length > 0 &&
      pending.preference_profile_id.length <= 160 &&
      typeof pending.preference_input_sha256 === "string" &&
      SHA256_PATTERN.test(pending.preference_input_sha256) &&
      (pending.photo_job_id === null ||
        (typeof pending.photo_job_id === "string" && SHA256_PATTERN.test(pending.photo_job_id)))
      ? (pending as PendingRecommendation)
      : null;
  } catch {
    return null;
  }
}

function parseCurrent(value: string | null): CurrentRecommendation | null {
  if (value === null || value.length > 1_024) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      !exactKeys(parsed as Record<string, unknown>, [
        "photo_job_id",
        "preference_input_sha256",
        "preference_profile_id",
        "recommendation_run_id",
        "schema_version",
      ])
    ) {
      return null;
    }
    const current = parsed as Record<string, unknown>;
    return current.schema_version === "phase5-current-recommendation-v2" &&
      typeof current.recommendation_run_id === "string" &&
      current.recommendation_run_id.length > 0 &&
      current.recommendation_run_id.length <= 160 &&
      typeof current.preference_profile_id === "string" &&
      current.preference_profile_id.length > 0 &&
      current.preference_profile_id.length <= 160 &&
      typeof current.preference_input_sha256 === "string" &&
      SHA256_PATTERN.test(current.preference_input_sha256) &&
      (current.photo_job_id === null ||
        (typeof current.photo_job_id === "string" && SHA256_PATTERN.test(current.photo_job_id)))
      ? (current as CurrentRecommendation)
      : null;
  } catch {
    return null;
  }
}

function readPending() {
  try {
    const raw = window.sessionStorage.getItem(PENDING_KEY);
    const parsed = parsePending(raw);
    if (raw !== null && parsed === null) window.sessionStorage.removeItem(PENDING_KEY);
    return parsed ?? memoryPending;
  } catch {
    return memoryPending;
  }
}

function readCurrent() {
  try {
    const raw = window.sessionStorage.getItem(CURRENT_KEY);
    const parsed = parseCurrent(raw);
    if (raw !== null && parsed === null) window.sessionStorage.removeItem(CURRENT_KEY);
    return parsed ?? memoryCurrent;
  } catch {
    return memoryCurrent;
  }
}

function writePending(value: PendingRecommendation | null) {
  memoryPending = value;
  try {
    if (value === null) window.sessionStorage.removeItem(PENDING_KEY);
    else window.sessionStorage.setItem(PENDING_KEY, JSON.stringify(value));
  } catch {
    // The bounded in-memory fallback remains available for this page lifetime.
  }
}

function writeCurrent(value: CurrentRecommendation | null) {
  memoryCurrent = value;
  try {
    if (value === null) window.sessionStorage.removeItem(CURRENT_KEY);
    else window.sessionStorage.setItem(CURRENT_KEY, JSON.stringify(value));
  } catch {
    // The bounded in-memory fallback remains available for this page lifetime.
  }
}

export function clearCurrentRecommendationReferenceIfMatches(runId: string): boolean {
  const current = readCurrent();
  if (current?.recommendation_run_id !== runId) return false;
  writeCurrent(null);
  return true;
}

function belongsToProfile(
  value: { preference_profile_id: string; preference_input_sha256: string },
  profile: PreferenceProfile,
  inputSha256: string,
) {
  return (
    value.preference_profile_id === profile.profile_id &&
    value.preference_input_sha256 === inputSha256
  );
}

function modeMatches(
  value: { preference_profile_id: string; preference_input_sha256: string; photo_job_id: string | null },
  profile: PreferenceProfile,
  inputSha256: string,
  photoJobId: string | null,
) {
  return belongsToProfile(value, profile, inputSha256) && value.photo_job_id === photoJobId;
}

export function ProfileRecommendationCTA({
  profile,
  photoJobId = null,
}: {
  profile: PreferenceProfile;
  photoJobId?: string | null;
}) {
  const navigate = useNavigate();
  const [state, setState] = useState<CTAState>("idle");
  const [inputSha256, setInputSha256] = useState<string | null>(null);
  const stateHeadingRef = useRef<HTMLHeadingElement>(null);
  const activeRequestRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);
  const announcements = useJourneyAnnouncements();

  useLayoutEffect(() => {
    generationRef.current += 1;
    activeRequestRef.current?.abort();
    activeRequestRef.current = null;
    setInputSha256(null);
    setState("idle");
    const pending = readPending();
    const current = readCurrent();
    if (pending !== null && pending.preference_profile_id !== profile.profile_id) {
      writePending(null);
    }
    if (current !== null && current.preference_profile_id !== profile.profile_id) {
      writeCurrent(null);
    }
  }, [profile.profile_id, photoJobId]);

  useEffect(
    () => () => {
      generationRef.current += 1;
      activeRequestRef.current?.abort();
    },
    [],
  );

  useEffect(() => {
    generationRef.current += 1;
    activeRequestRef.current?.abort();
    activeRequestRef.current = null;
    let active = true;
    // The fingerprint uses the profile's own generation tuple: legacy v1
    // profiles keep matching their historical pending/current records instead
    // of being hashed as if they were v2 submissions.
    void profileSubmissionFingerprint(profile.trip_conditions, profile).then((digest) => {
      if (!active) return;
      const pending = readPending();
      const current = readCurrent();
      if (pending !== null && !modeMatches(pending, profile, digest, photoJobId)) writePending(null);
      if (current !== null && !modeMatches(current, profile, digest, photoJobId)) writeCurrent(null);
      setInputSha256(digest);
      setState("idle");
    });
    return () => {
      active = false;
    };
  }, [photoJobId, profile]);

  useEffect(() => {
    if (state === "unavailable" || state === "error") {
      window.setTimeout(() => stateHeadingRef.current?.focus(), 0);
      announcements?.announcePage(
        state === "unavailable"
          ? "추천 준비 상태를 확인해 주세요."
          : "추천 요청을 다시 시도할 수 있어요.",
      );
    }
  }, [announcements, state]);

  const submit = async () => {
    if (state === "loading" || inputSha256 === null) return;
    const current = readCurrent();
    if (current !== null && modeMatches(current, profile, inputSha256, photoJobId)) {
      void navigate(`/recommendations/${encodeURIComponent(current.recommendation_run_id)}`);
      return;
    }
    const stored = readPending();
    const pending =
      stored !== null && modeMatches(stored, profile, inputSha256, photoJobId)
        ? stored
        : {
            schema_version: "phase5-pending-recommendation-v2" as const,
            request_id: crypto.randomUUID(),
            preference_profile_id: profile.profile_id,
            preference_input_sha256: inputSha256,
            photo_job_id: photoJobId,
          };
    writePending(pending);
    setState("loading");
    const generation = generationRef.current;
    const controller = new AbortController();
    activeRequestRef.current?.abort();
    activeRequestRef.current = controller;
    try {
      const created = await createRecommendationRun(
        {
          request_id: pending.request_id,
          preference_profile_id: pending.preference_profile_id,
          ...(pending.photo_job_id === null
            ? {}
            : { photo_job_id: pending.photo_job_id }),
        },
        { signal: controller.signal },
      );
      if (
        controller.signal.aborted ||
        activeRequestRef.current !== controller ||
        generationRef.current !== generation
      )
        return;
      if (created.preference_input_sha256 !== inputSha256) {
        setState("error");
        return;
      }
      writeCurrent({
        schema_version: "phase5-current-recommendation-v2",
        recommendation_run_id: created.recommendation_run_id,
        preference_profile_id: created.preference_profile_id,
        preference_input_sha256: created.preference_input_sha256,
        photo_job_id: photoJobId,
      });
      writePending(null);
      void navigate(`/recommendations/${encodeURIComponent(created.recommendation_run_id)}`);
    } catch (error) {
      if (controller.signal.aborted || generationRef.current !== generation) return;
      if (
        error instanceof ApiRequestError &&
        error.status === 503 &&
        recommendationErrorCode(error.body) === "NO_ACTIVE_SCORED_RELEASE"
      ) {
        setState("unavailable");
      } else {
        setState("error");
      }
    } finally {
      if (activeRequestRef.current === controller) activeRequestRef.current = null;
    }
  };

  if (state === "unavailable") {
    return (
      <section
        className="profile-state"
        data-status="NO_ACTIVE_SCORED_RELEASE"
        style={{ flexBasis: "100%" }}
      >
        <h2 ref={stateHeadingRef} tabIndex={-1}>추천 준비가 아직 끝나지 않았어요.</h2>
        <p>검증된 점수 프로필 24곳이 모두 준비된 뒤에만 추천을 보여드려요. 잠시 후 다시 확인해 주세요.</p>
        <button type="button" className="button button--primary" onClick={() => void submit()}>
          추천 준비 다시 확인
        </button>
        {announcements === null ? (
          <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            추천 준비 상태를 확인해 주세요.
          </p>
        ) : null}
      </section>
    );
  }

  if (state === "error") {
    return (
      <section className="profile-state" data-status="RECOVERABLE_API_FAILURE" style={{ flexBasis: "100%" }}>
        <h2 ref={stateHeadingRef} tabIndex={-1}>추천을 불러오지 못했어요.</h2>
        <p>기대 프로필은 이 브라우저에 남아 있어요. 연결을 확인하고 다시 시도해 주세요.</p>
        <button type="button" className="button button--primary" onClick={() => void submit()}>
          다시 시도하기
        </button>
        {announcements === null ? (
          <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            추천 요청을 다시 시도할 수 있어요.
          </p>
        ) : null}
      </section>
    );
  }

  const loading = state === "loading";
  return (
    <button
      type="button"
      className="button button--primary"
      style={{ flexBasis: "100%" }}
      disabled={loading || inputSha256 === null}
      aria-busy={loading}
      onClick={() => void submit()}
    >
      {loading
        ? "추천 5곳 고르는 중…"
        : photoJobId === null
          ? "바로 추천 보기"
          : "사진 취향을 반영해 추천 보기"}
    </button>
  );
}
