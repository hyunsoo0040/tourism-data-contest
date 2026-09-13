import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  ApiRequestError,
  createRecommendationRun,
  profileSubmissionFingerprint,
  recommendationErrorCode,
  type PreferenceProfile,
  type RecommendationRequest,
} from "../../api/api";
import { useJourneyAnnouncements } from "../../app/AppShell";
import { groundedTripForRecommendation, groundedTripInputSha256 } from "../journey/groundedTrip";
import { travelRegionName, useTravelRegions } from "../../api/recommendation-regions";
import { readConfirmedMoodReference } from "../photo/photoProjection";

type RecommendationPurpose = NonNullable<RecommendationRequest["purpose"]>;
const PURPOSES: ReadonlyArray<{ value: RecommendationPurpose; label: string }> = [
  { value: "SIGHTSEEING", label: "볼거리·체험" },
];

type PendingRecommendation = {
  schema_version: "phase5-pending-recommendation-v2" | "phase5-pending-recommendation-v3" | "phase5-pending-recommendation-v4";
  request_id: string;
  preference_profile_id: string;
  preference_input_sha256: string;
  photo_job_id: string | null;
  purpose?: RecommendationPurpose;
  grounded_input_sha256?: string;
};

type CurrentRecommendation = {
  schema_version: "phase5-current-recommendation-v2" | "phase5-current-recommendation-v3" | "phase5-current-recommendation-v4";
  recommendation_run_id: string;
  preference_profile_id: string;
  preference_input_sha256: string;
  photo_job_id: string | null;
  purpose?: RecommendationPurpose;
  grounded_input_sha256?: string;
};

type CTAState = "idle" | "loading" | "unavailable" | "insufficient" | "error" | "legacyPhoto";

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
        ...(["phase5-pending-recommendation-v3", "phase5-pending-recommendation-v4"].includes(String((parsed as Record<string, unknown>).schema_version)) ? ["purpose"] : []),
        ...((parsed as Record<string, unknown>).schema_version === "phase5-pending-recommendation-v4" ? ["grounded_input_sha256"] : []),
      ])
    ) {
      return null;
    }
    const pending = parsed as Record<string, unknown>;
    return (pending.schema_version === "phase5-pending-recommendation-v2" ||
      (["phase5-pending-recommendation-v3", "phase5-pending-recommendation-v4"].includes(String(pending.schema_version)) && PURPOSES.some(({ value }) => value === pending.purpose))) &&
      (pending.schema_version !== "phase5-pending-recommendation-v4" ||
        (typeof pending.grounded_input_sha256 === "string" && SHA256_PATTERN.test(pending.grounded_input_sha256))) &&
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
        ...(["phase5-current-recommendation-v3", "phase5-current-recommendation-v4"].includes(String((parsed as Record<string, unknown>).schema_version)) ? ["purpose"] : []),
        ...((parsed as Record<string, unknown>).schema_version === "phase5-current-recommendation-v4" ? ["grounded_input_sha256"] : []),
      ])
    ) {
      return null;
    }
    const current = parsed as Record<string, unknown>;
    return (current.schema_version === "phase5-current-recommendation-v2" ||
      (["phase5-current-recommendation-v3", "phase5-current-recommendation-v4"].includes(String(current.schema_version)) && PURPOSES.some(({ value }) => value === current.purpose))) &&
      (current.schema_version !== "phase5-current-recommendation-v4" ||
        (typeof current.grounded_input_sha256 === "string" && SHA256_PATTERN.test(current.grounded_input_sha256))) &&
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
  value: { preference_profile_id: string; preference_input_sha256: string; photo_job_id: string | null; purpose?: RecommendationPurpose; grounded_input_sha256?: string },
  profile: PreferenceProfile,
  inputSha256: string,
  photoJobId: string | null,
  purpose: RecommendationPurpose,
  groundedSha256: string | null,
) {
  // Historical runs considered every category, so they only match MIXED.
  return belongsToProfile(value, profile, inputSha256) && value.photo_job_id === photoJobId &&
    (value.purpose ?? "MIXED") === purpose && (value.grounded_input_sha256 ?? null) === groundedSha256;
}

export function ProfileRecommendationCTA({
  profile,
  photoJobId = null,
  onClearPhoto,
}: {
  profile: PreferenceProfile;
  photoJobId?: string | null;
  onClearPhoto?: () => void;
}) {
  const navigate = useNavigate();
  const [state, setState] = useState<CTAState>("idle");
  const purpose: RecommendationPurpose = "SIGHTSEEING";
  const [inputSha256, setInputSha256] = useState<string | null>(null);
  const [groundedSha256, setGroundedSha256] = useState<string | null>(null);
  const groundedInput = groundedTripForRecommendation();
  const travelRegions = useTravelRegions(groundedInput?.region_code != null);
  const groundedInputKey = JSON.stringify(groundedInput);
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
  }, [profile.profile_id, photoJobId, purpose, groundedInputKey]);

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
    void Promise.all([
      profileSubmissionFingerprint(profile.trip_conditions, profile),
      groundedTripInputSha256(groundedInput),
    ]).then(([digest, groundedDigest]) => {
      if (!active) return;
      const pending = readPending();
      const current = readCurrent();
      if (pending !== null && !modeMatches(pending, profile, digest, photoJobId, purpose, groundedDigest)) writePending(null);
      if (current !== null && !modeMatches(current, profile, digest, photoJobId, purpose, groundedDigest)) writeCurrent(null);
      setInputSha256(digest);
      setGroundedSha256(groundedDigest);
      setState("idle");
    });
    return () => {
      active = false;
    };
  }, [photoJobId, profile, purpose, groundedInputKey]);

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
    if (current !== null && modeMatches(current, profile, inputSha256, photoJobId, purpose, groundedSha256)) {
      void navigate(`/recommendations/${encodeURIComponent(current.recommendation_run_id)}`);
      return;
    }
    if (photoJobId !== null && readConfirmedMoodReference(profile.profile_id)?.photo_job_id !== photoJobId) {
      setState("legacyPhoto");
      return;
    }
    const stored = readPending();
    const pending: PendingRecommendation =
      stored !== null && modeMatches(stored, profile, inputSha256, photoJobId, purpose, groundedSha256)
        ? stored
        : {
            schema_version: groundedSha256 === null ? "phase5-pending-recommendation-v3" : "phase5-pending-recommendation-v4",
            request_id: crypto.randomUUID(),
            preference_profile_id: profile.profile_id,
            preference_input_sha256: inputSha256,
            photo_job_id: photoJobId,
            purpose,
            ...(groundedSha256 === null ? {} : { grounded_input_sha256: groundedSha256 }),
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
          purpose,
          grounded_input: groundedInput,
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
        schema_version: groundedSha256 === null ? "phase5-current-recommendation-v3" : "phase5-current-recommendation-v4",
        recommendation_run_id: created.recommendation_run_id,
        preference_profile_id: created.preference_profile_id,
        preference_input_sha256: created.preference_input_sha256,
        photo_job_id: photoJobId,
        purpose,
        ...(groundedSha256 === null ? {} : { grounded_input_sha256: groundedSha256 }),
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
      } else if (error instanceof ApiRequestError && recommendationErrorCode(error.body) === "INSUFFICIENT_ELIGIBLE_CANDIDATES") {
        setState("insufficient");
      } else {
        setState("error");
      }
    } finally {
      if (activeRequestRef.current === controller) activeRequestRef.current = null;
    }
  };

  const loading = state === "loading";
  const purposeSelector = (
    <>
    <p className="recommendation-region-choice" style={{ flexBasis: "100%" }}>여행 지역: <strong>{travelRegionName(groundedInput?.region_code, travelRegions.regions)}</strong>{" · "}
      <a href="/start?mode=edit">지역·조건 변경</a></p>
    <p className="recommendation-region-choice" style={{ flexBasis: "100%" }}>취향에 맞는 볼거리·체험을 추천해요.</p>
    </>
  );

  if (state === "insufficient") {
    return <>{purposeSelector}<section className="profile-state" role="status" style={{ flexBasis: "100%" }}>
      <h2>이 조건에 맞는 여행지가 아직 충분하지 않아요.</h2>
      <p>여행 조건을 조정하거나 다른 지역을 선택해 주세요. 선택한 지역 밖의 장소를 대신 추천하지 않아요.</p>
    </section></>;
  }

  if (state === "unavailable") {
    return (
      <>{purposeSelector}
      <section
        className="profile-state"
        data-status="NO_ACTIVE_SCORED_RELEASE"
        style={{ flexBasis: "100%" }}
      >
        <h2 ref={stateHeadingRef} tabIndex={-1}>추천 준비가 아직 끝나지 않았어요.</h2>
        <p>새 여행지 자료를 확인하고 있어요. 준비가 끝나면 추천을 다시 볼 수 있어요.</p>
        <button type="button" className="button button--primary" onClick={() => void submit()}>
          추천 준비 다시 확인
        </button>
        {announcements === null ? (
          <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            추천 준비 상태를 확인해 주세요.
          </p>
        ) : null}
      </section>
      </>
    );
  }

  if (state === "legacyPhoto") {
    return <>{purposeSelector}<section className="profile-state" role="status" style={{ flexBasis: "100%" }}>
      <h2>사진 분위기를 새로 확정해 주세요.</h2>
      <p>이전 사진 취향은 저장된 추천에서 확인할 수 있어요. 새 추천에는 사진의 분위기만 참고합니다.</p>
      {onClearPhoto && <button type="button" className="button button--primary" onClick={onClearPhoto}>사진 없이 계속하기</button>}
    </section></>;
  }

  if (state === "error") {
    return (
      <>{purposeSelector}
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
      </>
    );
  }

  return (
    <>
    {purposeSelector}
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
    </>
  );
}
