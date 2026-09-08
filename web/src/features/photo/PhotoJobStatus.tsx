import { useEffect, useRef, type ReactNode } from "react";

import { useJourneyAnnouncements } from "../../app/AppShell";

/**
 * Closed copy map for the six public photo-job states. The server vocabulary
 * is exactly queued|running|succeeded|failed|expired|deleted; anything else is
 * malformed and must fall back without rendering partial results.
 */

export type PhotoJobPublicState =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "expired"
  | "deleted";

export const PHOTO_STATUS_COPY: Record<
  PhotoJobPublicState,
  { heading: string; body: string; role: "status" | "alert" }
> = {
  queued: {
    heading: "사진 분석을 준비하고 있어요.",
    body: "사진을 안전하게 확인했고 분석 순서를 기다리고 있어요. 사진 없이 추천은 언제든 바로 볼 수 있어요.",
    role: "status",
  },
  running: {
    heading: "사진에서 여행 취향 후보를 찾고 있어요.",
    body: "완료 비율을 추측해 표시하지 않아요. 분석이 끝나면 직접 확인할 제안을 보여드릴게요.",
    role: "status",
  },
  succeeded: {
    heading: "원본 사진 삭제를 확인하고 있어요.",
    body: "추천은 사진 없이 바로 계속할 수 있어요. 삭제 확인이 끝나기 전에는 원본이 삭제됐다고 표시하지 않아요.",
    role: "status",
  },
  failed: {
    heading: "사진 분석을 마치지 못했어요.",
    body: "사진 없이 추천을 바로 계속할 수 있어요.",
    role: "alert",
  },
  expired: {
    heading: "사진 작업 시간이 지나 분석을 이어갈 수 없어요.",
    body: "",
    role: "alert",
  },
  deleted: {
    heading: "삭제를 요청했어요.",
    body: "원본 사진이 남지 않았는지 계속 확인하고 있어요.",
    role: "status",
  },
};

export const PHOTO_FALLBACK_COPY = {
  uploadUncertainty:
    "사진을 보내지 못했어요. 다시 시도하거나 사진 없이 추천을 계속해 주세요.",
  storageProviderUnavailable:
    "사진 분석을 지금 사용할 수 없어요. 사진은 외부 분석으로 전송되지 않았어요.",
  timeout: "기다리는 시간이 길어 사진 분석을 중단했어요. 사진 없이 추천을 바로 계속할 수 있어요.",
  expired: "사진 작업 시간이 지나 분석을 이어갈 수 없어요.",
  restart: "새 사진으로 다시 시작하기",
  deletedVerified: "원본 사진과 이 작업의 분석 제안을 삭제했어요.",
  deletePending: "삭제를 요청했어요. 원본 사진이 남지 않았는지 계속 확인하고 있어요.",
  refreshDeletion: "삭제 상태 다시 확인",
  pollError:
    "사진 진행 상태를 확인하지 못했어요. 연결을 확인하거나 사진 없이 추천을 계속해 주세요.",
  unknown: "사진 작업 상태를 확인하지 못했어요. 분석 결과를 사용하지 않고 사진 없이 계속해 주세요.",
  directEntry: "이 사진 작업을 다시 확인할 수 없어요. 사진 없이 추천을 계속해 주세요.",
  storageUnavailable:
    "이 브라우저에 사진 진행 상태를 저장하지 못했어요. 이 탭에서는 계속할 수 있지만, 화면을 닫으면 다시 이어서 확인하지 못할 수 있어요. 사진 파일은 브라우저 저장소에 보관하지 않아요.",
} as const;

/**
 * UI-derived states: never persisted server truth, rendered with the same
 * closed-copy discipline as the six public states. `cleanup_pending` is
 * derived only when deletion proof is incomplete; `deleted` completion still
 * requires dual residue+ledger evidence.
 */
export type PhotoJobUiDerivedState = "uploading" | "timeout" | "cleanup_pending" | "poll_error" | "unknown";

const PHOTO_UI_DERIVED_COPY: Record<
  PhotoJobUiDerivedState,
  { heading: string; body: string; role: "status" | "alert" }
> = {
  uploading: {
    heading: "사진 분석을 준비하고 있어요.",
    body: "",
    role: "status",
  },
  timeout: {
    heading: PHOTO_FALLBACK_COPY.timeout,
    body: "",
    role: "status",
  },
  cleanup_pending: {
    heading: PHOTO_STATUS_COPY.deleted.heading,
    body: PHOTO_FALLBACK_COPY.deletePending,
    role: "status",
  },
  poll_error: {
    heading: PHOTO_FALLBACK_COPY.pollError,
    body: "",
    role: "alert",
  },
  unknown: {
    heading: PHOTO_FALLBACK_COPY.unknown,
    body: "",
    role: "alert",
  },
};

function derivedCopy(
  state: string,
  fallbackBody?: string,
): { heading: string; body: string; role: "status" | "alert" } | null {
  if (Object.hasOwn(PHOTO_UI_DERIVED_COPY, state)) {
    const copy = PHOTO_UI_DERIVED_COPY[state as PhotoJobUiDerivedState];
    return fallbackBody === undefined ? copy : { ...copy, body: fallbackBody };
  }
  return null;
}

export const PHOTO_FAILED_HEADING = PHOTO_STATUS_COPY.failed.heading;

function isKnownState(state: string): state is PhotoJobPublicState {
  return Object.hasOwn(PHOTO_STATUS_COPY, state);
}

export type PhotoJobDeletionEvidence = {
  residue_verified: boolean;
  ledger_recorded: boolean;
};

export function PhotoJobStatus({
  state,
  deletion,
  fallbackBody,
  focusHeading = false,
  children,
}: {
  state: PhotoJobPublicState | string;
  /** Explicit deletion evidence; omit (undefined) when not a deletion view. */
  deletion?: PhotoJobDeletionEvidence | null;
  fallbackBody?: string;
  focusHeading?: boolean;
  children?: ReactNode;
}) {
  const known = isKnownState(state) ? state : null;
  const derived = known === null ? derivedCopy(state, fallbackBody) : null;
  const copy = known !== null ? PHOTO_STATUS_COPY[known] : derived;
  const headingRef = useRef<HTMLHeadingElement>(null);
  const announcements = useJourneyAnnouncements();
  const alert = copy?.role === "alert";
  const busy = state === "queued" || state === "running" || state === "uploading";

  useEffect(() => {
    if (!focusHeading) return;
    headingRef.current?.focus();
  }, [focusHeading, state]);

  useEffect(() => {
    if (copy !== null && !alert && copy.body !== "" && fallbackBody === undefined) {
      announcements?.announcePage(copy.body);
    }
  }, [announcements, alert, copy, fallbackBody]);

  if (copy === null) {
    return (
      <article className="profile-state" role="alert" style={{ padding: "var(--space-lg)" }}>
        <h1 ref={headingRef} tabIndex={-1}>
          {PHOTO_FALLBACK_COPY.unknown}
        </h1>
        {children}
      </article>
    );
  }

  const deletionProvided = deletion !== undefined;
  const deletionVerified =
    state === "deleted" &&
    deletion?.residue_verified === true &&
    deletion?.ledger_recorded === true;

  return (
    <article
      className="profile-state"
      data-photo-status={state}
      role={alert ? "alert" : "status"}
      aria-live="polite"
      aria-atomic="true"
      aria-busy={busy || undefined}
      style={{ padding: "var(--space-lg)" }}
    >
      <h1 ref={headingRef} tabIndex={-1}>
        {copy.heading}
      </h1>
      {copy.body !== "" ? <p>{copy.body}</p> : null}
      {state === "running" || state === "uploading" ? (
        <div className="profile-loading" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      ) : null}
      {deletionVerified ? <p>{PHOTO_FALLBACK_COPY.deletedVerified}</p> : null}
      {deletionProvided && state === "deleted" && !deletionVerified ? (
        <p>{PHOTO_FALLBACK_COPY.deletePending}</p>
      ) : null}
      {children}
    </article>
  );
}
