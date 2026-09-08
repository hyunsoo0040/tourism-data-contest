import type { RefObject } from "react";

type RecoveryState = "empty" | "recovery" | "api-error" | "invalid";

const COPY = {
  empty: {
    title: "아직 만든 여행 기대 프로필이 없어요.",
    body: "여행 조건과 아홉 가지 질문에 답하면 이번 경주의 기대를 세 축으로 확인할 수 있어요.",
    action: "여행 조건 입력하기",
  },
  recovery: {
    title: "기대 프로필을 다시 만들 수 있어요.",
    body: "여행 조건과 아홉 가지 답변은 이 브라우저에 남아 있어요. 같은 답변으로 기대 프로필을 다시 만들어 주세요.",
    action: "프로필 다시 만들기",
  },
  "api-error": {
    title: "프로필을 만들지 못했어요.",
    body: "입력한 답변은 이 브라우저에 보관되어 있어요.",
    action: "다시 시도하기",
  },
  invalid: {
    title: "프로필 형식을 확인하지 못했어요.",
    body: "잠시 후 다시 시도해 주세요.",
    action: "다시 시도하기",
  },
} as const;

export function ProfileRecoveryState({
  state,
  busy = false,
  onPrimary,
  onReviewAnswers,
  headingRef,
}: {
  state: RecoveryState;
  busy?: boolean;
  onPrimary: () => void;
  onReviewAnswers?: () => void;
  headingRef?: RefObject<HTMLHeadingElement | null>;
}) {
  const copy = COPY[state];
  const isError = state === "api-error" || state === "invalid";
  return (
    <article className="profile-state" role={isError ? "alert" : undefined}>
      <p className="eyebrow">이번 여행의 기대 프로필</p>
      <h1 ref={headingRef} tabIndex={-1}>{copy.title}</h1>
      <p>{copy.body}</p>
      {busy ? <p role="status" aria-live="polite">여행 기대를 정리하고 있어요.</p> : null}
      <div className="profile-state__actions">
        <button type="button" className="button button--primary" onClick={onPrimary} disabled={busy} aria-busy={busy || undefined}>
          {busy && state === "recovery" ? "프로필 다시 만드는 중…" : copy.action}
        </button>
        {onReviewAnswers ? <button type="button" className="button button--secondary" onClick={onReviewAnswers}>답변 확인하기</button> : null}
      </div>
    </article>
  );
}
