import { useEffect, useLayoutEffect, useRef } from "react";
import { Link } from "react-router-dom";

import { useJourneyAnnouncements } from "../../app/AppShell";
import { RecommendationShell } from "./RecommendationShell";

export type RecommendationPageState =
  | "loading"
  | "NO_ACTIVE_SCORED_RELEASE"
  | "INSUFFICIENT_ELIGIBLE_CANDIDATES"
  | "RECOVERABLE_API_FAILURE"
  | "RECOMMENDATION_RUN_NOT_FOUND"
  | "RECOMMENDATION_PIN_INVALID"
  | "RECOMMENDATION_PLACE_UNAVAILABLE"
  | "COMPARE_SELECTION_INVALID"
  | "COMPARE_API_FAILURE";

const COPY = {
  loading: {
    heading: "경주 여행지 5곳을 고르고 있어요.",
    body: "확인된 기대 프로필과 장소 근거를 연결하고 있어요.",
    action: null,
  },
  NO_ACTIVE_SCORED_RELEASE: {
    heading: "추천 준비가 아직 끝나지 않았어요.",
    body: "검증된 점수 프로필 24곳이 모두 준비된 뒤에만 추천을 보여드려요. 잠시 후 다시 확인해 주세요.",
    action: "추천 준비 다시 확인",
  },
  INSUFFICIENT_ELIGIBLE_CANDIDATES: {
    heading: "추천 5곳을 만들지 못했어요.",
    body: "검증 조건을 통과한 장소가 5곳보다 적어요. 임의의 장소를 채우지 않고 준비 상태를 다시 확인할게요.",
    action: "추천 준비 다시 확인",
  },
  RECOVERABLE_API_FAILURE: {
    heading: "추천을 불러오지 못했어요.",
    body: "기대 프로필은 이 브라우저에 남아 있어요. 연결을 확인하고 다시 시도해 주세요.",
    action: "다시 시도하기",
  },
  RECOMMENDATION_RUN_NOT_FOUND: {
    heading: "이 추천 결과를 다시 확인할 수 없어요.",
    body: "기대 프로필로 돌아가 현재 기준의 새 추천을 만들어 주세요.",
    action: "기대 프로필로 돌아가기",
  },
  RECOMMENDATION_PIN_INVALID: {
    heading: "이 추천 결과를 다시 확인할 수 없어요.",
    body: "기대 프로필로 돌아가 현재 기준의 새 추천을 만들어 주세요.",
    action: "기대 프로필로 돌아가기",
  },
  RECOMMENDATION_PLACE_UNAVAILABLE: {
    heading: "이 추천 결과를 다시 확인할 수 없어요.",
    body: "기대 프로필로 돌아가 현재 기준의 새 추천을 만들어 주세요.",
    action: "기대 프로필로 돌아가기",
  },
  COMPARE_SELECTION_INVALID: {
    heading: "비교할 장소를 다시 선택해 주세요.",
    body: "같은 추천 실행에서 장소 2~3곳을 다시 선택해 주세요.",
    action: "추천 5곳으로 돌아가기",
  },
  COMPARE_API_FAILURE: {
    heading: "비교 정보를 불러오지 못했어요.",
    body: "선택한 장소는 이 브라우저에 남아 있어요. 연결을 확인하고 다시 시도해 주세요.",
    action: "다시 시도하기",
  },
} as const;

const UNKNOWN_COPY = {
  heading: "추천 상태를 확인하지 못했어요.",
  body: "기대 프로필은 이 브라우저에 남아 있어요. 잠시 후 다시 시도해 주세요.",
  action: "다시 시도하기",
} as const;

function isKnownState(state: string): state is RecommendationPageState {
  return Object.hasOwn(COPY, state);
}

export function RecommendationStatePage({
  state,
  onPrimary,
  primaryHref,
  statusMessage = "",
}: {
  state: RecommendationPageState | string;
  onPrimary?: () => void;
  primaryHref?: string;
  statusMessage?: string;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const announcements = useJourneyAnnouncements();
  const knownState = isKnownState(state) ? state : null;
  const copy = knownState === null ? UNKNOWN_COPY : COPY[knownState];
  const machineState = knownState ?? "UNKNOWN_RECOMMENDATION_STATE";
  const isAlert =
    knownState === null ||
    knownState === "RECOVERABLE_API_FAILURE" ||
    knownState === "COMPARE_API_FAILURE";

  useLayoutEffect(() => {
    headingRef.current?.focus();
  }, [state]);

  useEffect(() => {
    if (!isAlert) announcements?.announcePage(copy.body);
    if (statusMessage !== "") announcements?.announceInteraction(statusMessage);
  }, [announcements, copy.body, isAlert, statusMessage]);

  return (
    <RecommendationShell>
      <article
        className="recommendation-state panel"
        data-status={machineState}
        role={isAlert ? "alert" : undefined}
      >
        <p className="eyebrow">사진 없이 고른 경주 여행지</p>
        <h1 ref={headingRef} tabIndex={-1}>{copy.heading}</h1>
        <p>{copy.body}</p>
        {state === "loading" ? (
          <div className="recommendation-loading" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
        ) : null}
        {copy.action !== null && primaryHref !== undefined ? (
          <Link className="button button--primary" to={primaryHref}>
            {copy.action}
          </Link>
        ) : copy.action !== null && onPrimary !== undefined ? (
          <button className="button button--primary" type="button" onClick={onPrimary}>
            {copy.action}
          </button>
        ) : null}
        {statusMessage === "" ? null : <p>{statusMessage}</p>}
        {announcements === null && !isAlert ? (
          <p
            className="visually-hidden"
            role="status"
            aria-label={copy.body}
            aria-live="polite"
            aria-atomic="true"
          />
        ) : null}
      </article>
    </RecommendationShell>
  );
}
