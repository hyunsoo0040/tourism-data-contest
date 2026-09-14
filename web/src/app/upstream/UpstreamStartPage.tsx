"use client";

import { JOURNEY_COPY } from "../../content/journey.ko";
import { useEffect, useRef, useState } from "react";
import { ApiRequestError, fetchPreferenceProfile } from "../../api/api";
import { createAndStorePreferenceProfile } from "../../features/profile/profileSubmission";
import { readProfileReference } from "../storage";

import { TripConditionForm } from "../../features/journey/TripConditionForm";
import { quizNavigationState } from "../../features/journey/quizNavigation";
import { useNavigate, useSearchParams } from "../react-router-dom";
import { useJourneyDraft } from "../AppShell";
import {
  type TripConditionFormValues,
  type TripConditions,
  questionnaireAnswersSchema,
} from "../schemas";

function formValues(conditions: Partial<TripConditions> | undefined): TripConditionFormValues {
  return {
    visit_date: conditions?.visit_date ?? "",
    visit_time: conditions?.visit_time ?? "",
    companion: conditions?.companion ?? "",
    transport: conditions?.transport ?? "",
    walking_tolerance: conditions?.walking_tolerance ?? "",
    indoor_outdoor_preference: conditions?.indoor_outdoor_preference ?? "",
    crowd_avoidance: conditions?.crowd_avoidance ?? "",
  };
}

export function UpstreamStartPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [resumeEnabled, setResumeEnabled] = useState(searchParams.get("resume") === "profile");
  const [busy, setBusy] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const activeRequest = useRef<AbortController | null>(null);
  const { state, draft, updateDraft, resetDraft, dismissNotice, reportStorageUnavailable } =
    useJourneyDraft();
  const recovered = state === "recovered";

  useEffect(() => {
    setResumeEnabled(searchParams.get("resume") === "profile");
    return () => { activeRequest.current?.abort(); activeRequest.current = null; };
  }, [searchParams.get("resume")]);

  const beginQuiz = (conditions: TripConditions) => {
    updateDraft({
      trip_conditions: conditions,
      current_route: "/quiz",
      current_question: 1,
    });
    void navigate("/quiz", { state: quizNavigationState(1) });
  };

  const submitTrip = async (conditions: TripConditions) => {
    if (activeRequest.current !== null) return;
    const reference = resumeEnabled ? readProfileReference().profile : null;
    if (reference === null) {
      beginQuiz(conditions);
      return;
    }
    const controller = new AbortController();
    activeRequest.current = controller;
    const current = () => activeRequest.current === controller && !controller.signal.aborted;
    setBusy(true);
    setRequestError(null);
    try {
      // Use the completed server result, not a possibly incomplete local draft.
      const previous = await fetchPreferenceProfile(reference.profile_id, { signal: controller.signal });
      if (!current()) return;
      const answers = questionnaireAnswersSchema.safeParse(previous.answers);
      if (!answers.success) {
        setResumeEnabled(false);
        setRequestError("이전 답변을 현재 테스트에 사용할 수 없어요. 여행 조건은 유지되며, 취향 테스트를 다시 진행해 주세요.");
        return;
      }
      const result = await createAndStorePreferenceProfile(conditions, answers.data, controller.signal, current);
      if (!current()) return;
      updateDraft({ current_route: "/profile", trip_conditions: conditions, answers: answers.data });
      if (result.reference?.state === "memory-fallback") reportStorageUnavailable();
      void navigate("/profile", { state: {
        announcement: "기존 취향 답변에 이번 여행 조건을 반영했어요.",
        focusProfile: true,
      } });
    } catch (error) {
      if (!current()) return;
      if (error instanceof ApiRequestError && error.status === 404) {
        setResumeEnabled(false);
        setRequestError("이전 테스트 결과를 찾지 못했어요. 여행 조건은 유지되며, 취향 테스트를 다시 진행해 주세요.");
      } else {
        setRequestError("기존 테스트 결과를 반영하지 못했어요. 입력한 여행 조건을 유지한 채 다시 시도해 주세요.");
      }
    } finally {
      if (current()) { activeRequest.current = null; setBusy(false); }
    }
  };

  const resetTrip = () => {
    const succeeded = resetDraft();
    if (succeeded) {
      activeRequest.current?.abort();
      activeRequest.current = null;
      setBusy(false);
      setResumeEnabled(false);
      setRequestError(null);
    }
    return succeeded;
  };

  return (
    <div className="up-root">
      <div className="up-start" data-journey-surface="start">
        <header className="topbar">
          <a className="brand" href="/" aria-label="IT-DA 소개로 이동">
            <img className="brand-mark-image" src="/itda-logo-icon.png" alt="" />
            <strong className="brand-wordmark">IT-DA</strong>
          </a>
          <a className="back-link" href="/">소개로 돌아가기</a>
        </header>

        <main>
          <section className="up-conditions" aria-label="여행 조건 입력">
            <div className="panel up-conditions-panel">
              <div className="up-conditions-head">
                <p className="eyebrow">Travel Conditions</p>
                <h1 id="start-heading">{JOURNEY_COPY.start.title}</h1>
                <p>
                  <br />{resumeEnabled
                    ? "이번 여행의 조건을 선택해 주세요. 저장된 취향 답변을 사용해 테스트 없이 프로필로 이어집니다."
                    : JOURNEY_COPY.start.description}
                </p>
              </div>
              <TripConditionForm
                defaultValues={formValues(draft?.trip_conditions)}
                recovered={recovered}
                onDismissRecovery={dismissNotice}
                onReset={resetTrip}
                onSubmit={(conditions) => void submitTrip(conditions)}
                primaryLabel={resumeEnabled ? "여행 조건 반영하고 프로필 보기" : JOURNEY_COPY.start.primaryLabel}
                busy={busy}
                requestError={requestError}
              />
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
