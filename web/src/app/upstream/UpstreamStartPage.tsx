"use client";

import { JOURNEY_COPY } from "../../content/journey.ko";
import { useEffect, useRef, useState } from "react";
import { fetchPreferenceProfile } from "../../api/api";
import { createAndStorePreferenceProfile } from "../../features/profile/profileSubmission";
import { prepareProfileNavigation } from "../../features/profile/preparedProfile";
import { readProfileReference } from "../storage";

import { TripConditionForm } from "../../features/journey/TripConditionForm";
import { quizNavigationState } from "../../features/journey/quizNavigation";
import { useNavigate } from "../react-router-dom";
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
  const [resumeEnabled, setResumeEnabled] = useState(() => readProfileReference().profile !== null);
  const [busy, setBusy] = useState(false);
  const activeRequest = useRef<AbortController | null>(null);
  const { state, draft, updateDraft, resetDraft, dismissNotice, reportStorageUnavailable } =
    useJourneyDraft();
  const recovered = state === "recovered";

  useEffect(() => {
    return () => { activeRequest.current?.abort(); activeRequest.current = null; };
  }, []);

  const beginQuiz = (conditions: TripConditions, restartAnswers = false) => {
    updateDraft({
      trip_conditions: conditions,
      current_route: "/quiz",
      current_question: 1,
      ...(restartAnswers ? { answers: {} } : {}),
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
    try {
      // Use the completed server result, not a possibly incomplete local draft.
      const previous = await fetchPreferenceProfile(reference.profile_id, { signal: controller.signal });
      if (!current()) return;
      const answers = questionnaireAnswersSchema.safeParse(previous.answers);
      if (!answers.success) {
        setResumeEnabled(false);
        beginQuiz(conditions, true);
        return;
      }
      const result = await createAndStorePreferenceProfile(conditions, answers.data, controller.signal, current);
      if (!current()) return;
      updateDraft({ current_route: "/profile", trip_conditions: conditions, answers: answers.data });
      if (result.reference?.state === "memory-fallback") reportStorageUnavailable();
      void navigate("/profile", { state: {
        preparedProfileKey: prepareProfileNavigation(result.profile),
        announcement: "기존 취향 답변에 이번 여행 조건을 반영했어요.",
        focusProfile: true,
      } });
    } catch {
      if (!current()) return;
      setResumeEnabled(false);
      beginQuiz(conditions, true);
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
    }
    return succeeded;
  };

  return (
    <div className="up-root">
      <div className="up-start" data-journey-surface="start">
        <header className="topbar">
          <a className="brand main-page-logo" href="/" aria-label="IT-DA 소개로 이동">
            <img className="brand-mark-image" src="/itda-logo-icon.png" alt="" />
            <strong className="brand-wordmark">IT-DA</strong>
          </a>
          <a className="back-link" href="/">메인으로</a>
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
                allowRestart={resumeEnabled}
                onSubmit={(conditions) => void submitTrip(conditions)}
                primaryLabel={resumeEnabled ? "여행 조건 그대로 유지" : JOURNEY_COPY.start.primaryLabel}
                busy={busy}
              />
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
