"use client";

import { JOURNEY_COPY } from "../../content/journey.ko";

import { TripConditionForm } from "../../features/journey/TripConditionForm";
import { quizNavigationState } from "../../features/journey/quizNavigation";
import { useNavigate } from "../react-router-dom";
import { useJourneyDraft } from "../AppShell";
import {
  type TripConditionFormValues,
  type TripConditions,
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
  const { state, draft, updateDraft, resetDraft, dismissNotice, reportStorageUnavailable } =
    useJourneyDraft();
  const recovered = state === "recovered";

  const beginQuiz = (conditions: TripConditions) => {
    updateDraft({
      trip_conditions: conditions,
      current_route: "/quiz",
      current_question: 1,
    });
    void navigate("/quiz", { state: quizNavigationState(1) });
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
                  <br />{JOURNEY_COPY.start.description}
                </p>
              </div>
              <TripConditionForm
                defaultValues={formValues(draft?.trip_conditions)}
                recovered={recovered}
                onDismissRecovery={dismissNotice}
                onReset={resetDraft}
                onSubmit={beginQuiz}
                primaryLabel={JOURNEY_COPY.start.primaryLabel}
                busy={false}
                requestError={null}
              />
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
