"use client";

import { TripConditionForm } from "../../features/journey/TripConditionForm";
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
    void navigate("/quiz?q=1");
  };

  return (
    <div className="up-root">
      <div className="up-start" data-journey-surface="start">
        <header className="topbar">
          <a className="brand" href="/" aria-label="IT-DA 소개로 이동">
            <span className="brand-mark">잇</span>
            IT-DA
          </a>
          <a className="back-link" href="/">소개로 돌아가기</a>
        </header>

        <main>
          <section className="up-conditions" aria-label="여행 조건 입력">
            <div className="panel up-conditions-panel">
              <div className="up-conditions-head">
                <p className="eyebrow">Travel Conditions</p>
                <h1 id="start-heading">이번 경주, 어떤 시간을 보내고 싶나요?</h1>
                <p>
                  취향 테스트를 시작하기 전에 이번 여행의 조건을 고르면, 추천이 일정과 상황에 맞아집니다.
                </p>
              </div>
              <TripConditionForm
                defaultValues={formValues(draft?.trip_conditions)}
                recovered={recovered}
                onDismissRecovery={dismissNotice}
                onReset={resetDraft}
                onSubmit={beginQuiz}
                primaryLabel="취향 테스트 시작하기"
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

