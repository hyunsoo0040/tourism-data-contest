import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { useJourneyDraft } from "../app/AppShell";
import {
  questionnaireAnswersSchema,
  type TripConditionFormValues,
  type TripConditions,
} from "../app/schemas";
import { TripConditionForm } from "../features/journey/TripConditionForm";
import { createAndStorePreferenceProfile } from "../features/profile/profileSubmission";

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

export function StartPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { state, draft, updateDraft, resetDraft, dismissNotice, reportStorageUnavailable } = useJourneyDraft();
  const [busy, setBusy] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const editMode = searchParams.get("mode") === "edit";

  const beginQuiz = (conditions: TripConditions) => {
    updateDraft({
      trip_conditions: conditions,
      current_route: "/quiz",
      current_question: 1,
    });
    void navigate("/quiz?q=1");
  };

  const applyEdit = async (conditions: TripConditions) => {
    const parsedAnswers = questionnaireAnswersSchema.safeParse(draft?.answers);
    if (!parsedAnswers.success || busy) {
      setRequestError("답변을 다시 확인한 뒤 수정 내용을 반영해 주세요.");
      return;
    }
    setBusy(true);
    setRequestError(null);
    try {
      const result = await createAndStorePreferenceProfile(conditions, parsedAnswers.data);
      updateDraft({ current_route: "/profile", trip_conditions: conditions, answers: parsedAnswers.data });
      if (result.reference?.state === "memory-fallback") reportStorageUnavailable();
      void navigate("/profile", {
        state: {
          announcement: "수정한 답변으로 기대 프로필을 다시 만들었어요.",
          focusProfile: true,
        },
      });
    } catch {
      setRequestError("프로필을 만들지 못했어요. 입력한 답변은 이 브라우저에 보관되어 있어요.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="start-page">
      <header className="page-intro">
        <p className="eyebrow">경주 여행 기대 프로필</p>
        <h1 id="start-heading" tabIndex={-1}>
          이번 경주, 어떤 시간을 보내고 싶나요?
        </h1>
        <p>
          여행 조건과 아홉 가지 장면을 고르면, 지금 이 여행에서 기대하는 세 가지 경험을 보여드려요.
          약 1분 걸려요.
        </p>
        <p className="privacy-note">계정 없이 진행하며, 답변은 이 브라우저에만 임시 저장돼요.</p>
      </header>
      <TripConditionForm
        defaultValues={formValues(draft?.trip_conditions)}
        recovered={!editMode && state === "recovered"}
        onDismissRecovery={dismissNotice}
        onReset={resetDraft}
        onSubmit={editMode ? (conditions) => void applyEdit(conditions) : beginQuiz}
        primaryLabel={editMode ? "수정 내용 반영하기" : "취향 테스트 시작하기"}
        secondaryLabel={editMode ? "변경하지 않고 프로필로 돌아가기" : undefined}
        onSecondary={editMode ? () => void navigate("/profile") : undefined}
        busy={busy}
        requestError={requestError}
      />
    </article>
  );
}
