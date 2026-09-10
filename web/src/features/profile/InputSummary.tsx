import { FRONTEND_QUESTIONNAIRE } from "../../content/questionnaire";
import { TRIP_FIELD_LABELS, tripChoiceLabel } from "../../content/journey.ko";
import type { PreferenceProfile } from "../../api/api";
import { questionnaireAnswersSchema } from "../../app/schemas";

/** Legacy questionnaire-v1 Likert labels (values 1..5); replay display only. */
const LEGACY_ANSWER_LABELS: Record<number, string> = {
  1: "전혀 그렇지 않아요",
  2: "별로 그렇지 않아요",
  3: "보통이에요",
  4: "꽤 그래요",
  5: "매우 그래요",
};

const CURRENT_QUESTIONS = FRONTEND_QUESTIONNAIRE.questions;
type CurrentQuestion = (typeof CURRENT_QUESTIONS)[number];

export function InputSummary({
  profile,
  onEditTrip,
  onEditQuestion,
}: {
  profile: PreferenceProfile;
  onEditTrip: () => void;
  onEditQuestion: (ordinal: number) => void;
}) {
  const conditions = profile.trip_conditions;
  // Answer rendering is version-coupled: legacy v1 profiles show their nine
  // Likert answers, current v2 profiles show the twelve scenario choices.
  // Rendering v1 values through the current choice copy (or vice versa) would
  // silently distort what the user actually picked.
  const isCurrentAnswers = questionnaireAnswersSchema.safeParse(profile.answers).success;
  return (
    <details className="profile-details input-summary">
      <summary>입력한 내용</summary>
      <section aria-labelledby="trip-summary-title">
        <div className="summary-heading-row">
          <h3 id="trip-summary-title">여행 조건</h3>
          <button type="button" className="button button--secondary" onClick={onEditTrip}>여행 조건 수정하기</button>
        </div>
        <dl>
          <div><dt>방문 날짜</dt><dd>{conditions.visit_date ?? "아직 미정"}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.visit_time}</dt><dd>{tripChoiceLabel("visit_time", conditions.visit_time)}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.companion}</dt><dd>{tripChoiceLabel("companion", conditions.companion)}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.transport}</dt><dd>{tripChoiceLabel("transport", conditions.transport)}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.walking_tolerance}</dt><dd>{tripChoiceLabel("walking_tolerance", conditions.walking_tolerance)}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.indoor_outdoor_preference}</dt><dd>{tripChoiceLabel("indoor_outdoor_preference", conditions.indoor_outdoor_preference)}</dd></div>
          <div><dt>{TRIP_FIELD_LABELS.crowd_avoidance}</dt><dd>{tripChoiceLabel("crowd_avoidance", conditions.crowd_avoidance)}</dd></div>
        </dl>
      </section>
      {isCurrentAnswers ? (
        <CurrentAnswerSummary answers={profile.answers} onEditQuestion={onEditQuestion} />
      ) : (
        <LegacyAnswerSummary answers={profile.answers} onEditQuestion={onEditQuestion} />
      )}
    </details>
  );
}

function CurrentAnswerSummary({
  answers,
  onEditQuestion,
}: {
  answers: PreferenceProfile["answers"];
  onEditQuestion: (ordinal: number) => void;
}) {
  return (
    <section aria-labelledby="answer-summary-title">
      <h3 id="answer-summary-title">열두 가지 시나리오 답변</h3>
      <ol className="answer-summary-list">
        {CURRENT_QUESTIONS.map((question: CurrentQuestion) => {
          const ordinal = question.ordinal;
          const value = answers[`q${ordinal}` as keyof PreferenceProfile["answers"]];
          const selected = question.options.find((option) => option.value === value);
          return (
            <li key={ordinal}>
              <span>
                시나리오 {ordinal} · {selected?.text_ko ?? ""}
              </span>
              <button type="button" className="button button--secondary" onClick={() => onEditQuestion(ordinal)}>
                시나리오 {ordinal} 답변 수정
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function LegacyAnswerSummary({
  answers,
  onEditQuestion,
}: {
  answers: PreferenceProfile["answers"];
  onEditQuestion: (ordinal: number) => void;
}) {
  return (
    <section aria-labelledby="answer-summary-title">
      <h3 id="answer-summary-title">이전 여행 취향 검사 답변 (레거시)</h3>
      <ol className="answer-summary-list">
        {Array.from({ length: 9 }, (_, index) => index + 1).map((ordinal) => {
          const value = answers[`q${ordinal}` as keyof PreferenceProfile["answers"]];
          return (
            <li key={ordinal}>
              <span>질문 {ordinal} · {LEGACY_ANSWER_LABELS[value] ?? ""}</span>
              <button type="button" className="button button--secondary" onClick={() => onEditQuestion(ordinal)}>
                질문 {ordinal} 답변 수정
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
