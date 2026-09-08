import questionnaireV2Artifact from "../../../../contracts/questionnaire-v2.json";
import type { PreferenceProfile } from "../../api/api";
import { questionnaireAnswersSchema } from "../../app/schemas";

const CONDITION_LABELS = {
  visit_time: { MORNING: "오전", DAYTIME: "낮", SUNSET: "해질녘", EVENING: "저녁", UNDECIDED: "아직 미정" },
  companion: { SOLO: "혼자", FRIEND_OR_PARTNER: "친구·연인", FAMILY_WITH_CHILDREN: "가족·아이", WITH_SENIORS: "어르신 동반", GROUP: "여럿이" },
  transport: { WALK_OR_TRANSIT: "도보·대중교통", CAR_OR_TAXI: "자가용·택시", MIXED: "둘 다" },
  walking_tolerance: { WITHIN_30_MINUTES: "30분 이내로 가볍게", ABOUT_1_HOUR: "1시간 안팎", EXTENDED_WALKING_OK: "충분히 걸어도 괜찮아요" },
  indoor_outdoor_preference: { INDOOR: "실내 위주", NO_PREFERENCE: "상관없어요", OUTDOOR: "야외 위주" },
  crowd_avoidance: { LOW: "괜찮아요", MEDIUM: "조금 피하고 싶어요", HIGH: "많이 피하고 싶어요" },
} as const;

/** Legacy questionnaire-v1 Likert labels (values 1..5); replay display only. */
const LEGACY_ANSWER_LABELS: Record<number, string> = {
  1: "전혀 그렇지 않아요",
  2: "별로 그렇지 않아요",
  3: "보통이에요",
  4: "꽤 그래요",
  5: "매우 그래요",
};

const CURRENT_QUESTIONS = questionnaireV2Artifact.questions;
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
          <div><dt>방문 시간</dt><dd>{CONDITION_LABELS.visit_time[conditions.visit_time]}</dd></div>
          <div><dt>동행</dt><dd>{CONDITION_LABELS.companion[conditions.companion]}</dd></div>
          <div><dt>이동수단</dt><dd>{CONDITION_LABELS.transport[conditions.transport]}</dd></div>
          <div><dt>도보 허용</dt><dd>{CONDITION_LABELS.walking_tolerance[conditions.walking_tolerance]}</dd></div>
          <div><dt>실내외 선호</dt><dd>{CONDITION_LABELS.indoor_outdoor_preference[conditions.indoor_outdoor_preference]}</dd></div>
          <div><dt>혼잡 회피</dt><dd>{CONDITION_LABELS.crowd_avoidance[conditions.crowd_avoidance]}</dd></div>
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
