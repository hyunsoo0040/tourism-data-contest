import type { Ref } from "react";
import type { components } from "../../contracts/generated/api";

type QuestionnaireScenarioItem = components["schemas"]["QuestionnaireScenarioItem"];
type QuestionnaireChoiceOption = components["schemas"]["QuestionnaireChoiceOption"];

type QuestionCardProps = {
  question: QuestionnaireScenarioItem;
  answerOptions: QuestionnaireChoiceOption[];
  value: number | undefined;
  onChange: (value: number) => void;
  disabled?: boolean;
  invalid?: boolean;
  headingRef?: Ref<HTMLHeadingElement>;
  countLabel: string;
  onBack: () => void;
  onRestart: () => void;
};

export function QuestionCard({
  question,
  answerOptions,
  value,
  onChange,
  disabled = false,
  invalid = false,
  headingRef,
  countLabel,
  onBack,
  onRestart,
}: QuestionCardProps) {
  const hintId = `${question.question_id}-hint`;
  const errorId = `${question.question_id}-error`;

  return (
    <section
      className="panel question"
      aria-describedby={invalid ? `${hintId} ${errorId}` : hintId}
    >
      <div className="question-top">
        <div>
          <p className="eyebrow">Question</p>
          <h2 ref={headingRef} tabIndex={-1}>{question.title_ko}</h2>
          <p id={hintId}>{question.description_ko}</p>
        </div>
        <span className="count">{countLabel}</span>
      </div>
      <div className="options" role="radiogroup" aria-label={question.title_ko}>
        {answerOptions.map((option, index) => (
          <button
            aria-checked={value === option.value}
            className="option"
            disabled={disabled}
            key={option.value}
            onClick={() => onChange(option.value)}
            role="radio"
            type="button"
          >
            <b aria-hidden="true">{String.fromCharCode(65 + index)}</b>
            <span>{option.text_ko}</span>
          </button>
        ))}
      </div>
      {invalid ? (
        <p className="field-error" id={errorId} role="alert">
          이번 여행의 마음과 가까운 답변을 선택해 주세요.
        </p>
      ) : null}
      <div className="controls">
        <button className="control" disabled={disabled} onClick={onBack} type="button">이전</button>
        <button className="control" disabled={disabled} onClick={onRestart} type="button">처음부터</button>
      </div>
    </section>
  );
}
