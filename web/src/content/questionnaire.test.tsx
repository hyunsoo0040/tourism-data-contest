import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QuestionCard } from "../features/journey/QuestionCard";
import { FRONTEND_QUESTIONNAIRE, withQuestionnaireCopy } from "./questionnaire";
import copy from "./questionnaire.ko.json";

describe("editable questionnaire copy", () => {
  it("changes visible text without changing choice values, scoring identity, or order", () => {
    const edited = structuredClone(copy);
    const first = edited.questions[0]!;
    first.title_ko = "여행이 시작되기 전, 무엇을 하고 싶나요?";
    first.description_ko = "지금의 마음과 가까운 행동을 골라 주세요.";
    first.options[0]!.text_ko = "새로 다듬은 선택지 문구";
    // Editing tools may reorder entries: identities, not array positions, bind copy.
    first.options.reverse();
    edited.questions.reverse();
    const presented = withQuestionnaireCopy(FRONTEND_QUESTIONNAIRE, edited);
    expect(presented.config_hash).toBe(FRONTEND_QUESTIONNAIRE.config_hash);
    expect(presented.scoring_matrix).toEqual(FRONTEND_QUESTIONNAIRE.scoring_matrix);
    expect(presented.question_order).toEqual(FRONTEND_QUESTIONNAIRE.question_order);
    const question = presented.questions[0]!;
    expect(question.question_id).toBe("q1");
    const select = vi.fn();
    render(<QuestionCard question={question} answerOptions={question.options}
      value={undefined} onChange={select} countLabel="1 / 12"
      onBack={vi.fn()} onRestart={vi.fn()} />);
    expect(screen.getByRole("heading", { name: first.title_ko })).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: "새로 다듬은 선택지 문구" }));
    expect(select).toHaveBeenCalledWith(1);
    expect(FRONTEND_QUESTIONNAIRE.questions[0]!.title_ko).not.toBe(first.title_ko);
  });

  it.each([
    ["version", (edited: typeof copy) => { edited.questionnaire_version = "wrong"; }],
    ["missing question", (edited: typeof copy) => { edited.questions.pop(); }],
    ["duplicate question", (edited: typeof copy) => { edited.questions[1]!.question_id = "q1"; }],
    ["unknown question", (edited: typeof copy) => { edited.questions[0]!.question_id = "q99"; }],
    ["missing choice", (edited: typeof copy) => { edited.questions[0]!.options.pop(); }],
    ["duplicate choice", (edited: typeof copy) => { edited.questions[0]!.options[1]!.choice_id = "q1o1"; }],
    ["unknown choice", (edited: typeof copy) => { edited.questions[0]!.options[0]!.choice_id = "q2o1"; }],
    ["empty title", (edited: typeof copy) => { edited.questions[0]!.title_ko = "  "; }],
    ["empty choice", (edited: typeof copy) => { edited.questions[0]!.options[0]!.text_ko = ""; }],
  ])("fails visibly for %s rather than rendering an ambiguous answer mapping", (_name, mutate) => {
    const edited = structuredClone(copy);
    mutate(edited);
    expect(() => withQuestionnaireCopy(FRONTEND_QUESTIONNAIRE, edited)).toThrow();
  });
});
