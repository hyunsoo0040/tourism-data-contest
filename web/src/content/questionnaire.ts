import scoringSnapshot from "../../../contracts/questionnaire-v2.json" with { type: "json" };
import type { components } from "../contracts/generated/api";
import copy from "./questionnaire.ko.json" with { type: "json" };

type QuestionnaireDefinition = components["schemas"]["QuestionnaireDefinitionV2"];

export type QuestionnaireCopy = {
  content_version: string;
  questionnaire_version: string;
  questions: Array<{
    question_id: string;
    title_ko: string;
    description_ko: string;
    options: Array<{ choice_id: string; text_ko: string }>;
  }>;
};

function assertCopy(text: string): void {
  if (typeof text !== "string" || !text.trim()) {
    throw new Error("Questionnaire copy must contain non-empty text.");
  }
}

/** Editable text is joined by stable IDs, never by its position in the copy file. */
export function withQuestionnaireCopy(
  definition: QuestionnaireDefinition,
  presentation: QuestionnaireCopy,
): QuestionnaireDefinition {
  assertCopy(presentation.content_version);
  if (presentation.questionnaire_version !== definition.questionnaire_version) {
    throw new Error("Questionnaire copy belongs to a different questionnaire version.");
  }
  const questions = new Map(presentation.questions.map((question) => [question.question_id, question]));
  if (questions.size !== presentation.questions.length || questions.size !== definition.questions.length) {
    throw new Error("Questionnaire copy must cover each question ID exactly once.");
  }
  return {
    ...definition,
    questions: definition.questions.map((question) => {
      const text = questions.get(question.question_id);
      if (!text) throw new Error(`Missing copy for ${question.question_id}.`);
      assertCopy(text.title_ko);
      assertCopy(text.description_ko);
      const options = new Map(text.options.map((option) => [option.choice_id, option.text_ko]));
      if (options.size !== text.options.length || options.size !== question.options.length) {
        throw new Error(`Copy must cover each choice ID exactly once for ${question.question_id}.`);
      }
      const presentOption = (option: (typeof question.options)[number]) => {
        const label = options.get(option.choice_id);
        if (label === undefined) throw new Error(`Missing copy for ${option.choice_id}.`);
        assertCopy(label);
        return { ...option, text_ko: label };
      };
      return {
        ...question,
        title_ko: text.title_ko,
        description_ko: text.description_ko,
        options: [presentOption(question.options[0]), presentOption(question.options[1]), presentOption(question.options[2])],
      };
    }),
  };
}

/** Backend snapshots retain scoring identity; the web content file owns visible questions. */
export const FRONTEND_QUESTIONNAIRE = withQuestionnaireCopy(
  scoringSnapshot as unknown as QuestionnaireDefinition,
  copy,
);

export const QUESTIONNAIRE_CONTENT_VERSION = copy.content_version;
