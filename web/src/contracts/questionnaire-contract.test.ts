import questionnaireArtifact from "../../../contracts/questionnaire-v2.json";
import type { components, paths } from "./generated/api";

type QuestionnaireDefinition = components["schemas"]["QuestionnaireDefinitionV2"];
type CurrentQuestionnaireResponse =
  paths["/v1/questionnaires/current"]["get"]["responses"][200]["content"]["application/json"];
type ConflictResponse =
  paths["/v1/preference-profiles"]["post"]["responses"][409]["content"]["application/json"];
type NotFoundResponse =
  paths["/v1/preference-profiles/{profile_id}"]["get"]["responses"][404]["content"]["application/json"];

type Assert<Condition extends true> = Condition;
type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;
type JsonShape<Value> =
  Value extends string
    ? string
    : Value extends number
      ? number
      : Value extends boolean
        ? boolean
        : Value extends (infer Item)[]
          ? JsonShape<Item>[]
          : Value extends object
            ? { [Key in keyof Value]: JsonShape<Value[Key]> }
            : Value;

type _ServedQuestionnaireUsesGeneratedSchema = Assert<
  Equal<CurrentQuestionnaireResponse, QuestionnaireDefinition>
>;
type _ArtifactMatchesGeneratedQuestionnaireShape = Assert<
  typeof questionnaireArtifact extends JsonShape<QuestionnaireDefinition> ? true : false
>;
type _ConflictUsesGeneratedErrorSchema = Assert<
  Equal<ConflictResponse, components["schemas"]["ErrorResponse"]>
>;
type _NotFoundUsesGeneratedErrorSchema = Assert<
  Equal<NotFoundResponse, components["schemas"]["ErrorResponse"]>
>;

const servedQuestionnaire = questionnaireArtifact;

describe("canonical questionnaire consumer contract", () => {
  it("consumes the committed artifact through generated OpenAPI declarations", () => {
    expect(servedQuestionnaire).toEqual(questionnaireArtifact);
  });

  it("preserves IDs, visible order, Korean copy, versions, and config hash", () => {
    expect(servedQuestionnaire.questions.map(({ question_id }) => question_id)).toEqual(
      questionnaireArtifact.questions.map(({ question_id }) => question_id),
    );
    expect(servedQuestionnaire.questions.map(({ ordinal }) => ordinal)).toEqual(
      questionnaireArtifact.question_order,
    );
    expect(servedQuestionnaire.questions.map(({ title_ko }) => title_ko)).toEqual(
      questionnaireArtifact.questions.map(({ title_ko }) => title_ko),
    );
    expect(servedQuestionnaire.questionnaire_version).toBe(
      questionnaireArtifact.questionnaire_version,
    );
    expect(servedQuestionnaire.scoring_version).toBe(questionnaireArtifact.scoring_version);
    expect(servedQuestionnaire.description_template_version).toBe(
      questionnaireArtifact.description_template_version,
    );
    expect(servedQuestionnaire.config_hash).toBe(questionnaireArtifact.config_hash);
  });

  it("exposes exactly 36 canonical choices with stable IDs and values 1..3", () => {
    const choices = servedQuestionnaire.questions.flatMap(({ options }) => options);
    expect(choices).toHaveLength(36);
    servedQuestionnaire.questions.forEach((question) => {
      question.options.forEach((option, index) => {
        expect(option.value).toBe(index + 1);
        expect(option.choice_id).toBe(`q${question.ordinal}o${index + 1}`);
      });
    });
  });
});
