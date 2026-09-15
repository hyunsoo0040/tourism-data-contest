import { describe, expect, it } from "vitest";

import questionnaire from "../../../../contracts/questionnaire-v2.json";
import golden from "../../../../fixtures/synthetic/preference-golden.json";
import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";
import { currentProfileReferenceRecordSchema, profileReferenceRecordSchema } from "../schemas";
import { projectDisplayScores } from "../../features/profile/displayScores";
import { pickResultForProfile } from "./resultProjection";

const definition = questionnaire as unknown as QuestionnaireDefinition;

describe("server-scored quiz result", () => {
  for (const example of golden.cases) {
    it(`uses the same winning axis as the server for ${example.id}`, () => {
      const scores = definition.axis_tie_break.map((axis, index) => ({
        axis, basis_points: example.basis_points[index]!, display_score: example.display_scores[index]!,
      }));
      const profile = {
        answers: Object.fromEntries(example.answers.map((value, index) => [`q${index + 1}`, value])),
        scores,
      } as PreferenceProfile;
      const winner = [...scores].sort((a, b) => b.basis_points - a.basis_points)[0]!;
      const result = pickResultForProfile(definition, profile);
      expect(result.name).toBe(definition.result_types.find((type) => type.axis === winner.axis)!.name_ko);
      expect(result.match).toBe(projectDisplayScores(scores, definition.axis_tie_break)![winner.axis]);
      expect(result.keywords.length).toBeLessThanOrEqual(6);
    });
  }

  it("uses unrounded server scores rather than answer frequency or rounded-score ties", () => {
    const profile = {
      answers: Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`q${i + 1}`, 1])),
      scores: [
        { axis: "HISTORY_TRADITION", basis_points: 3600, display_score: 36 },
        { axis: "EMOTION_IMAGE", basis_points: 3636, display_score: 36 },
        { axis: "REST_IMMERSION", basis_points: 1800, display_score: 18 },
      ],
    } as PreferenceProfile;
    expect(pickResultForProfile(definition, profile)).toMatchObject({ name: "구성적 진정성", match: 41 });
  });

  it.each([
    ["HISTORY_TRADITION", "관광 대상 자체가 지닌 고유한 가치와 원래의 모습을 중요하게 보는 여행자입니다.", ["원형", "역사", "전통", "고유성", "문화", "가치"], "역사와 전통이 담긴 공간부터 장소 고유의 모습과 가치를 직접 경험할 수 있는 여행지가 잘 맞습니다."],
    ["EMOTION_IMAGE", "장소에 대한 이미지와 기대, 그 안에 담긴 의미를 중요하게 보는 여행자입니다.", ["이미지", "기대", "인식", "이야기", "의미", "상징"], "미디어와 사람들의 이야기 속에서 형성된 장소의 이미지와 기대를 직접 경험할 수 있는 여행지가 잘 맞습니다."],
    ["REST_IMMERSION", "일상에서 벗어나 자신의 감정과 생각에 집중하는 경험을 중요하게 보는 여행자입니다.", ["자유", "감정", "몰입", "여유", "자기표현", "해방"], "평소의 역할과 틀에서 벗어나 자유롭게 자신을 표현하고, 자신의 감정과 생각에 집중할 수 있는 여행지가 잘 맞습니다."],
  ] as const)("uses the reviewed %s authenticity copy", (axis, description, keywords, recommend) => {
    const profile = {
      answers: Object.fromEntries(Array.from({ length: 12 }, (_, index) => [`q${index + 1}`, 1])),
      scores: [
        { axis: "HISTORY_TRADITION", basis_points: axis === "HISTORY_TRADITION" ? 3600 : 1800, display_score: 36 },
        { axis: "EMOTION_IMAGE", basis_points: axis === "EMOTION_IMAGE" ? 3600 : 1800, display_score: 36 },
        { axis: "REST_IMMERSION", basis_points: axis === "REST_IMMERSION" ? 3600 : 1800, display_score: 36 },
      ],
    } as PreferenceProfile;

    expect(pickResultForProfile(definition, profile)).toMatchObject({ description, keywords, recommend });
  });

  it("retains old choice-scoring references without treating them as new results", () => {
    const reference = {
      schema_version: "phase1-profile-reference-v1", profile_schema_version: "preference-profile-v2",
      questionnaire_version: "questionnaire-v2", scoring_version: "choice-bp-v2",
      description_template_version: "current-trip-expectation-v1", profile_id: "profile:old",
      updated_at: "2026-09-08T12:00:00Z",
    };
    expect(profileReferenceRecordSchema.safeParse(reference).success).toBe(true);
    expect(currentProfileReferenceRecordSchema.safeParse(reference).success).toBe(false);
  });
});
