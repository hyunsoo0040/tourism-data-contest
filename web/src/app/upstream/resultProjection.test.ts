import { describe, expect, it } from "vitest";

import questionnaire from "../../../../contracts/questionnaire-v2.json";
import golden from "../../../../fixtures/synthetic/preference-golden.json";
import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";
import { currentProfileReferenceRecordSchema, profileReferenceRecordSchema } from "../schemas";
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
      expect(result.match).toBe(winner.display_score);
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
    expect(pickResultForProfile(definition, profile)).toMatchObject({ name: "구성적 진정성", match: 36 });
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
