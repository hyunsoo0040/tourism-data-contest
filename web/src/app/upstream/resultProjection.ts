"use client";

import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";

/**
 * Shared upstream-style result projection over a persisted profile: maps the
 * stored canonical v2 answers onto the served contract's result_types copy.
 * Presentation only — scoring stays server-owned.
 */
export function pickResultForProfile(
  questionnaire: QuestionnaireDefinition,
  profile: PreferenceProfile,
) {
  const counts: Record<string, number> = {};
  const keywords: string[] = [];
  const answers: Record<string, number> = profile.answers as unknown as Record<string, number>;
  for (const ordinal of questionnaire.question_order) {
    const item = questionnaire.questions.find((q) => q.ordinal === ordinal);
    if (item === undefined) continue;
    const value = answers[item.question_id];
    if (value === undefined) continue;
    const option = item.options.find((candidate) => candidate.value === value);
    if (option === undefined) continue;
    counts[option.axis] = (counts[option.axis] ?? 0) + 1;
    keywords.push(...option.keywords_ko);
  }
  const tieBreak = questionnaire.axis_tie_break;
  const topAxis = [...tieBreak].sort((left, right) => (counts[right] ?? 0) - (counts[left] ?? 0))[0] ?? tieBreak[0]!;
  const info = questionnaire.result_types.find((type) => type.axis === topAxis) ?? questionnaire.result_types[0]!;
  const totalAnswers = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const match = totalAnswers === 0 ? 0 : Math.round(((counts[topAxis] ?? 0) / totalAnswers) * 100);
  const keywordCounts = new Map<string, number>();
  for (const keyword of keywords) {
    keywordCounts.set(keyword, (keywordCounts.get(keyword) ?? 0) + 1);
  }
  const frequent = [...keywordCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([keyword]) => keyword);
  const assetName = info.character_image.split("/").pop() ?? "original-seeker.jpg";
  return {
    name: info.name_ko,
    description: info.description_ko,
    character: info.character_ko,
    role: info.role_ko,
    lens: info.lens_ko,
    recommend: info.recommend_ko,
    image: `/upstream-assets/characters/${assetName}`,
    badgeClass:
      info.axis === "HISTORY_TRADITION" ? "history" : info.axis === "EMOTION_IMAGE" ? "image" : "rest",
    match,
    keywords: frequent,
  };
}
