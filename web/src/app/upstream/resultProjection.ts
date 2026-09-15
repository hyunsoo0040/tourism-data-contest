"use client";

import type { PreferenceProfile, QuestionnaireDefinition } from "../../api/api";
import { projectDisplayScores } from "../../features/profile/displayScores";

const AUTHENTICITY_RESULT_COPY = {
  HISTORY_TRADITION: {
    description: "관광 대상 자체가 지닌 고유한 가치와 원래의 모습을 중요하게 보는 여행자입니다.",
    keywords: ["원형", "역사", "전통", "고유성", "문화", "가치"],
    recommend: "역사와 전통이 담긴 공간부터 장소 고유의 모습과 가치를 직접 경험할 수 있는 여행지가 잘 맞습니다.",
  },
  EMOTION_IMAGE: {
    description: "장소에 대한 이미지와 기대, 그 안에 담긴 의미를 중요하게 보는 여행자입니다.",
    keywords: ["이미지", "기대", "인식", "이야기", "의미", "상징"],
    recommend: "미디어와 사람들의 이야기 속에서 형성된 장소의 이미지와 기대를 직접 경험할 수 있는 여행지가 잘 맞습니다.",
  },
  REST_IMMERSION: {
    description: "일상에서 벗어나 자신의 감정과 생각에 집중하는 경험을 중요하게 보는 여행자입니다.",
    keywords: ["자유", "감정", "몰입", "여유", "자기표현", "해방"],
    recommend: "평소의 역할과 틀에서 벗어나 자유롭게 자신을 표현하고, 자신의 감정과 생각에 집중할 수 있는 여행지가 잘 맞습니다.",
  },
} as const;

/**
 * Shared upstream-style result projection over a persisted profile: maps the
 * server-owned scores onto the served contract's result_types copy.
 * The result wording is presentation-only; scoring stays server-owned.
 */
export function pickResultForProfile(
  questionnaire: QuestionnaireDefinition,
  profile: PreferenceProfile,
) {
  const tieBreak = questionnaire.axis_tie_break;
  const byAxis = new Map(profile.scores.map((score) => [score.axis, score]));
  const topAxis = [...tieBreak].sort((left, right) =>
    (byAxis.get(right)?.basis_points ?? 0) - (byAxis.get(left)?.basis_points ?? 0)
  )[0] ?? tieBreak[0]!;
  const info = questionnaire.result_types.find((type) => type.axis === topAxis) ?? questionnaire.result_types[0]!;
  const copy = AUTHENTICITY_RESULT_COPY[topAxis];
  const match = projectDisplayScores(profile.scores, tieBreak)?.[topAxis] ?? 0;
  const sourceAssetName = info.character_image.split("/").pop() ?? "original-seeker.jpg";
  const assetName = {
    "original-seeker.jpg": "original-seeker-card.jpg",
    "mood-weaver.jpg": "mood-weaver-card.jpg",
    "flow-walker.jpg": "flow-walker-card.jpg",
  }[sourceAssetName] ?? sourceAssetName;
  return {
    name: info.name_ko,
    description: copy.description,
    character: info.character_ko,
    role: info.role_ko,
    axisLabel: {
      HISTORY_TRADITION: "대상•원형형",
      EMOTION_IMAGE: "의미•이미지형",
      REST_IMMERSION: "자기•몰입형",
    }[topAxis],
    lens: info.lens_ko,
    recommend: copy.recommend,
    image: `/upstream-assets/characters/${assetName}`,
    badgeClass:
      info.axis === "HISTORY_TRADITION" ? "history" : info.axis === "EMOTION_IMAGE" ? "image" : "rest",
    match,
    keywords: [...copy.keywords],
  };
}
