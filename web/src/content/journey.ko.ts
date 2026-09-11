import type { TripConditionFormValues, TripConditions } from "../app/schemas";

// Edit labels freely; the enum values are part of the backend request contract.
export type TripChoiceField = Exclude<keyof TripConditionFormValues, "visit_date">;

type TripChoiceOptions = {
  [Field in TripChoiceField]: Array<{ value: TripConditions[Field]; label: string }>;
};

export const TRIP_FIELD_LABELS: Record<TripChoiceField, string> = {
  visit_time: "방문 시간",
  companion: "동행",
  transport: "이동수단",
  walking_tolerance: "도보 허용",
  indoor_outdoor_preference: "실내외 선호",
  crowd_avoidance: "혼잡 회피",
};

export const TRIP_CHOICES: TripChoiceOptions = {
  visit_time: [
    { value: "MORNING", label: "오전" },
    { value: "DAYTIME", label: "낮" },
    { value: "SUNSET", label: "해질녘" },
    { value: "EVENING", label: "저녁" },
    { value: "UNDECIDED", label: "아직 미정" },
  ],
  companion: [
    { value: "SOLO", label: "혼자" },
    { value: "FRIEND_OR_PARTNER", label: "친구" },
    { value: "FAMILY_WITH_CHILDREN", label: "아이 동반" },
    { value: "WITH_SENIORS", label: "어르신 동반" },
    
  ],
  transport: [
    { value: "WALK_OR_TRANSIT", label: "도보·대중교통" },
    { value: "CAR_OR_TAXI", label: "자가용·택시" },
    { value: "MIXED", label: "둘 다" },
  ],
  walking_tolerance: [
    { value: "WITHIN_30_MINUTES", label: "30분 이내로 가볍게" },
    { value: "ABOUT_1_HOUR", label: "1시간 안팎" },
    { value: "EXTENDED_WALKING_OK", label: "충분히 걸어도 괜찮아요" },
  ],
  indoor_outdoor_preference: [
    { value: "INDOOR", label: "실내 위주" },
    { value: "NO_PREFERENCE", label: "상관없어요" },
    { value: "OUTDOOR", label: "야외 위주" },
  ],
  crowd_avoidance: [
    { value: "LOW", label: "괜찮아요" },
    { value: "MEDIUM", label: "조금 피하고 싶어요" },
    { value: "HIGH", label: "많이 피하고 싶어요" },
  ],
};

export const JOURNEY_COPY = {
  start: {
    title: "이번 여행, 어떤 시간을 보내고 싶나요?",
    description: "취향 테스트를 시작하기 전에 이번 여행의 조건을 고르면, 추천이 일정과 상황에 맞아집니다.",
    legacyDescription: "여행 조건과 열두 가지 장면을 고르면, 지금 이 여행에서 기대하는 세 가지 경험을 보여드려요. 약 1분 걸려요.",
    primaryLabel: "취향 테스트 시작하기",
  },
  quiz: {
    titleLines: ["12개의 장면으로", "여행의 의미를 찾아요"],
    descriptionLines: [
      "정답은 없습니다. 하루 여행처럼 이어지는 상황 속에서 더 자연스러운 선택을 골라보세요.",
      "마음에 드는 선택지가 여러 개라면, 그중 가장 끌리는 방향을 선택해 주세요.",
    ],
  },
  region: {
    legend: "여행 지역",
    label: "어디로 떠날까요?",
    all: "전국에서 찾아보기",
    previous: "이전에 선택한 지역",
    help: "지역을 고르면 그 안에서 추천해요. 아직 정하지 않았다면 전국의 여행지를 살펴보세요.",
  },
  visit: {
    legend: "방문 시점",
    dateLabel: "방문 날짜 (선택)",
    timeLabel: "정확한 방문 시간 (선택)",
  },
  facilities: {
    legend: "필요한 편의시설 (선택)",
    help: "이번 방문에 필요한 항목을 직접 선택해 주세요.",
  },
} as const;

export function tripChoiceLabel(field: TripChoiceField, value: string): string {
  return TRIP_CHOICES[field].find((choice) => choice.value === value)?.label ?? "확인 필요";
}
