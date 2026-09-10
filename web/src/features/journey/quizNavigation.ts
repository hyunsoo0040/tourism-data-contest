export type QuizNavigationState = {
  questionOrdinal: number;
  editingProfile?: true;
};

export function quizOrdinal(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 12
    ? value
    : null;
}

export function legacyQuizOrdinal(search: string): number | null {
  const values = new URLSearchParams(search).getAll("q");
  if (values.length !== 1 || !/^\d+$/.test(values[0]!)) return null;
  return quizOrdinal(Number(values[0]));
}

export function readQuizNavigationState(state: unknown) {
  const record = typeof state === "object" && state !== null && !Array.isArray(state)
    ? state as Record<string, unknown>
    : null;
  return {
    questionOrdinal: quizOrdinal(record?.questionOrdinal),
    editingProfile: record?.editingProfile === true,
  };
}

export function quizNavigationState(ordinal: number, editingProfile = false): QuizNavigationState {
  if (quizOrdinal(ordinal) === null) throw new RangeError("질문 번호는 1부터 12까지의 정수여야 합니다.");
  return editingProfile ? { questionOrdinal: ordinal, editingProfile: true } : { questionOrdinal: ordinal };
}
