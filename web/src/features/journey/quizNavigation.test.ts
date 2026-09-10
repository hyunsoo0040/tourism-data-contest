import { describe, expect, it } from "vitest";
import { legacyQuizOrdinal, quizNavigationState, quizOrdinal, readQuizNavigationState } from "./quizNavigation";

describe("퀴즈 navigation state", () => {
  it.each([1, 7, 12])("정수 %s를 보존한다", (ordinal) => {
    expect(quizOrdinal(ordinal)).toBe(ordinal);
    expect(readQuizNavigationState(quizNavigationState(ordinal))).toEqual({ questionOrdinal: ordinal, editingProfile: false });
  });
  it.each([null, undefined, "2", 0, 13, 1.5, NaN, Infinity, [], {}])("잘못된 번호 %j를 거부한다", (value) => {
    expect(quizOrdinal(value)).toBeNull();
  });
  it.each([null, undefined, "2", 2, [], [{ questionOrdinal: 2 }]])("잘못된 state %j를 무시한다", (state) => {
    expect(readQuizNavigationState(state)).toEqual({ questionOrdinal: null, editingProfile: false });
  });
  it.each(["", "?q=", "?q=x", "?q=1.5", "?q=0", "?q=13", "?q=-1", "?q=1&q=2", "?q=1&q=1", "?q=1e1", "?q=%202"]) ("이전 링크 %s의 잘못된 번호를 무시한다", (search) => {
    expect(legacyQuizOrdinal(search)).toBeNull();
  });
  it("이전 링크를 읽고 편집 플래그와 번호만 생성한다", () => {
    expect(legacyQuizOrdinal("?q=7&other=value")).toBe(7);
    expect(quizNavigationState(7, true)).toEqual({ questionOrdinal: 7, editingProfile: true });
    expect(readQuizNavigationState({ questionOrdinal: 7, editingProfile: "true" }).editingProfile).toBe(false);
    expect(() => quizNavigationState(13)).toThrow(RangeError);
  });
});
