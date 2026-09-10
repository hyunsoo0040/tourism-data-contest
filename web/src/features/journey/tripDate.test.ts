import { describe, expect, it, vi } from "vitest";

import { localDate } from "./tripDate";

describe("현지 여행 날짜", () => {
  it.each([
    [new Date(2026, 0, 2), "2026-01-02"],
    [new Date(2028, 1, 29), "2028-02-29"],
    [new Date(2026, 11, 31, 23, 59), "2026-12-31"],
  ])("현지 달력 날짜를 두 자리 월·일로 표시한다", (date, expected) => {
    expect(localDate(date)).toBe(expected);
  });

  it("UTC 문자열이 아니라 현지 날짜 필드를 사용한다", () => {
    const date = new Date("2026-09-08T15:30:00Z");
    vi.spyOn(date, "getFullYear").mockReturnValue(2026);
    vi.spyOn(date, "getMonth").mockReturnValue(8);
    vi.spyOn(date, "getDate").mockReturnValue(9);
    expect(localDate(date)).toBe("2026-09-09");
    expect(date.toISOString().slice(0, 10)).toBe("2026-09-08");
  });
});
