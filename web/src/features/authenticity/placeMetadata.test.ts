import { describe, expect, it } from "vitest";
import type { Detail } from "./api";
import { placeIntroduction, placeMapUrl } from "./placeMetadata";

describe("verified place information", () => {
  it("uses the official overview instead of short fee facts or photo analysis", () => {
    const overview = "관광지의 역사와 주변 볼거리를 설명하는 공식 자료입니다. ".repeat(4);
    const detail = { evidence: [
      { role: "OFFICIAL_DESCRIPTION", excerpt: "무료", retrieved_at: "2026-09-10" },
      { role: "OFFICIAL_DESCRIPTION", excerpt: overview, retrieved_at: "2026-09-11T00:00:00Z" },
      { role: "PLACE_PHOTO", excerpt: "사진에서 추정한 장소 설명".repeat(50) },
    ] } as Detail;
    expect(placeIntroduction(detail)).toEqual({ text: overview.trim(), retrievedAt: "2026-09-11T00:00:00Z" });
    expect(placeIntroduction({ evidence: [] } as unknown as Detail)).toBeNull();
  });
  it("encodes the actual place name and address into a map search", () => {
    expect(decodeURIComponent(placeMapUrl("영랑호", "강원특별자치도 속초시"))).toBe("https://map.naver.com/p/search/영랑호 강원특별자치도 속초시");
  });
});
