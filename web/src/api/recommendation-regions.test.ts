import { describe, expect, it } from "vitest";
import { parseRecommendationRegions, travelRegionName } from "./recommendation-regions";

describe("published recommendation regions", () => {
  it("uses the current catalogue's codes, names and counts, including new provider regions", () => {
    const regions = parseRecommendationRegions({ candidate_sha256: "a".repeat(64), regions: [
      { region_code: "12", region_name: "전남광주통합특별시", place_count: 67 },
      { region_code: "36", region_name: "세종특별자치시", place_count: 11 },
    ] });
    expect(regions).toHaveLength(2);
    expect(travelRegionName("12", regions)).toBe("전남광주통합특별시");
    expect(travelRegionName(null, regions)).toBe("전국");
    expect(travelRegionName("51", regions)).toBe("선택한 지역");
    expect(parseRecommendationRegions({ candidate_sha256: null, regions: [] })).toEqual([]);
  });

  it.each([
    { region_code: "36110", region_name: "세종특별자치시", place_count: 11 },
    { region_code: "36", region_name: "", place_count: 11 },
    { region_code: "36", region_name: "세종특별자치시", place_count: -1 },
  ])("rejects malformed province options", (region) => {
    expect(() => parseRecommendationRegions({ candidate_sha256: "a".repeat(64), regions: [region] })).toThrow();
  });

  it("rejects conflicting duplicate region identities", () => {
    expect(() => parseRecommendationRegions({ candidate_sha256: "a".repeat(64), regions: [
      { region_code: "12", region_name: "전남광주통합특별시", place_count: 67 },
      { region_code: "12", region_name: "중복", place_count: 1 },
    ] })).toThrow();
  });
});
