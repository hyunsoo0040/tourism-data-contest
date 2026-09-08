import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { PlaceOperatingInformation } from "../../api/api";
import { OperatingInformation } from "./OperatingInformation";

const AVAILABLE: PlaceOperatingInformation = {
  place_id: "place:test",
  state: "AVAILABLE",
  snapshot: {
    provider: "TOUR_API",
    operation: "detailIntro2",
    content_type_id: "39",
    entries: [
      {
        kind: "OPENING_HOURS",
        label_ko: "영업시간",
        value_ko: "11:00~20:00",
        provider_field: "opentimefood",
      },
      {
        kind: "REST_DATES",
        label_ko: "휴무일",
        value_ko: "매주 월요일",
        provider_field: "restdatefood",
      },
    ],
    retrieved_at: "2026-09-05T04:30:00Z",
    provider_modifiedtime: "20260905043000",
    source_label_ko: "한국관광공사 TourAPI(KorService2 detailIntro2)",
    cached: false,
  },
  unavailable_reason: null,
};

describe("OperatingInformation", () => {
  it("renders official fields, source, and absolute retrieval time without live inference", () => {
    const { container } = render(
      <OperatingInformation information={AVAILABLE} loading={false} />,
    );

    const available = container.querySelector(
      '[data-operating-information-state="available"]',
    );
    expect(available).not.toBeNull();
    expect(within(available as HTMLElement).getByText("영업시간")).toBeTruthy();
    expect(within(available as HTMLElement).getByText("11:00~20:00")).toBeTruthy();
    expect(screen.getByText(/한국관광공사 TourAPI/)).toBeTruthy();
    expect(screen.getByText(/2026\. 09\. 05\. 13:30 확인/)).toBeTruthy();
    expect(container.textContent).not.toContain("현재 영업 중");
    expect(container.textContent).not.toContain("혼잡");
    expect(container.textContent).not.toContain("주차");
  });

  it("distinguishes loading from provider failure", () => {
    const { rerender } = render(<OperatingInformation loading />);
    expect(screen.getByText("최신 운영 정보를 확인하고 있어요.")).toBeTruthy();

    rerender(
      <OperatingInformation
        loading={false}
        information={{
          place_id: "place:test",
          state: "UNVERIFIED",
          snapshot: null,
          unavailable_reason: "PROVIDER_UNAVAILABLE",
        }}
      />,
    );
    expect(
      screen.getByText("현재 공식 운영 정보를 불러오지 못했어요. 방문 전 다시 확인해 주세요."),
    ).toBeTruthy();
  });
});
