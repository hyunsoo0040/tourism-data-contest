import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  GROUNDED_TRIP_STORAGE_KEY,
  groundedTripForRecommendation,
  groundedTripInputSha256,
  parseGroundedTripInput,
  readGroundedTripInput,
  resetGroundedTripInput,
  writeGroundedTripInput,
} from "./groundedTrip";
import { TripConditionForm } from "./TripConditionForm";

const EMPTY = { visit_date: null, visit_time: null, required_facilities: [] };

beforeEach(() => {
  window.sessionStorage.clear();
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ candidate_sha256: "a".repeat(64), regions: [
    { region_code: "11", region_name: "서울특별시", place_count: 50 },
    { region_code: "12", region_name: "전남광주통합특별시", place_count: 42 },
    { region_code: "51", region_name: "강원특별자치도", place_count: 30 },
  ] }))));
});
afterEach(() => vi.unstubAllGlobals());

describe("separate explicit trip context", () => {
  it("matches the backend canonical authority hash without modifying the questionnaire fingerprint", async () => {
    expect(await groundedTripInputSha256({ visit_date: "2026-10-03", visit_time: "14:30",
      required_facilities: ["wheelchair_rental", "accessible_toilet"] }))
      .toBe("8b1ec81104a759c8407c9b1260a1629a3c9c9045c4685b92914988ca0b85a0a1");
    expect(groundedTripForRecommendation({ ...EMPTY, visit_date: "2026-10-03" })).toBeNull();
  });
  it("stores only explicitly selected needs in canonical order, separately from profile storage", () => {
    expect(readGroundedTripInput()).toEqual(EMPTY);
    expect(writeGroundedTripInput({
      visit_date: "2026-10-03", visit_time: "14:30",
      required_facilities: ["wheelchair_rental", "accessible_toilet"],
    })).toBe(true);
    expect(readGroundedTripInput()).toEqual({
      visit_date: "2026-10-03", visit_time: "14:30",
      required_facilities: ["accessible_toilet", "wheelchair_rental"],
    });
    expect(resetGroundedTripInput()).toBe(true);
    expect(readGroundedTripInput()).toEqual(EMPTY);
  });

  it("carries an explicit national region into requests and their fingerprint, with nationwide as the default", async () => {
    const seoul = { ...EMPTY, region_code: "11" };
    expect(writeGroundedTripInput(seoul)).toBe(true);
    expect(groundedTripForRecommendation()).toEqual(seoul);
    expect(await groundedTripInputSha256(seoul)).not.toBe(await groundedTripInputSha256({ ...EMPTY, region_code: "26" }));
    expect(await groundedTripInputSha256({ ...EMPTY, region_code: null })).toBe(await groundedTripInputSha256(EMPTY));
  });

  it.each([
    { ...EMPTY, companion: "WITH_SENIORS" },
    { ...EMPTY, required_facilities: ["wheelchair_rental", "wheelchair_rental"] },
    { ...EMPTY, required_facilities: ["guessed_mobility_need"] },
    { ...EMPTY, visit_date: "2026-02-30" },
    { ...EMPTY, visit_time: "25:00" },
    { ...EMPTY, region_code: "47130" },
    { ...EMPTY, region_code: "KR" },
  ])("rejects invalid or inferred context without manufacturing facility choices", (input) => {
    expect(parseGroundedTripInput(input)).toBeNull();
    window.sessionStorage.setItem(GROUNDED_TRIP_STORAGE_KEY, JSON.stringify(input));
    expect(readGroundedTripInput()).toEqual(EMPTY);
  });

  it("reports storage failure so a selected need cannot silently disappear", () => {
    const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("disabled"); });
    expect(writeGroundedTripInput(EMPTY)).toBe(false);
    spy.mockRestore();
  });
});

describe("explicit facilities in the trip form", () => {
  function form(onSubmit = vi.fn()) {
    render(<TripConditionForm
      defaultValues={{ visit_date: "2099-10-03", visit_time: "DAYTIME", companion: "WITH_SENIORS",
        transport: "CAR_OR_TAXI", walking_tolerance: "WITHIN_30_MINUTES",
        indoor_outdoor_preference: "NO_PREFERENCE", crowd_avoidance: "HIGH" }}
      recovered={false} onDismissRecovery={() => {}} onReset={() => true} onSubmit={onSubmit}
    />);
    return onSubmit;
  }

  it("does not infer facilities from seniors and preserves the existing profile submission shape", async () => {
    const onSubmit = form();
    expect(screen.getAllByRole("checkbox").every((input) => !(input as HTMLInputElement).checked)).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "장애인 화장실" }));
    fireEvent.change(screen.getByLabelText("정확한 방문 시간 (선택)"), { target: { value: "14:30" } });
    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ visit_date: "2099-10-03", visit_time: "DAYTIME",
      companion: "WITH_SENIORS", transport: "CAR_OR_TAXI", walking_tolerance: "WITHIN_30_MINUTES",
      indoor_outdoor_preference: "NO_PREFERENCE", crowd_avoidance: "HIGH" });
    expect(readGroundedTripInput()).toEqual({ visit_date: "2099-10-03", visit_time: "14:30",
      required_facilities: ["accessible_toilet"] });
  });

  it("restores explicit choices without changing them when the companion changes", () => {
    writeGroundedTripInput({ ...EMPTY, required_facilities: ["stroller_rental"] });
    form();
    expect((screen.getByRole("checkbox", { name: "유모차 대여" }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("radio", { name: "혼자" }));
    expect((screen.getByRole("checkbox", { name: "유모차 대여" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("checkbox", { name: "휠체어 대여" }) as HTMLInputElement).checked).toBe(false);
  });

  it("restores and submits a province choice without changing the sealed questionnaire fields", async () => {
    writeGroundedTripInput({ ...EMPTY, region_code: "11" });
    const onSubmit = form();
    const select = screen.getByRole("combobox", { name: "어디로 떠날까요?" });
    expect(select).toHaveProperty("value", "11");
    await waitFor(() => expect(select.querySelectorAll("option")).toHaveLength(4));
    expect(screen.getByRole("option", { name: "전남광주통합특별시 · 42곳" })).toBeTruthy();
    fireEvent.change(select, { target: { value: "51" } });
    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(readGroundedTripInput().region_code).toBe("51");
    expect(onSubmit.mock.calls[0]?.[0]).not.toHaveProperty("region_code");
  });

  it("keeps the user on the form if an explicit need cannot be stored", async () => {
    const onSubmit = form();
    fireEvent.click(screen.getByRole("checkbox", { name: "단차 없는 출입구" }));
    const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("disabled"); });
    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));
    await screen.findByRole("alert");
    expect(onSubmit).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
