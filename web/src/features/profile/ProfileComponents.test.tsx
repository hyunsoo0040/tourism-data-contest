import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createRef } from "react";
import { describe, expect, it, vi } from "vitest";

import type { PreferenceProfile } from "../../api/api";
import { CalculationDetails } from "./CalculationDetails";
import { InputSummary } from "./InputSummary";
import { ProfileNarrative } from "./ProfileNarrative";
import { ProfileRecoveryState } from "./ProfileRecoveryState";
import { ResetDraftDialog } from "./ResetDraftDialog";
import { ThreeAxisProfile } from "./ThreeAxisProfile";

const profile: PreferenceProfile = {
  profile_id: "profile-components",
  request_id: "request-components",
  schema_version: "preference-profile-v1",
  questionnaire_version: "questionnaire-v1",
  scoring_version: "integer-bp-v1",
  description_template_version: "current-trip-expectation-v1",
  config_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  created_at: "2026-07-22T12:00:00Z",
  is_current_trip_expectation: true,
  description_ko: "서버가 보낸 문장을 그대로 보여 줘요.",
  trip_conditions: {
    visit_date: null,
    visit_time: "SUNSET",
    companion: "SOLO",
    transport: "WALK_OR_TRANSIT",
    walking_tolerance: "WITHIN_30_MINUTES",
    indoor_outdoor_preference: "NO_PREFERENCE",
    crowd_avoidance: "MEDIUM",
  },
  answers: { q1: 1, q2: 2, q3: 3, q4: 4, q5: 5, q6: 1, q7: 2, q8: 3, q9: 4 },
  scores: [
    { axis: "HISTORY_TRADITION", basis_points: 0, display_score: 0 },
    { axis: "EMOTION_IMAGE", basis_points: 10_000, display_score: 100 },
    { axis: "REST_IMMERSION", basis_points: 5_000, display_score: 50 },
  ],
};

describe("profile result components", () => {
  it("renders fixed H-E-R meters from display_score at the inclusive boundaries", () => {
    render(<ThreeAxisProfile scores={profile.scores} />);

    const meters = screen.getAllByRole("meter");
    expect(meters.map((meter) => meter.getAttribute("aria-label"))).toEqual([
      "역사·전통 0점 / 100점",
      "감성·이미지 100점 / 100점",
      "휴식·몰입 50점 / 100점",
    ]);
    expect(meters.map((meter) => meter.getAttribute("aria-valuenow"))).toEqual(["0", "100", "50"]);
    expect(meters[0]?.querySelector<HTMLElement>(".axis-meter__fill")?.style.width).toBe("0%");
    expect(meters[1]?.querySelector<HTMLElement>(".axis-meter__fill")?.style.width).toBe("100%");
    expect(screen.queryByText(/basis/i)).toBeNull();
  });

  it("keeps ties in fixed order and renders the server narrative verbatim", () => {
    const tied = profile.scores.map((score) => ({ ...score, basis_points: 3_300, display_score: 33 }));
    const { rerender } = render(<ThreeAxisProfile scores={tied} />);
    expect(screen.getAllByRole("meter").map((meter) => meter.getAttribute("aria-label"))).toEqual([
      "역사·전통 33점 / 100점",
      "감성·이미지 33점 / 100점",
      "휴식·몰입 33점 / 100점",
    ]);

    rerender(<ProfileNarrative description={profile.description_ko} />);
    expect(screen.getByText(profile.description_ko).textContent).toBe(profile.description_ko);
  });

  it("shows only approved provenance, copies the full hash, and formats UTC", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<CalculationDetails profile={profile} />);

    fireEvent.click(screen.getByText("프로필 계산 정보"));
    expect(screen.getByText("0123456789ab…cdef")).toBeTruthy();
    expect(screen.getByText(/UTC/)).toBeTruthy();
    expect(screen.queryByText("basis_points")).toBeNull();
    expect(screen.queryByText("q1")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "전체 설정 식별자 복사" }));
    expect(writeText).toHaveBeenCalledWith(profile.config_hash);
    // copyHash is async: its setCopyState lands in a microtask after the
    // click's synchronous act scope. Drain inside act so the status update
    // stays inside React's scheduler under load (Phase 6 sync pattern).
    await act(async () => {});
  });

  it("summarizes inputs with precise edit actions", () => {
    const onEditTrip = vi.fn();
    const onEditQuestion = vi.fn();
    render(
      <InputSummary
        profile={profile}
        onEditTrip={onEditTrip}
        onEditQuestion={onEditQuestion}
      />,
    );
    fireEvent.click(screen.getByText("입력한 내용"));
    fireEvent.click(screen.getByRole("button", { name: "여행 조건 수정하기" }));
    fireEvent.click(screen.getByRole("button", { name: "질문 7 답변 수정" }));
    expect(onEditTrip).toHaveBeenCalledOnce();
    expect(onEditQuestion).toHaveBeenCalledWith(7);
  });
});

describe("profile recovery and reset components", () => {
  it("renders empty, recovery, busy, API error, and malformed invariant states", () => {
    const { rerender } = render(<ProfileRecoveryState state="empty" onPrimary={vi.fn()} />);
    expect(screen.getByRole("heading", { name: "아직 만든 여행 기대 프로필이 없어요." })).toBeTruthy();

    rerender(<ProfileRecoveryState state="recovery" onPrimary={vi.fn()} />);
    expect(screen.getByRole("button", { name: "프로필 다시 만들기" })).toBeTruthy();

    rerender(<ProfileRecoveryState state="recovery" busy onPrimary={vi.fn()} />);
    expect(screen.getByRole("button", { name: "프로필 다시 만드는 중…" }).getAttribute("aria-busy")).toBe("true");

    rerender(<ProfileRecoveryState state="api-error" onPrimary={vi.fn()} />);
    expect(screen.getByRole("alert").textContent).toContain("프로필을 만들지 못했어요");

    rerender(<ProfileRecoveryState state="invalid" onPrimary={vi.fn()} />);
    expect(screen.getByRole("alert").textContent).toContain("프로필 형식을 확인하지 못했어요");
  });

  it("traps focus, cancels with Escape, confirms explicitly, and surfaces cleanup failure", async () => {
    const onClose = vi.fn();
    const onConfirm = vi.fn().mockReturnValue(false);
    const triggerRef = createRef<HTMLButtonElement>();
    render(
      <>
        <button ref={triggerRef}>처음부터 다시</button>
        <ResetDraftDialog
          open
          triggerRef={triggerRef}
          onClose={onClose}
          onConfirm={onConfirm}
        />
      </>,
    );

    const dialog = screen.getByRole("dialog", { name: "작성한 내용을 지울까요?" });
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "계속 작성하기" }));
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: "모두 지우고 새로 시작하기" }),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "모두 지우고 새로 시작하기" }));
    expect(onConfirm).toHaveBeenCalledOnce();
    await waitFor(() => expect(within(dialog).getByRole("alert").textContent).toContain("저장 내용을 모두 지우지 못했어요"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
  });
});
