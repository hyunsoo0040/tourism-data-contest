import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PreferenceProfile } from "../../api/api";
import { FRONTEND_QUESTIONNAIRE } from "../../content/questionnaire";
import { ProfileStoryButton } from "./ProfileStoryButton";
import { downloadProfileStory, profileStoryData, renderProfileStory } from "./profileStory";

vi.mock("./profileStory", async (importOriginal) => ({
  ...await importOriginal<typeof import("./profileStory")>(),
  renderProfileStory: vi.fn(),
  downloadProfileStory: vi.fn(),
}));

const profile = {
  scores: [
    { axis: "HISTORY_TRADITION", basis_points: 3600, display_score: 36 },
    { axis: "EMOTION_IMAGE", basis_points: 3636, display_score: 36 },
    { axis: "REST_IMMERSION", basis_points: 1800, display_score: 18 },
  ],
  answers: {}, description_ko: "현재 여행 결과", profile_id: "private-profile-id",
  trip_conditions: { visit_date: "2026-09-14" },
} as PreferenceProfile;
const file = new File(["png-test"], "story.png", { type: "image/png" });

function nativeShare(share?: ReturnType<typeof vi.fn>) {
  Object.defineProperty(navigator, "canShare", { configurable: true, value: vi.fn(() => Boolean(share)) });
  Object.defineProperty(navigator, "share", { configurable: true, value: share });
}

async function ready() {
  vi.mocked(renderProfileStory).mockResolvedValue(file);
  render(<ProfileStoryButton profile={profile} questionnaire={FRONTEND_QUESTIONNAIRE} />);
  return screen.findByRole("button", { name: "이미지 공유·저장" });
}

afterEach(() => { vi.resetAllMocks(); nativeShare(); });

describe("profile story sharing", () => {
  it("uses the visible type and 100-point distribution, exporting no private inputs", () => {
    const data = profileStoryData(profile, FRONTEND_QUESTIONNAIRE)!;
    expect(data.character).toBe("무드 위버");
    expect(data.scores.map((score) => score.value)).toEqual([39, 41, 20]);
    expect(Object.keys(data).sort()).toEqual(["character", "image", "isMock", "lens", "role", "scores", "theme", "type"]);
    expect(JSON.stringify(data)).not.toContain("private-profile-id");
    expect(JSON.stringify(data)).not.toContain("2026-09-14");
  });

  it("downloads the PNG when file sharing is unavailable", async () => {
    nativeShare();
    fireEvent.click(await ready());
    expect(downloadProfileStory).toHaveBeenCalledWith(file);
  });

  it("calls native sharing immediately on the tap with the already prepared file", async () => {
    const share = vi.fn().mockResolvedValue(undefined);
    nativeShare(share);
    fireEvent.click(await ready());
    expect(share).toHaveBeenCalledWith({ files: [file] });
    await act(async () => {});
    expect(downloadProfileStory).not.toHaveBeenCalled();
  });

  it("does not download or report failure when the user cancels the share sheet", async () => {
    nativeShare(vi.fn().mockRejectedValue(new DOMException("Cancelled", "AbortError")));
    fireEvent.click(await ready());
    await act(async () => {});
    expect(downloadProfileStory).not.toHaveBeenCalled();
    expect(screen.getByRole("status").textContent).toBe("");
  });

  it("falls back to downloading when a browser rejects sharing", async () => {
    nativeShare(vi.fn().mockRejectedValue(new DOMException("Blocked", "NotAllowedError")));
    fireEvent.click(await ready());
    await waitFor(() => expect(downloadProfileStory).toHaveBeenCalledWith(file));
  });

  it("retries asset failures and never shares the previous profile's PNG", async () => {
    nativeShare();
    vi.mocked(renderProfileStory).mockRejectedValueOnce(new Error("image failed")).mockResolvedValueOnce(file);
    const { rerender } = render(<ProfileStoryButton profile={profile} questionnaire={FRONTEND_QUESTIONNAIRE} />);
    fireEvent.click(await screen.findByRole("button", { name: "이미지 다시 준비" }));
    await screen.findByRole("button", { name: "이미지 공유·저장" });
    let finish: (file: File) => void = () => {};
    vi.mocked(renderProfileStory).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve; }));
    rerender(<ProfileStoryButton profile={{ ...profile, scores: [...profile.scores].reverse() as PreferenceProfile["scores"] }} questionnaire={FRONTEND_QUESTIONNAIRE} />);
    expect(screen.getByRole("button").getAttribute("disabled")).not.toBeNull();
    expect(downloadProfileStory).not.toHaveBeenCalled();
    await act(async () => finish(new File(["new"], "new.png")));
    fireEvent.click(screen.getByRole("button", { name: "이미지 공유·저장" }));
    expect(vi.mocked(downloadProfileStory).mock.lastCall?.[0].name).toBe("new.png");
  });

  it("does not expose sharing for an all-zero result", () => {
    render(<ProfileStoryButton profile={{ ...profile, scores: profile.scores.map((score) => ({ ...score, basis_points: 0, display_score: 0 })) as PreferenceProfile["scores"] }} questionnaire={FRONTEND_QUESTIONNAIRE} />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(renderProfileStory).not.toHaveBeenCalled();
  });
});
