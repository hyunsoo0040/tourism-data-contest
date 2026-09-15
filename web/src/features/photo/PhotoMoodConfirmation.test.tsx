import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PhotoMoodConfirmation, type MoodReviewView } from "./PhotoMoodConfirmation";

afterEach(cleanup);

const review: MoodReviewView = {
  schema_version: "photo-mood-review.v1", family: "photo-mood-v1", job_id: "a".repeat(64),
  preference_profile_id: "profile:test", draft_sha256: "b".repeat(64), confirmation: null,
  batches: [{ image_index: 1, analysis_kind: "MODEL", candidates: [
    { candidate_id: "c".repeat(64), observation: { dimension: "water", state: "OBSERVED", level: 3, certainty: "HIGH" } },
    { candidate_id: "d".repeat(64), observation: { dimension: "greenery", state: "UNKNOWN", level: null, certainty: "LOW" } },
  ] }],
};

describe("appearance-only confirmation", () => {
  it("sends stored references and inclusion only", async () => {
    const confirm = vi.fn().mockResolvedValue(undefined);
    render(<PhotoMoodConfirmation review={review} onConfirm={confirm} onSkip={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "사진 분위기로 계속" }));
    await waitFor(() => expect(confirm).toHaveBeenCalledWith({
      draft_sha256: review.draft_sha256,
      choices: [{ candidate_id: "c".repeat(64), included: true }],
    }));
    expect(screen.queryByText("초록 식물이 보이는 풍경")).toBeNull();
  });

  it("hides internal candidates and permits skipping without confirmation", () => {
    const confirm = vi.fn(), skip = vi.fn();
    render(<PhotoMoodConfirmation review={review} onConfirm={confirm} onSkip={skip} />);
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByText(/물이 보이는 풍경|water/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "사진 입력 건너뛰기" }));
    expect(skip).toHaveBeenCalledTimes(1);
    expect(confirm).not.toHaveBeenCalled();
  });

  it("makes empty observations an explicit baseline continuation", () => {
    render(<PhotoMoodConfirmation review={{ ...review, batches: [] }} onConfirm={vi.fn()} onSkip={vi.fn()} />);
    expect(screen.getByText("사진에서 분위기를 확인하지 못했어요. 사진 없이 추천을 이어갈 수 있어요.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "사진 분위기 없이 계속" })).toBeTruthy();
  });

  it("does not confirm before continuing and reports failed requests", async () => {
    const confirm = vi.fn().mockRejectedValue(new Error("provider secret"));
    render(<PhotoMoodConfirmation review={review} onConfirm={confirm} onSkip={vi.fn()} />);
    expect(confirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "사진 분위기로 계속" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("확정하지 못했어요"));
    expect(screen.queryByText("provider secret")).toBeNull();
  });
});
