import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { RecommendationButton } from "./RecommendationButton";

afterEach(() => vi.useRealTimers());

it("shows actual completed stages without inventing elapsed-time progress", () => {
  vi.useFakeTimers();
  const startedAt = Date.now(), onClick = vi.fn();
  const view = render(<RecommendationButton label="추천 장소 보기" progress={null} onClick={onClick} />);
  fireEvent.click(screen.getByRole("button", { name: "추천 장소 보기" }));
  expect(onClick).toHaveBeenCalledTimes(1);
  view.rerender(<RecommendationButton label="추천 장소 보기" progress={{ stage: "PREFERENCES", startedAt }} onClick={onClick} />);
  const bar = screen.getByRole("progressbar", { name: "추천 진행 상황" });
  expect(bar.getAttribute("aria-valuenow")).toBe("0");
  const button = screen.getByRole("button");
  expect(button).toHaveProperty("disabled", true);
  fireEvent.click(button); expect(onClick).toHaveBeenCalledTimes(1);
  act(() => vi.advanceTimersByTime(16000));
  expect(bar.getAttribute("aria-valuenow")).toBe("0");
  expect(screen.getByRole("status").textContent).toContain("응답을 기다리고 있어요");
  for (const [stage, count] of [["MATCHING", "1"], ["DETAILS", "2"], ["READY", "3"]] as const) {
    view.rerender(<RecommendationButton label="추천 장소 보기" progress={{ stage, startedAt }} onClick={onClick} />);
    expect(bar.getAttribute("aria-valuenow")).toBe(count);
    expect(button.querySelectorAll('[data-state="done"]')).toHaveLength(Number(count));
  }
  expect(button.textContent).toContain("추천 준비 완료");
  expect(button.querySelector('[data-state="active"]')).toBeNull();
  view.rerender(<RecommendationButton label="추천 장소 보기" progress={null} onClick={onClick} />);
  expect(screen.queryByRole("progressbar")).toBeNull();
  expect(screen.getByRole("button", { name: "추천 장소 보기" })).toHaveProperty("disabled", false);
  expect(vi.getTimerCount()).toBe(0);
});


it("can disable the other photo action without showing a second progress indicator", () => {
  const onClick = vi.fn();
  render(<RecommendationButton label="사진 없이 추천 보기" variant="secondary" disabled progress={null} onClick={onClick} />);
  const button = screen.getByRole("button", { name: "사진 없이 추천 보기" });
  expect(button).toHaveProperty("disabled", true);
  expect(button.className).toContain("button--secondary");
  expect(button.getAttribute("aria-busy")).toBe("false");
  expect(screen.queryByRole("progressbar")).toBeNull();
  fireEvent.click(button); expect(onClick).not.toHaveBeenCalled();
});
