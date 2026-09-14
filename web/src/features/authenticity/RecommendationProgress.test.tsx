import { act, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { RecommendationProgress } from "./RecommendationProgress";

afterEach(() => vi.useRealTimers());

it("keeps the current stage while time passes, announces a long wait, and stops its timer", () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-09-14T00:00:00Z"));
  const startedAt = Date.now();
  const view = render(<RecommendationProgress stage="PREFERENCES" startedAt={startedAt} />);
  act(() => vi.advanceTimersByTime(16000));
  expect(screen.getByText("16초 경과")).toBeTruthy();
  expect(screen.getByText(/아직 응답을 기다리고 있어요/)).toBeTruthy();
  expect(screen.getByText("취향·여행 조건 확인").closest("li")?.getAttribute("aria-current")).toBe("step");
  expect(screen.getByText("관광지 특성과 선호 비교").closest("li")?.getAttribute("data-state")).toBe("pending");
  view.rerender(<RecommendationProgress stage="MATCHING" startedAt={startedAt} />);
  expect(screen.getByText("취향·여행 조건 확인").closest("li")?.getAttribute("data-state")).toBe("done");
  act(() => vi.advanceTimersByTime(45000));
  expect(screen.getByText("1분 1초 경과")).toBeTruthy();
  view.rerender(<RecommendationProgress stage="READY" startedAt={startedAt} />);
  expect(screen.queryByText(/아직 응답을 기다리고 있어요/)).toBeNull();
  expect(vi.getTimerCount()).toBe(0);
  view.rerender(<RecommendationProgress stage="PREFERENCES" startedAt={Date.now()} />);
  expect(screen.getByText("0초 경과")).toBeTruthy();
  view.unmount(); expect(vi.getTimerCount()).toBe(0);
});
