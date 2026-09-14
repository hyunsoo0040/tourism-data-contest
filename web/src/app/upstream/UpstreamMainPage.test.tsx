import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { PROFILE_STORAGE_KEY, resetJourneyStorage, STORAGE_RETENTION_MS, writeProfileReference } from "../storage";
import { UpstreamMainPage } from "./UpstreamMainPage";

beforeEach(() => {
  resetJourneyStorage();
  localStorage.clear();
});

describe("main start link", () => {
  it("starts with travel conditions even when a profile is stored", () => {
    writeProfileReference("saved-profile");
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "12문항 취향 테스트로 자세히 보기" }).getAttribute("href")).toBe("/start");
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/start");
  });

  it("starts with travel conditions for a first-time visitor", () => {
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "12문항 취향 테스트로 자세히 보기" }).getAttribute("href")).toBe("/start");
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/start");
  });

  it.each(["expired", "corrupt"])("does not resume a %s result", (state) => {
    if (state === "expired") writeProfileReference("expired-profile", localStorage, Date.now() - STORAGE_RETENTION_MS - 1);
    else localStorage.setItem(PROFILE_STORAGE_KEY, "{broken-json");
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "12문항 취향 테스트로 자세히 보기" }).getAttribute("href")).toBe("/start");
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/start");
  });

  it("keeps travel conditions first after testing or resetting", () => {
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "12문항 취향 테스트로 자세히 보기" }).getAttribute("href")).toBe("/start");
    writeProfileReference("new-profile");
    fireEvent(window, new Event("focus"));
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/start");
    resetJourneyStorage();
    fireEvent(window, new Event("pageshow"));
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/start");
  });
});
