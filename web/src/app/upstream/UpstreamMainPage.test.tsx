import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { PROFILE_STORAGE_KEY, resetJourneyStorage, STORAGE_RETENTION_MS, writeProfileReference } from "../storage";
import { UpstreamMainPage } from "./UpstreamMainPage";

beforeEach(() => {
  resetJourneyStorage();
  localStorage.clear();
});

describe("main start link", () => {
  it("opens the current journey even when a legacy result is stored", () => {
    writeProfileReference("saved-profile");
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/trip");
  });

  it("keeps the existing start destination for a first-time visitor", () => {
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/trip");
  });

  it.each(["expired", "corrupt"])("does not resume a %s result", (state) => {
    if (state === "expired") writeProfileReference("expired-profile", localStorage, Date.now() - STORAGE_RETENTION_MS - 1);
    else localStorage.setItem(PROFILE_STORAGE_KEY, "{broken-json");
    render(<UpstreamMainPage />);
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/trip");
  });

  it("refreshes the destination when the user returns after testing or resetting", () => {
    render(<UpstreamMainPage />);
    writeProfileReference("new-profile");
    fireEvent(window, new Event("focus"));
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/trip");
    resetJourneyStorage();
    fireEvent(window, new Event("pageshow"));
    expect(screen.getByRole("link", { name: "시작하기" }).getAttribute("href")).toBe("/trip");
  });
});
