import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider, type RouteObject } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DRAFT_STORAGE_KEY,
  STORAGE_MESSAGES,
  createEmptyDraft,
  writeDraft,
} from "../../app/storage";

const shellStyles = readFileSync(resolve(process.cwd(), "src/app/styles/internal.css"), "utf8");

async function loadStartRoutes(): Promise<RouteObject[]> {
  try {
    const routeModulePath = "../../app/routes";
    const module = await import(/* @vite-ignore */ routeModulePath);
    return module.appRoutes;
  } catch {
    throw new Error("Expected the /start route and trip-condition form to be implemented");
  }
}

async function renderStart(initialEntry = "/start") {
  const appRoutes = await loadStartRoutes();
  const router = createMemoryRouter(appRoutes, { initialEntries: [initialEntry] });
  render(<RouterProvider router={router} />);
  await screen.findByRole("heading", { name: "이번 경주, 어떤 시간을 보내고 싶나요?" });
  expect(screen.queryByRole("region", { name: "기능 선택" })).toBeNull();
  return router;
}

function completeRequiredChoices() {
  fireEvent.click(screen.getByRole("radio", { name: "아직 미정" }));
  fireEvent.click(screen.getByRole("radio", { name: "혼자" }));
  fireEvent.click(screen.getByRole("radio", { name: "도보·대중교통" }));
  fireEvent.click(screen.getByRole("radio", { name: "30분 이내로 가볍게" }));
  fireEvent.click(screen.getByRole("radio", { name: "상관없어요" }));
  fireEvent.click(screen.getByRole("radio", { name: "조금 피하고 싶어요" }));
}

describe("/start current-trip form", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("announces linked Korean validation errors and stays on /start", async () => {
    const router = await renderStart();

    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));

    const summary = await screen.findByRole("alert");
    expect(within(summary).getByText("방문 시간을 선택해 주세요.")).toBeTruthy();
    expect(within(summary).getByText("동행을 선택해 주세요.")).toBeTruthy();
    for (const link of within(summary).getAllByRole("link")) {
      const targetId = link.getAttribute("href")?.slice(1);
      expect(targetId).toBeTruthy();
      expect(document.getElementById(targetId ?? "")).toBeTruthy();
    }
    expect(router.state.location.pathname).toBe("/start");
  });

  it("persists generated-contract enum values and routes only to /quiz?q=1", async () => {
    const router = await renderStart();
    fireEvent.change(screen.getByLabelText("방문 날짜 (선택)"), {
      target: { value: "2026-10-03" },
    });
    completeRequiredChoices();

    fireEvent.click(screen.getByRole("button", { name: "취향 테스트 시작하기" }));

    await waitFor(() => expect(router.state.location.pathname).toBe("/quiz"));
    expect(router.state.location.search).toBe("?q=1");
    expect(router.state.location.search).not.toContain("SOLO");
    const stored = JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
      trip_conditions: Record<string, unknown>;
      questionnaire_version: string;
    };
    expect(stored.questionnaire_version).toBe("questionnaire-v2");
    expect(stored.trip_conditions).toEqual({
      visit_date: "2026-10-03",
      visit_time: "UNDECIDED",
      companion: "SOLO",
      transport: "WALK_OR_TRANSIT",
      walking_tolerance: "WITHIN_30_MINUTES",
      indoor_outdoor_preference: "NO_PREFERENCE",
      crowd_avoidance: "MEDIUM",
    });
  });

  it("restores a valid draft and dismisses the recovery notice without clearing values", async () => {
    writeDraft({
      ...createEmptyDraft(),
      trip_conditions: {
        visit_date: null,
        visit_time: "MORNING",
        companion: "FRIEND_OR_PARTNER",
      },
    });

    await renderStart();
    expect(await screen.findByText(STORAGE_MESSAGES.recovered)).toBeTruthy();
    expect((screen.getByRole("radio", { name: "오전" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("radio", { name: "친구·연인" }) as HTMLInputElement).checked).toBe(
      true,
    );

    fireEvent.click(screen.getByRole("button", { name: "계속 작성하기" }));

    expect(screen.queryByText(STORAGE_MESSAGES.recovered)).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).not.toBeNull();
  });

  it("announces corrupt storage recovery without exposing the malformed payload", async () => {
    window.localStorage.setItem(DRAFT_STORAGE_KEY, "{secret-looking-corrupt-data");

    await renderStart();

    expect(await screen.findByRole("status")).toHaveProperty(
      "textContent",
      STORAGE_MESSAGES.invalid,
    );
    expect(screen.queryByText("secret-looking-corrupt-data")).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it("keeps restored data on cancel and clears it only after reset confirmation", async () => {
    writeDraft({
      ...createEmptyDraft(),
      trip_conditions: { visit_time: "DAYTIME", companion: "SOLO" },
    });
    await renderStart();

    const resetTrigger = screen.getByRole("button", { name: "처음부터 시작하기" });
    fireEvent.click(resetTrigger);
    expect(screen.getByRole("dialog", { name: "작성한 내용을 지울까요?" })).toBeTruthy();
    expect(document.activeElement?.textContent).toBe("계속 작성하기");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).not.toBeNull();
    expect(document.activeElement).toBe(resetTrigger);

    fireEvent.click(resetTrigger);
    fireEvent.click(screen.getByRole("button", { name: "모두 지우고 새로 시작하기" }));

    await screen.findByText(STORAGE_MESSAGES.reset);
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });
});

describe("mobile action and error-summary CSS contracts", () => {
  it("keeps the primary action fixed at 320x568 with safe-area and document clearance", () => {
    expect(shellStyles).toMatch(
      /\.start-action-bar\s*\{[^}]*position:\s*fixed[^}]*right:\s*0[^}]*bottom:\s*0[^}]*left:\s*0[^}]*\}/s,
    );
    expect(shellStyles).toMatch(
      /\.start-action-bar\s*\{[^}]*env\(safe-area-inset-bottom\)[^}]*\}/s,
    );
    expect(shellStyles).toMatch(
      /\.start-page\s*\{[^}]*padding-bottom:\s*calc\([^}]*safe-area-inset-bottom[^}]*\)[^}]*\}/s,
    );
    expect(shellStyles).not.toMatch(/overflow-x:\s*(?:clip|hidden)/);
    expect(shellStyles).toMatch(/\*\s*\{[^}]*box-sizing:\s*border-box[^}]*\}/s);
    expect(shellStyles).toMatch(
      /\.start-action-bar \.button\s*\{[^}]*width:\s*100%[^}]*max-width:\s*720px[^}]*margin-inline:\s*auto[^}]*\}/s,
    );
  });

  it("returns the action to document flow for constrained-height or zoomed layouts", () => {
    expect(shellStyles).toMatch(
      /@media\s*\(min-width:\s*768px\),\s*\(max-height:\s*480px\)[\s\S]*?\.start-action-bar\s*\{[^}]*position:\s*static[^}]*\}/,
    );
  });

  it("gives every error-summary anchor a 44px target", () => {
    expect(shellStyles).toMatch(
      /\.error-summary a\s*\{[^}]*display:\s*inline-flex[^}]*min-height:\s*44px[^}]*align-items:\s*center[^}]*\}/s,
    );
  });
});
