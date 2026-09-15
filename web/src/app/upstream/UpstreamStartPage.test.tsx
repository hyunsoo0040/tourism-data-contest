import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchPreferenceProfile, type PreferenceProfile } from "../../api/api";
import { createAndStorePreferenceProfile } from "../../features/profile/profileSubmission";
import { AppShell } from "../AppShell";
import { createEmptyDraft, readDraft, readProfileReference, resetJourneyStorage, writeDraft, writeProfileReference } from "../storage";
import { UpstreamStartPage } from "./UpstreamStartPage";

vi.mock("../../api/api", async (original) => ({
  ...await original<typeof import("../../api/api")>(),
  fetchPreferenceProfile: vi.fn(),
}));
vi.mock("../../features/profile/profileSubmission", () => ({ createAndStorePreferenceProfile: vi.fn() }));

const answers = { q1: 1, q2: 2, q3: 3, q4: 1, q5: 2, q6: 3, q7: 1, q8: 2, q9: 3, q10: 1, q11: 2, q12: 3 } as const;
// The resume controller consumes only answers; response validation belongs to the API client.
const previous = { profile_id: "previous-profile", answers } as PreferenceProfile;

function fillConditions() {
  fireEvent.change(screen.getByLabelText("방문 날짜 (선택)"), { target: { value: "2099-10-03" } });
  for (const name of ["아직 미정", "친구", "도보·대중교통", "30분 이내로 가볍게", "상관없어요", "조금 피하고 싶어요"]) {
    fireEvent.click(screen.getByRole("radio", { name }));
  }
}

async function renderResume(path = "/start") {
  const router = createMemoryRouter([{
    element: <AppShell />,
    children: [
      { path: "/start", element: <UpstreamStartPage /> },
      { path: "/profile", element: <main><h1>프로필 결과</h1></main> },
      { path: "/quiz", element: <main><h1>취향 테스트</h1></main> },
    ],
  }], { initialEntries: [path] });
  const view = render(<RouterProvider router={router} />);
  await screen.findByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" });
  fillConditions();
  return { router, ...view };
}

function submit() {
  fireEvent.submit(document.getElementById("trip-condition-form")!);
}

beforeEach(() => {
  resetJourneyStorage();
  localStorage.clear();
  vi.mocked(fetchPreferenceProfile).mockReset().mockResolvedValue(previous);
  vi.mocked(createAndStorePreferenceProfile).mockReset().mockResolvedValue({ profile: previous, reference: null });
});

describe("resuming a saved test through trip conditions", () => {
  it("uses the main-page logo treatment", async () => {
    await renderResume();

    expect(screen.getByRole("link", { name: "IT-DA 소개로 이동" }).classList.contains("main-page-logo")).toBe(true);
  });

  it.each(["/start", "/start?resume=profile"])("reuses completed answers and applies new conditions from %s", async (path) => {
    writeProfileReference(previous.profile_id);
    writeDraft({ ...createEmptyDraft(), answers: { q1: 3 } });
    const { router } = await renderResume(path);
    expect(router.state.location.pathname).toBe("/start");
    expect(screen.getByRole("button", { name: "여행 조건 반영하고 프로필 보기" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "처음부터 시작하기" })).toHaveLength(1);
    submit();
    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(fetchPreferenceProfile).toHaveBeenCalledWith(previous.profile_id, { signal: expect.any(AbortSignal) });
    expect(createAndStorePreferenceProfile).toHaveBeenCalledWith(
      expect.objectContaining({ visit_date: "2099-10-03", companion: "FRIEND_OR_PARTNER" }),
      answers, expect.any(AbortSignal), expect.any(Function),
    );
    expect(readDraft().draft).toMatchObject({
      current_route: "/profile", answers,
      trip_conditions: { visit_date: "2099-10-03", companion: "FRIEND_OR_PARTNER" },
    });
  });

  it("keeps restart available after dismissing recovery and only discards results after confirmation", async () => {
    writeProfileReference(previous.profile_id);
    writeDraft({ ...createEmptyDraft(), answers });
    const { router } = await renderResume();
    fireEvent.click(screen.getByRole("button", { name: "계속 작성하기" }));
    fireEvent.click(screen.getByRole("button", { name: "처음부터 시작하기" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "계속 작성하기" }));
    expect(readProfileReference().profile?.profile_id).toBe(previous.profile_id);
    expect(screen.getByRole("button", { name: "여행 조건 반영하고 프로필 보기" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "처음부터 시작하기" }));
    fireEvent.click(screen.getByRole("button", { name: "모두 지우고 새로 시작하기" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(readProfileReference().profile).toBeNull();
    expect(readDraft().draft).toBeNull();
    expect(screen.getByRole("button", { name: "취향 테스트 시작하기" })).toBeTruthy();
    fillConditions();
    submit();
    await waitFor(() => expect(router.state.location.pathname).toBe("/quiz"));
    expect(fetchPreferenceProfile).not.toHaveBeenCalled();
    expect(createAndStorePreferenceProfile).not.toHaveBeenCalled();
    expect(readDraft().draft?.answers).toEqual({});
  });

  it("offers restart when only a completed profile reference remains", async () => {
    writeProfileReference(previous.profile_id);
    await renderResume();
    expect(screen.getByRole("button", { name: "처음부터 시작하기" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "여행 조건 반영하고 프로필 보기" })).toBeTruthy();
  });

  it("retains entered conditions after a failed lookup and allows retry", async () => {
    writeProfileReference(previous.profile_id);
    vi.mocked(fetchPreferenceProfile).mockRejectedValueOnce(new Error("offline"));
    const { router } = await renderResume();
    submit();
    await screen.findByText(/기존 테스트 결과를 반영하지 못했어요/);
    expect(router.state.location.pathname).toBe("/start");
    expect(createAndStorePreferenceProfile).not.toHaveBeenCalled();
    expect((screen.getByLabelText("방문 날짜 (선택)") as HTMLInputElement).value).toBe("2099-10-03");
    submit();
    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
  });

  it("starts the quiz if the saved reference has disappeared", async () => {
    const { router } = await renderResume();
    submit();
    await waitFor(() => expect(router.state.location.pathname).toBe("/quiz"));
    expect(fetchPreferenceProfile).not.toHaveBeenCalled();
    expect(createAndStorePreferenceProfile).not.toHaveBeenCalled();
  });

  it("does not create a result if the user leaves during lookup", async () => {
    writeProfileReference(previous.profile_id);
    let finish!: (profile: PreferenceProfile) => void;
    vi.mocked(fetchPreferenceProfile).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const { router, unmount } = await renderResume();
    submit();
    await waitFor(() => expect(fetchPreferenceProfile).toHaveBeenCalledOnce());
    const signal = vi.mocked(fetchPreferenceProfile).mock.calls[0][1]?.signal;
    unmount();
    await act(async () => { finish(previous); });
    expect(signal?.aborted).toBe(true);
    expect(createAndStorePreferenceProfile).not.toHaveBeenCalled();
    expect(router.state.location.pathname).toBe("/start");
  });
});
