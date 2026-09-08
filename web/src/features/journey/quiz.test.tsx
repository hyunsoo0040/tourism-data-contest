import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import questionnaireArtifact from "../../../../contracts/questionnaire-v2.json";
import { appRoutes } from "../../app/routes";
import {
  DRAFT_STORAGE_KEY,
  PENDING_PROFILE_SUBMISSION_KEY,
  PROFILE_STORAGE_KEY,
  STORAGE_MESSAGES,
  createEmptyDraft,
  writeDraft,
} from "../../app/storage";

const completeTripConditions = {
  visit_date: null,
  visit_time: "UNDECIDED",
  companion: "SOLO",
  transport: "WALK_OR_TRANSIT",
  walking_tolerance: "WITHIN_30_MINUTES",
  indoor_outdoor_preference: "NO_PREFERENCE",
  crowd_avoidance: "MEDIUM",
} as const;

function questionnaireResponse() {
  return new Response(JSON.stringify(questionnaireArtifact), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

async function renderQuiz(initialEntry = "/quiz?q=1") {
  const router = createMemoryRouter(appRoutes, { initialEntries: ["/start", initialEntry] });
  const view = render(<RouterProvider router={router} />);
  const ordinal = Number(new URL(initialEntry, "https://itda.test").searchParams.get("q") ?? "1");
  await screen.findByText(questionnaireArtifact.questions[ordinal - 1]!.title_ko);
  return { router, ...view };
}

describe("/quiz canonical twelve-question journey", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 1,
      trip_conditions: completeTripConditions,
    });
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(questionnaireResponse())));
  });

  it("pushes q navigation and preserves one editable answer through Back and refresh", async () => {
    const firstRender = await renderQuiz();
    expect(screen.getByText("1 / 12")).toBeTruthy();
    expect(screen.getByText("0 / 12 응답 완료")).toBeTruthy();
    await waitFor(() =>
      expect(document.activeElement?.textContent).toBe(questionnaireArtifact.questions[0]!.title_ko),
    );

    fireEvent.click(screen.getAllByRole("radio")[2]);

    await waitFor(() => expect(firstRender.router.state.location.search).toBe("?q=2"));
    expect(await screen.findByText(questionnaireArtifact.questions[1]!.title_ko)).toBeTruthy();
    expect(
      (JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
        answers: { q1?: number };
      }).answers.q1,
    ).toBe(3);

    await act(async () => firstRender.router.navigate(-1));
    await waitFor(() => expect(firstRender.router.state.location.search).toBe("?q=1"));
    await waitFor(() =>
      expect(screen.getAllByRole("radio")[2]?.getAttribute("aria-checked")).toBe("true"),
    );

    firstRender.unmount();

    const refreshed = await renderQuiz("/quiz?q=1");
    expect(screen.getAllByRole("radio")[2]?.getAttribute("aria-checked")).toBe("true");
    refreshed.unmount();
  });

  it("has no independent advance action and redirects unavailable direct entry", async () => {
    const first = await renderQuiz();
    expect(screen.queryByRole("button", { name: "다음 질문" })).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(first.router.state.location.search).toBe("?q=1");
    first.unmount();

    const router = createMemoryRouter(appRoutes, { initialEntries: ["/quiz?q=7"] });
    render(<RouterProvider router={router} />);
    await waitFor(() => expect(router.state.location.search).toBe("?q=1"));
    expect(await screen.findByText(questionnaireArtifact.questions[0]!.title_ko)).toBeTruthy();
    expect(router.state.location.search).not.toContain("q7=");
  });

  it("preserves scroll while advancing, going back, and restarting with accessible question focus", async () => {
    const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
    const focus = vi.spyOn(HTMLElement.prototype, "focus");
    const { router } = await renderQuiz();
    await waitFor(() => expect(document.activeElement?.textContent).toBe(questionnaireArtifact.questions[0]!.title_ko));
    scrollTo.mockClear();
    focus.mockClear();

    fireEvent.click(screen.getAllByRole("radio")[0]);
    await waitFor(() => expect(document.activeElement?.textContent).toBe(questionnaireArtifact.questions[1]!.title_ko));
    expect(scrollTo).not.toHaveBeenCalled();
    expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });

    await act(async () => router.navigate(-1));
    await waitFor(() => expect(document.activeElement?.textContent).toBe(questionnaireArtifact.questions[0]!.title_ko));
    expect(scrollTo).not.toHaveBeenCalled();
    expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });

    fireEvent.click(screen.getByRole("button", { name: "처음부터" }));
    await waitFor(() => expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("0"));
    expect(scrollTo).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "이전" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/start"));
    expect(scrollTo).toHaveBeenCalledWith({ top: 0 });
  });

  it("counts completed answers consistently when advancing, revisiting, refreshing, and restarting", async () => {
    const first = await renderQuiz();
    const progress = () => screen.getByRole("progressbar", { name: "응답 진행도" });
    expect(progress().getAttribute("aria-valuenow")).toBe("0");
    for (let answered = 1; answered <= 2; answered += 1) {
      fireEvent.click(screen.getAllByRole("radio")[0]);
      await waitFor(() => expect(progress().getAttribute("aria-valuenow")).toBe(String(answered)));
      expect(screen.getByText(`${answered} / 12 응답 완료`)).toBeTruthy();
    }
    await act(async () => first.router.navigate(-1));
    expect(progress().getAttribute("aria-valuenow")).toBe("2");
    fireEvent.click(screen.getAllByRole("radio")[1]);
    await waitFor(() => expect(first.router.state.location.search).toBe("?q=3"));
    expect(progress().getAttribute("aria-valuenow")).toBe("2");
    first.unmount();

    await renderQuiz("/quiz?q=3");
    expect(progress().getAttribute("aria-valuenow")).toBe("2");
    fireEvent.click(screen.getByRole("button", { name: "처음부터" }));
    await waitFor(() => expect(progress().getAttribute("aria-valuenow")).toBe("0"));
  });

  it("walks the served order from q=1 through q=12 without putting answers in the URL", async () => {
    const { router } = await renderQuiz();

    for (let ordinal = 1; ordinal < 12; ordinal += 1) {
      expect(screen.getByText(questionnaireArtifact.questions[ordinal - 1]!.title_ko)).toBeTruthy();
      fireEvent.click(screen.getAllByRole("radio")[2]);
      await waitFor(() => expect(router.state.location.search).toBe(`?q=${ordinal + 1}`));
    }

    expect(screen.getByText(questionnaireArtifact.questions[11]!.title_ko)).toBeTruthy();
    expect(router.state.location.search).toBe("?q=12");
    expect(router.state.location.search).not.toContain("answers");
    expect(
      Object.keys(
        (JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
          answers: Record<string, number>;
        }).answers,
      ),
    ).toEqual(["q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11"]);
  });

  it("redirects to /start when complete trip conditions are missing", async () => {
    window.localStorage.clear();
    writeDraft(createEmptyDraft());
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/quiz?q=1"] });
    render(<RouterProvider router={router} />);

    await waitFor(() => expect(router.state.location.pathname).toBe("/start"));
    expect(
      await screen.findByRole("heading", { name: "이번 경주, 어떤 시간을 보내고 싶나요?" }),
    ).toBeTruthy();
  });

  it("submits the complete generated request once and stores a recoverable profile reference", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    let createdProfile: Record<string, unknown> | null = null;
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
      if (String(input) === "/v1/preference-profiles/profile-123" && createdProfile !== null) {
        return new Response(JSON.stringify(createdProfile), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      const submission = JSON.parse(String(init?.body)) as {
        request_id: string;
        trip_conditions: typeof completeTripConditions;
        answers: Record<string, number>;
      };
      createdProfile = {
          profile_id: "profile-123",
          request_id: submission.request_id,
          schema_version: "preference-profile-v2",
          questionnaire_version: questionnaireArtifact.questionnaire_version,
          scoring_version: questionnaireArtifact.scoring_version,
          description_template_version: questionnaireArtifact.description_template_version,
          config_hash: questionnaireArtifact.config_hash,
          created_at: "2026-07-22T12:00:00Z",
          is_current_trip_expectation: true,
          description_ko: "이번 여행에서는 역사·전통과 감성·이미지 경험을 더 기대하고 있어요.",
          trip_conditions: submission.trip_conditions,
          answers: submission.answers,
          scores: [
            { axis: "HISTORY_TRADITION", basis_points: 5000, display_score: 50 },
            { axis: "EMOTION_IMAGE", basis_points: 5000, display_score: 50 },
            { axis: "REST_IMMERSION", basis_points: 5000, display_score: 50 },
          ],
        };
      return new Response(
        JSON.stringify(createdProfile),
        { status: 201, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const { router } = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);

    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(
      await screen.findByRole("heading", { name: "당신이 기대하는 경주의 시간" }),
    ).toBeTruthy();
    const postCalls = fetchMock.mock.calls.filter(([, init]) =>
      init?.method === "POST",
    );
    expect(postCalls).toHaveLength(1);
    expect(JSON.parse(String(postCalls[0]?.[1]?.body))).toEqual({
      request_id: expect.any(String),
      trip_conditions: completeTripConditions,
      answers: {
        ...firstEight,
        q12: 3,
      },
    });
    expect(JSON.parse(window.localStorage.getItem(PROFILE_STORAGE_KEY) ?? "null")).toMatchObject({
      profile_id: "profile-123",
      questionnaire_version: questionnaireArtifact.questionnaire_version,
    });
  });

  it("shows the storage warning when a completed quiz keeps its profile reference only in memory", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    let createdProfile: Record<string, unknown> | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        if (init?.method !== "POST") return new Response(JSON.stringify(createdProfile), { status: 200 });
        const submission = JSON.parse(String(init.body)) as {
          request_id: string;
          trip_conditions: typeof completeTripConditions;
          answers: Record<string, number>;
        };
        createdProfile = {
          profile_id: "profile-memory-quiz",
          request_id: submission.request_id,
          schema_version: "preference-profile-v2",
          questionnaire_version: questionnaireArtifact.questionnaire_version,
          scoring_version: questionnaireArtifact.scoring_version,
          description_template_version: questionnaireArtifact.description_template_version,
          config_hash: questionnaireArtifact.config_hash,
          created_at: "2026-07-22T12:00:00Z",
          is_current_trip_expectation: true,
          description_ko: "이번 여행의 기대를 정리했어요.",
          trip_conditions: submission.trip_conditions,
          answers: submission.answers,
          scores: [
            { axis: "HISTORY_TRADITION", basis_points: 5000, display_score: 50 },
            { axis: "EMOTION_IMAGE", basis_points: 5000, display_score: 50 },
            { axis: "REST_IMMERSION", basis_points: 5000, display_score: 50 },
          ],
        };
        return new Response(JSON.stringify(createdProfile), { status: 201 });
      }),
    );
    const nativeSetItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
      if (key === PROFILE_STORAGE_KEY) throw new DOMException("quota", "QuotaExceededError");
      return nativeSetItem.call(this, key, value);
    });
    const { router } = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);

    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(await screen.findByRole("heading", { name: "당신이 기대하는 경주의 시간" })).toBeTruthy();
    expect(await screen.findByText(STORAGE_MESSAGES.unavailable)).toBeTruthy();
  });

  it("keeps all answers and fails closed when the created profile version or hash mismatches", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 2]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        const submission = JSON.parse(String(init?.body)) as {
          request_id: string;
          answers: Record<string, number>;
          trip_conditions: typeof completeTripConditions;
        };
        return new Response(
          JSON.stringify({
            profile_id: "profile-tampered",
            request_id: submission.request_id,
            questionnaire_version: "questionnaire-v999",
            config_hash: "wrong-hash",
            scoring_version: questionnaireArtifact.scoring_version,
            description_template_version: questionnaireArtifact.description_template_version,
            schema_version: "preference-profile-v2",
            created_at: "2026-07-22T12:00:00Z",
            is_current_trip_expectation: true,
            description_ko: "변조된 응답",
            trip_conditions: submission.trip_conditions,
            answers: submission.answers,
            scores: [],
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    const { router } = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);

    expect((await screen.findByRole("alert")).textContent).toContain(
      "프로필 형식을 확인하지 못했어요. 잠시 후 다시 시도해 주세요.",
    );
    expect(router.state.location.pathname).toBe("/quiz");
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
    expect(
      (JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
        answers: Record<string, number>;
      }).answers,
    ).toEqual({ ...firstEight, q12: 3 });
  });

  it("offers an explicit retry with the same request ID and prevents duplicate in-flight posts", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    const submissions: Array<{
      request_id: string;
      answers: Record<string, number>;
      trip_conditions: typeof completeTripConditions;
    }> = [];
    let postCount = 0;
    let resolveFirstResponse!: (response: Response) => void;
    const firstResponse = new Promise<Response>((resolve) => {
      resolveFirstResponse = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        const submission = JSON.parse(String(init?.body)) as (typeof submissions)[number];
        submissions.push(submission);
        postCount += 1;
        if (postCount === 1) return firstResponse;
        return new Response(
          JSON.stringify({
            profile_id: "profile-retried",
            request_id: submission.request_id,
            questionnaire_version: questionnaireArtifact.questionnaire_version,
            config_hash: questionnaireArtifact.config_hash,
            scoring_version: questionnaireArtifact.scoring_version,
            description_template_version: questionnaireArtifact.description_template_version,
            schema_version: "preference-profile-v2",
            created_at: "2026-07-22T12:00:00Z",
            is_current_trip_expectation: true,
            description_ko: "이번 여행에서는 역사·전통과 감성·이미지 경험을 더 기대하고 있어요.",
            trip_conditions: submission.trip_conditions,
            answers: submission.answers,
            scores: [
              { axis: "HISTORY_TRADITION", basis_points: 5000, display_score: 50 },
              { axis: "EMOTION_IMAGE", basis_points: 5000, display_score: 50 },
              { axis: "REST_IMMERSION", basis_points: 5000, display_score: 50 },
            ],
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    const { router } = await renderQuiz("/quiz?q=12");
    const selectedOption = screen.getAllByRole("radio")[2] as HTMLButtonElement;
    fireEvent.click(selectedOption);
    await waitFor(() => expect(selectedOption.disabled).toBe(true));
    fireEvent.click(selectedOption);
    expect(submissions).toHaveLength(1);
    resolveFirstResponse(
      new Response(JSON.stringify({ detail: "temporary" }), { status: 503 }),
    );

    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(submissions).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "다시 시도하기" }));

    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(submissions).toHaveLength(2);
    expect(submissions[1]!.request_id).toBe(submissions[0]!.request_id);
  });

  it("rejects a malformed matching-version profile without storing partial output", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        const submission = JSON.parse(String(init?.body)) as {
          request_id: string;
          answers: Record<string, number>;
          trip_conditions: typeof completeTripConditions;
        };
        return new Response(
          JSON.stringify({
            profile_id: "profile-malformed",
            request_id: submission.request_id,
            questionnaire_version: questionnaireArtifact.questionnaire_version,
            config_hash: questionnaireArtifact.config_hash,
            scoring_version: questionnaireArtifact.scoring_version,
            description_template_version: questionnaireArtifact.description_template_version,
            schema_version: "preference-profile-v2",
            created_at: "not-a-date",
            is_current_trip_expectation: true,
            description_ko: "완전한 축 점수가 없는 응답",
            trip_conditions: submission.trip_conditions,
            answers: submission.answers,
            scores: [
              { axis: "HISTORY_TRADITION", basis_points: 10001, display_score: 101 },
            ],
          }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    const { router } = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);

    expect((await screen.findByRole("alert")).textContent).toContain(
      "프로필 형식을 확인하지 못했어요. 잠시 후 다시 시도해 주세요.",
    );
    expect(router.state.location.pathname).toBe("/quiz");
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
  });

  it("maps a 422 answer error back to its question and clears stale errors on navigation", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        return new Response(
          JSON.stringify({
            detail: [{ loc: ["body", "answers", "q3"], msg: "Input should be valid" }],
          }),
          { status: 422, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    const { router } = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);

    expect((await screen.findByRole("alert")).textContent).toContain("확인할 답변이 있어요.");
    fireEvent.click(screen.getByRole("button", { name: "답변 확인하기" }));
    await waitFor(() => expect(router.state.location.search).toBe("?q=3"));
    await waitFor(() =>
      expect(document.activeElement?.textContent).toBe(questionnaireArtifact.questions[2]!.title_ko),
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("does not create an answer-required alert during browser question navigation", async () => {
    const { router } = await renderQuiz();
    fireEvent.click(screen.getAllByRole("radio")[2]);
    await waitFor(() => expect(router.state.location.search).toBe("?q=2"));
    expect(screen.queryByRole("alert")).toBeNull();

    await act(async () => router.navigate(-1));
    await waitFor(() => expect(router.state.location.search).toBe("?q=1"));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reuses the pending request ID after refresh but rotates it when the payload changes", async () => {
    const firstEight = Object.fromEntries(
      questionnaireArtifact.questions.slice(0, 11).map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: firstEight,
    });
    const submissions: Array<{ request_id: string; answers: Record<string, number> }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") return questionnaireResponse();
        submissions.push(JSON.parse(String(init?.body)) as (typeof submissions)[number]);
        return new Response(JSON.stringify({ detail: "temporary" }), { status: 503 });
      }),
    );

    const first = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);
    await screen.findByRole("alert");
    first.unmount();

    const refreshed = await renderQuiz("/quiz?q=12");
    fireEvent.click(screen.getAllByRole("radio")[2]);
    await waitFor(() => expect(submissions).toHaveLength(2));
    expect(submissions[1]!.request_id).toBe(submissions[0]!.request_id);

    // Rotating the payload requires a different answer: navigate to q11,
    // pick a different choice, advance to q12, and resubmit.
    await act(async () => refreshed.router.navigate("/quiz?q=11"));
    await screen.findByText(questionnaireArtifact.questions[10]!.title_ko);
    fireEvent.click(screen.getAllByRole("radio")[1]);
    await waitFor(() =>
      expect(
        (JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as {
          answers: Record<string, number>;
        }).answers.q11,
      ).toBe(2),
    );
    await screen.findByText(questionnaireArtifact.questions[11]!.title_ko);
    fireEvent.click(screen.getAllByRole("radio")[2]);
    await waitFor(() => expect(submissions).toHaveLength(3));
    expect(submissions[2]!.request_id).not.toBe(submissions[1]!.request_id);
    refreshed.unmount();
  });

  it.each([
    {
      label: "422 validation",
      response: () =>
        new Response(
          JSON.stringify({
            detail: [{ loc: ["body", "answers", "q3"], msg: "Input should be valid" }],
          }),
          { status: 422, headers: { "Content-Type": "application/json" } },
        ),
    },
    {
      label: "503 service",
      response: () => new Response(JSON.stringify({ detail: "temporary" }), { status: 503 }),
    },
  ])("ignores a delayed $label failure after browser Back leaves q12", async ({ response }) => {
    const allAnswers = Object.fromEntries(
      questionnaireArtifact.questions.map(({ question_id }) => [question_id, 3]),
    );
    writeDraft({
      ...createEmptyDraft(),
      current_route: "/quiz",
      current_question: 12,
      trip_conditions: completeTripConditions,
      answers: allAnswers,
    });
    let resolvePost!: (value: Response) => void;
    const delayedPost = new Promise<Response>((resolve) => {
      resolvePost = resolve;
    });
    let postSignal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) === "/v1/questionnaires/current") {
          return Promise.resolve(questionnaireResponse());
        }
        postSignal = init?.signal ?? undefined;
        return delayedPost;
      }),
    );
    const router = createMemoryRouter(appRoutes, {
      initialEntries: ["/quiz?q=11", "/quiz?q=12"],
      initialIndex: 1,
    });
    render(<RouterProvider router={router} />);
    await screen.findByText(questionnaireArtifact.questions[11]!.title_ko);

    const selectedOption = screen.getAllByRole("radio")[2] as HTMLButtonElement;
    fireEvent.click(selectedOption);
    await waitFor(() => expect(selectedOption.disabled).toBe(true));
    await act(async () => router.navigate(-1));
    await screen.findByText(questionnaireArtifact.questions[10]!.title_ko);
    await waitFor(() => expect(postSignal?.aborted).toBe(true));

    await act(async () => {
      resolvePost(response());
      await delayedPost;
    });

    expect(router.state.location.search).toBe("?q=11");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByRole("button", { name: "다음 질문" })).toBeNull();
    expect(window.localStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY)).not.toBeNull();
  });
});
