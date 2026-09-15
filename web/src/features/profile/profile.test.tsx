import { StrictMode } from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import questionnaireArtifact from "../../../../contracts/questionnaire-v2.json";
import { FRONTEND_QUESTIONNAIRE } from "../../content/questionnaire";
import {
  profileSubmissionFingerprint,
  type PreferenceProfile,
  type QuestionnaireSubmission,
} from "../../api/api";
import { appRoutes } from "../../app/routes";
import {
  DRAFT_STORAGE_KEY,
  PROFILE_STORAGE_KEY,
  STORAGE_MESSAGES,
  createEmptyDraft,
  resetJourneyStorage,
  writeDraft,
  writeProfileReference,
} from "../../app/storage";
import {
  writeConfirmedPhotoReference,
  writeConfirmedMoodReference,
  CONFIRMED_MOOD_REFERENCE_STORAGE_KEY,
} from "../photo/photoProjection";
import { ProfileRecommendationCTA } from "./ProfileRecommendationCTA";
import { writeScenarioPhoto } from "../authenticity/scenario";
import type { Photo } from "../authenticity/api";
import photoFixture from "../authenticity/__fixtures__/scenario-photo.json";
import { groundedTripInputSha256, writeGroundedTripInput } from "../journey/groundedTrip";

const tripConditions = {
  visit_date: null,
  visit_time: "SUNSET",
  companion: "SOLO",
  transport: "WALK_OR_TRANSIT",
  walking_tolerance: "WITHIN_30_MINUTES",
  indoor_outdoor_preference: "NO_PREFERENCE",
  crowd_avoidance: "MEDIUM",
} as const;
const answers = {
  q1: 1, q2: 2, q3: 3, q4: 1, q5: 2, q6: 3,
  q7: 1, q8: 2, q9: 3, q10: 1, q11: 2, q12: 3,
} as const;

function profile(overrides: Partial<PreferenceProfile> = {}): PreferenceProfile {
  return {
    profile_id: "profile-current",
    request_id: "request-current",
    schema_version: "preference-profile-v2",
    questionnaire_version: "questionnaire-v2",
    scoring_version: "choice-distribution-v3",
    description_template_version: "current-trip-expectation-v1",
    config_hash: questionnaireArtifact.config_hash,
    created_at: "2026-07-22T12:00:00Z",
    is_current_trip_expectation: true,
    description_ko: "이번 여행에서는 대상•원형형과 의미•이미지형 경험을 더 기대하고 있어요.",
    trip_conditions: tripConditions,
    answers,
    scores: [
      { axis: "HISTORY_TRADITION", basis_points: 0, display_score: 0 },
      { axis: "EMOTION_IMAGE", basis_points: 10_000, display_score: 100 },
      { axis: "REST_IMMERSION", basis_points: 5_000, display_score: 50 },
    ],
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function renderProfile() {
  const router = createMemoryRouter(appRoutes, { initialEntries: ["/profile"] });
  render(<RouterProvider router={router} />);
  await waitFor(() => expect(screen.queryByLabelText("저장된 여행 내용 불러오는 중")).toBeNull());
  return router;
}

async function renderStrictProfile() {
  const router = createMemoryRouter(appRoutes, { initialEntries: ["/profile"] });
  render(
    <StrictMode>
      <RouterProvider router={router} />
    </StrictMode>,
  );
  await waitFor(() => expect(screen.queryByLabelText("저장된 여행 내용 불러오는 중")).toBeNull());
  return router;
}

describe("/profile result, reload, and recovery", () => {
  it("reuses an identical extra-needs run but creates a new request after the needs change, including photo mode", async () => {
    const currentProfile = profile({ profile_id: "profile-facility-current" });
    const inputSha256 = await profileSubmissionFingerprint(currentProfile.trip_conditions, currentProfile);
    const bodies: Record<string, unknown>[] = [];
    const firstGrounded = { visit_date: "2026-10-03", visit_time: null, required_facilities: ["accessible_toilet" as const] };
    writeGroundedTripInput(firstGrounded);
    writeConfirmedMoodReference(currentProfile.profile_id, "f".repeat(64), "e".repeat(64));
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      bodies.push(body);
      return Promise.resolve(jsonResponse({ schema_version: "itda.recommendation-run-created.v1",
        recommendation_run_id: `recommendation-run:needs-${bodies.length}`, request_id: body.request_id,
        preference_profile_id: currentProfile.profile_id, preference_input_sha256: inputSha256 }));
    }));
    const router = createMemoryRouter([
      { path: "/profile", element: <ProfileRecommendationCTA profile={currentProfile} photoJobId={"f".repeat(64)} /> },
      { path: "/recommendations/:runId", element: <p>시설 추천 완료</p> },
    ], { initialEntries: ["/profile"] });
    render(<RouterProvider router={router} />);
    async function submit() {
      const button = screen.getByRole("button", { name: "사진 취향을 반영해 추천 보기" });
      await waitFor(() => expect(button).toHaveProperty("disabled", false));
      fireEvent.click(button);
      await screen.findByText("시설 추천 완료");
    }
    await submit();
    const stored = JSON.parse(window.sessionStorage.getItem("itda:phase5:current-recommendation:v2")!);
    expect(stored.schema_version).toBe("phase5-current-recommendation-v4");
    expect(stored.preference_input_sha256).toBe(inputSha256);
    expect(stored.grounded_input_sha256).toBe(await groundedTripInputSha256(firstGrounded));
    await act(async () => { await router.navigate("/profile"); });
    await submit();
    expect(bodies).toHaveLength(1);
    writeGroundedTripInput({ ...firstGrounded, required_facilities: ["step_free_entry"] });
    await act(async () => { await router.navigate("/profile"); });
    await submit();
    expect(bodies).toHaveLength(2);
    expect(bodies[1]!.request_id).not.toBe(bodies[0]!.request_id);
    expect(bodies[1]!.grounded_input).toMatchObject({ required_facilities: ["step_free_entry"] });
    expect(bodies[1]!.photo_job_id).toBe("f".repeat(64));
  });

  it("retries the same explicit needs with one request ID and replaces it when only those needs change", async () => {
    const currentProfile = profile({ profile_id: "profile-facility-retry" });
    const bodies: Record<string, unknown>[] = [];
    writeGroundedTripInput({ visit_date: "2026-10-03", visit_time: "14:30", required_facilities: [] });
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return Promise.resolve(jsonResponse({}, 500));
    }));
    const router = createMemoryRouter([
      { path: "/profile", element: <ProfileRecommendationCTA profile={currentProfile} /> },
      { path: "/edit", element: <p>추가 조건 수정</p> },
    ], { initialEntries: ["/profile"] });
    render(<RouterProvider router={router} />);
    const cta = screen.getByRole("button", { name: "바로 추천 보기" });
    await waitFor(() => expect(cta).toHaveProperty("disabled", false));
    fireEvent.click(cta);
    fireEvent.click(await screen.findByRole("button", { name: "다시 시도하기" }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]!.request_id).toBe(bodies[0]!.request_id);
    await act(async () => { await router.navigate("/edit"); });
    writeGroundedTripInput({ visit_date: "2026-10-03", visit_time: "15:30", required_facilities: [] });
    await act(async () => { await router.navigate("/profile"); });
    const changed = screen.getByRole("button", { name: "바로 추천 보기" });
    await waitFor(() => expect(changed).toHaveProperty("disabled", false));
    fireEvent.click(changed);
    await waitFor(() => expect(bodies).toHaveLength(3));
    expect(bodies[2]!.request_id).not.toBe(bodies[0]!.request_id);
    expect(bodies[2]!.grounded_input).toMatchObject({ visit_time: "15:30" });
    expect(bodies[2]!.preference_profile_id).toBe(bodies[0]!.preference_profile_id);
  });

  it("retries sightseeing with one request ID and offers no excluded purposes", async () => {
    const currentProfile = profile({ profile_id: "profile-purpose-retry" });
    const bodies: Record<string, unknown>[] = [];
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return Promise.resolve(jsonResponse({ code: "TEMPORARY_FAILURE" }, 500));
    }));
    const router = createMemoryRouter([{ path: "/profile", element: <ProfileRecommendationCTA profile={currentProfile} /> }], { initialEntries: ["/profile"] });
    render(<RouterProvider router={router} />);
    const cta = screen.getByRole("button", { name: "바로 추천 보기" });
    await waitFor(() => expect(cta).toHaveProperty("disabled", false));
    fireEvent.click(cta);
    fireEvent.click(await screen.findByRole("button", { name: "다시 시도하기" }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[0]!.purpose).toBe("SIGHTSEEING");
    expect(bodies[1]!.request_id).toBe(bodies[0]!.request_id);
    expect(bodies[1]!.purpose).toBe("SIGHTSEEING");
    expect(screen.queryByRole("combobox", { name: "추천 여행 목적" })).toBeNull();
    expect(screen.queryByRole("option", { name: "먹거리" })).toBeNull();
    expect(screen.queryByRole("option", { name: "숙소" })).toBeNull();
  });

  it("discards a stored food run and reuses only the new sightseeing run", async () => {
    const currentProfile = profile({ profile_id: "profile-purpose-current" });
    const inputSha256 = await profileSubmissionFingerprint(currentProfile.trip_conditions, currentProfile);
    window.sessionStorage.setItem("itda:phase5:current-recommendation:v2", JSON.stringify({
      schema_version: "phase5-current-recommendation-v3", recommendation_run_id: "old-food-run",
      preference_profile_id: currentProfile.profile_id, preference_input_sha256: inputSha256,
      photo_job_id: null, purpose: "FOOD",
    }));
    const bodies: Record<string, unknown>[] = [];
    vi.stubGlobal("fetch", vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      bodies.push(body);
      return Promise.resolve(jsonResponse({
        schema_version: "itda.recommendation-run-created.v1",
        recommendation_run_id: `recommendation-run:purpose-${bodies.length}`,
        request_id: body.request_id,
        preference_profile_id: currentProfile.profile_id,
        preference_input_sha256: inputSha256,
      }));
    }));
    const router = createMemoryRouter([
      { path: "/profile", element: <ProfileRecommendationCTA profile={currentProfile} /> },
      { path: "/recommendations/:runId", element: <p>추천 완료</p> },
    ], { initialEntries: ["/profile"] });
    render(<RouterProvider router={router} />);
    let cta = screen.getByRole("button", { name: "바로 추천 보기" });
    await waitFor(() => expect(cta).toHaveProperty("disabled", false));
    fireEvent.click(cta);
    await screen.findByText("추천 완료");
    await act(async () => { await router.navigate("/profile"); });
    expect(bodies[0]!.purpose).toBe("SIGHTSEEING");
    cta = screen.getByRole("button", { name: "바로 추천 보기" });
    await waitFor(() => expect(cta).toHaveProperty("disabled", false));
    fireEvent.click(cta);
    await screen.findByText("추천 완료");
    expect(bodies).toHaveLength(1);

  });

  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("refetches a stored profile, renders only server values, and restores a missing draft", async () => {
    writeProfileReference("profile-current");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(profile()));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(screen.queryByText("대표 유형 점수")).toBeNull();
    expect(document.querySelector(".match-card > b")).toBeNull();
    expect(screen.getByText("무드 위버").tagName).toBe("B");
    expect(screen.getAllByRole("meter").map((meter) => meter.getAttribute("aria-valuenow"))).toEqual(["0", "67", "33"]);
    expect(screen.queryByText("당신의 여행 한 문장")).toBeNull();
    expect(screen.queryByText("입력한 내용")).toBeNull();
    expect(screen.queryByText("프로필 계산 정보")).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith("/v1/preference-profiles/profile-current", expect.any(Object));
    const restored = JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as { answers: unknown; trip_conditions: unknown };
    expect(restored.answers).toEqual(answers);
    expect(restored.trip_conditions).toEqual(tripConditions);
  });

  it("keeps a matching saved profile usable when JSON object keys arrive in another order", async () => {
    const current = profile();
    writeProfileReference(current.profile_id);
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    const reverseKeys = (value: object) => Object.fromEntries(Object.entries(value).reverse());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      ...current,
      trip_conditions: reverseKeys(current.trip_conditions),
      answers: reverseKeys(current.answers),
    })));
    await renderProfile();
    expect(await screen.findByText("취향에 맞는 볼거리·체험을 추천해요.")).toBeTruthy();
    expect(screen.queryByText("기대 프로필을 다시 만들 수 있어요.")).toBeNull();
  });

  it("keeps photo input on its dedicated route", async () => {
    writeProfileReference("profile-current");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(profile())));
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/photo"] });
    render(<RouterProvider router={router} />);

    expect(await screen.findByRole("heading", { name: "사진으로 전하는 취향" })).toBeTruthy();
    expect(router.state.location.pathname).toBe("/photo");
    expect(screen.queryByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeNull();
  });

  function scenarioWire(current: PreferenceProfile) {
    const inputs: Record<string, unknown>[] = [];
    const runs: Record<string, unknown>[] = [];
    const run = { profile_id: "a".repeat(64), intent_sha256: "b".repeat(64), run_sha256: "c".repeat(64), ranking_version: "scenario-axis-bridge-ranking.v1", state: "EMPTY", result_count: 0, items: [] };
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === `/v1/preference-profiles/${current.profile_id}`) return jsonResponse(current);
      if (path === "/v1/authenticity/sessions") return jsonResponse({ token: "scenario-test-token" });
      if (path === "/v1/authenticity/scenario-profiles") {
        inputs.push(JSON.parse(String(init?.body)));
        return jsonResponse({ profile_id: "a".repeat(64), intent_sha256: "b".repeat(64) });
      }
      if (path === "/v1/authenticity/runs" && init?.method === "POST") {
        runs.push(JSON.parse(String(init.body)));
        return jsonResponse(run);
      }
      if (path === `/v1/authenticity/runs/${run.run_sha256}`) return jsonResponse(run);
      if (path === "/v1/authenticity/saved") return jsonResponse([]);
      return new Promise<Response>(() => undefined);
    });
    vi.stubGlobal("fetch", fetchMock);
    return { inputs, runs, fetchMock };
  }

  it.each(["creation", "preparation"])("retries a failed scenario %s with the same request IDs after explicit retry", async stage => {
    const current = profile({ profile_id: "profile-retry-scenario" });
    writeProfileReference(current.profile_id);
    const wire = scenarioWire(current), original = wire.fetchMock.getMockImplementation()!;
    const runBodies: unknown[] = []; let failed = false;
    wire.fetchMock.mockImplementation(async (path, init) => {
      if (String(path) === "/v1/authenticity/runs" && init?.method === "POST") {
        runBodies.push(JSON.parse(String(init.body)));
        if (stage === "creation" && !failed) { failed = true; return jsonResponse({ detail: "일시적인 연결 실패" }, 503); }
      }
      if (stage === "preparation" && String(path) === `/v1/authenticity/runs/${"c".repeat(64)}` && !failed) { failed = true; return jsonResponse({ detail: "일시적인 연결 실패" }, 503); }
      return original(path, init);
    });
    const router = await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "추천 장소 보기" }));
    expect((await screen.findByRole("alert")).textContent).toContain("일시적인 연결 실패");
    expect(runBodies).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "추천 장소 보기" }));
    await waitFor(() => expect(router.state.location.pathname).toContain("/recommendations/a-"));
    expect(wire.inputs).toHaveLength(2); expect(wire.inputs[0]).toEqual(wire.inputs[1]);
    expect(runBodies).toHaveLength(2); expect(runBodies[0]).toEqual(runBodies[1]);
  });

  it("keeps a failed photo replacement and automatically confirms every observed atmosphere", async () => {
    const current = profile({ profile_id: "profile-photo-api" });
    writeProfileReference(current.profile_id);
    const wire = scenarioWire(current), original = wire.fetchMock.getMockImplementation()!;
    let uploads = 0; const confirmations: unknown[] = [];
    const candidates = photoFixture.review.batches.flatMap(batch => batch.candidates);
    const allConfirmed = { ...photoFixture.confirmed,
      selected_candidate_ids: candidates.map(candidate => candidate.candidate_id),
      targets: Object.fromEntries(candidates.map(candidate => [candidate.observation.dimension, candidate.observation.level])),
    };
    const createUrl = vi.fn(() => "blob:synthetic-photo");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: vi.fn() }));
    wire.fetchMock.mockImplementation(async (path, init) => {
      if (String(path) === "/v1/authenticity/info") return jsonResponse({ photo_enabled: true });
      if (String(path) === "/v1/authenticity/photos") {
        expect(init.body).toBeInstanceOf(FormData);
        return ++uploads === 1 ? jsonResponse(photoFixture.review) : jsonResponse({ detail: "사진 교체 실패" }, 503);
      }
      if (String(path).endsWith("/confirm")) { confirmations.push(JSON.parse(String(init.body))); return jsonResponse(allConfirmed); }
      return original(path, init);
    });
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/photo"] });
    render(<RouterProvider router={router} />);
    const picker = await screen.findByLabelText("여행 분위기 참고 사진");
    expect((picker as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "사진을 분위기 분석에 사용하는 데 동의해요." }));
    await waitFor(() => expect((picker as HTMLInputElement).disabled).toBe(false));
    const file = new File(["synthetic fixture: provider is stubbed"], "test.jpg", { type: "image/jpeg" });
    fireEvent.change(picker, { target: { files: [file] } });
    await screen.findByText("사진에서 확인한 분위기를 모두 추천에 자동으로 반영해요.");
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    expect(screen.queryByText(/녹지|greenery|3\/4/)).toBeNull();
    fireEvent.change(picker, { target: { files: [file] } });
    expect((await screen.findByRole("alert")).textContent).toContain("사진 교체 실패");
    expect(screen.getByAltText("선택한 여행 사진 1").getAttribute("src")).toBe("blob:synthetic-photo");
    fireEvent.click(screen.getByRole("button", { name: "사진 분위기로 추천 보기" }));
    await waitFor(() => expect(router.state.location.pathname).toContain("/recommendations/a-"));
    expect(confirmations).toEqual([{ candidate_ids: allConfirmed.selected_candidate_ids }]);
    expect(wire.inputs[0]).toMatchObject({ answers: current.answers, visual_input_kind: "CONFIRMED_PHOTO", photo_receipt_sha256: allConfirmed.receipt_sha256, visual_targets: allConfirmed.targets });
  });

  it.each(["unknown", "confirmation failure"])("does not submit photo preferences for %s", async mode => {
    const current = profile({ profile_id: "profile-photo-unavailable" });
    writeProfileReference(current.profile_id);
    const wire = scenarioWire(current), original = wire.fetchMock.getMockImplementation()!;
    const review = structuredClone(photoFixture.review) as Photo;
    if (mode === "unknown") review.batches.forEach(batch => batch.candidates.forEach(candidate => {
      candidate.observation = { ...candidate.observation, state: "UNKNOWN", level: null, certainty: "LOW" };
    }));
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:synthetic-photo", revokeObjectURL: vi.fn() }));
    let confirmations = 0;
    wire.fetchMock.mockImplementation(async (path, init) => {
      if (String(path) === "/v1/authenticity/info") return jsonResponse({ photo_enabled: true });
      if (String(path) === "/v1/authenticity/photos") return jsonResponse(review);
      if (String(path).endsWith("/confirm")) { confirmations++; return jsonResponse({ detail: "사진 반영 실패" }, 503); }
      return original(path, init);
    });
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/photo"] });
    render(<RouterProvider router={router} />);
    const picker = await screen.findByLabelText("여행 분위기 참고 사진");
    fireEvent.click(screen.getByRole("checkbox", { name: "사진을 분위기 분석에 사용하는 데 동의해요." }));
    await waitFor(() => expect(picker).toHaveProperty("disabled", false));
    fireEvent.change(picker, { target: { files: [new File(["synthetic"], "test.png", { type: "image/png" })] } });
    const apply = await screen.findByRole("button", { name: "사진 분위기로 추천 보기" });
    if (mode === "unknown") {
      expect(apply).toHaveProperty("disabled", true);
      expect(screen.getByText(/사진에서 분위기를 확인하지 못했어요/)).toBeTruthy();
      expect(confirmations).toBe(0);
    } else {
      fireEvent.click(apply);
      expect((await screen.findByRole("alert")).textContent).toContain("사진 반영 실패");
      expect(apply).toHaveProperty("disabled", false);
      expect(confirmations).toBe(1);
    }
    expect(wire.inputs).toHaveLength(0);
    expect(router.state.location.pathname).toBe("/photo");
    expect(screen.queryByRole("button", { name: "사진 없이 추천 보기" })).toBeNull();
    expect(picker).toHaveProperty("disabled", false);

  });

  it("advances progress only after real request boundaries and clears it after failure", async () => {
    const current = profile({ profile_id: "profile-stage-check" });
    writeProfileReference(current.profile_id);
    const wire = scenarioWire(current), original = wire.fetchMock.getMockImplementation()!;
    let resolveProfile!: (response: Response) => void, resolveRun!: (response: Response) => void;
    wire.fetchMock.mockImplementation(async (path, init) => {
      if (String(path) === "/v1/authenticity/scenario-profiles") return new Promise<Response>(resolve => { resolveProfile = resolve; });
      if (String(path) === "/v1/authenticity/runs" && init?.method === "POST") return new Promise<Response>(resolve => { resolveRun = resolve; });
      return original(path, init);
    });
    await renderProfile(); fireEvent.click(await screen.findByRole("button", { name: "추천 장소 보기" }));
    await waitFor(() => expect(resolveProfile).toBeDefined());
    expect(screen.getByRole("progressbar", { name: "추천 진행 상황" }).getAttribute("aria-valuenow")).toBe("0");
    expect(resolveRun).toBeUndefined();
    await act(async () => resolveProfile(jsonResponse({ profile_id: "a".repeat(64), intent_sha256: "b".repeat(64) })));
    await waitFor(() => expect(resolveRun).toBeDefined());
    expect(screen.getByRole("progressbar", { name: "추천 진행 상황" }).getAttribute("aria-valuenow")).toBe("1");
    await act(async () => resolveRun(jsonResponse({ detail: "일시적인 연결 실패" }, 503)));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByRole("progressbar", { name: "추천 진행 상황" })).toBeNull();
    expect((screen.getByRole("button", { name: "추천 장소 보기" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("waits for profile review and sends unchanged scenario answers to the latest API", async () => {
    const current = profile({ profile_id: "profile-no-photo" });
    writeProfileReference(current.profile_id);
    const wire = scenarioWire(current);
    const router = await renderProfile();
    const cta = await screen.findByRole("button", { name: "추천 장소 보기" });
    expect(wire.inputs).toHaveLength(0); expect(wire.runs).toHaveLength(0);
    fireEvent.click(cta);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/recommendations/a-${"c".repeat(64)}`));
    expect(wire.inputs[0]).toMatchObject({ schema_version: "scenario-expectation-bridge.v1", questionnaire_config_hash: current.config_hash, answers: current.answers, trip_conditions: current.trip_conditions, visual_input_kind: "NONE", visual_targets: {}, photo_receipt_sha256: null });
    expect(wire.inputs[0]).not.toHaveProperty("photo_job_id");
    expect(wire.inputs[0]).not.toHaveProperty("desired_levels");
    expect(wire.runs).toHaveLength(1);
    expect(wire.fetchMock.mock.calls.some(([path]) => path === "/v1/recommendation-runs")).toBe(false);
  });

  it("binds only explicitly confirmed current-profile photo targets to the scenario bridge", async () => {
    const current = profile({ profile_id: "profile-with-photo" });
    writeProfileReference(current.profile_id);
    writeScenarioPhoto(current.profile_id, { photo_id: "photo-current", state: "CONFIRMED", targets: { greenery: 3 }, receipt_sha256: "d".repeat(64), batches: [], created_at: "2026-09-14T00:00:00Z", deletion_state: "ORIGINAL_DISCARDED", original_retained: false, selected_candidate_ids: [] } satisfies Photo);
    const wire = scenarioWire(current);
    const router = await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "사진 취향을 반영해 추천 보기" }));
    await waitFor(() => expect(router.state.location.pathname).toContain("/recommendations/a-"));
    expect(wire.inputs[0]).toMatchObject({ photo_receipt_sha256: "d".repeat(64), visual_input_kind: "CONFIRMED_PHOTO", visual_targets: { greenery: 3 } });
    expect(wire.inputs[0]).not.toHaveProperty("photo_job_id");
  });

  it("does not reuse historical mixed-purpose runs or another profile's photo targets", async () => {
    const current = profile({ profile_id: "profile-photo-current" });
    writeProfileReference(current.profile_id);
    writeConfirmedPhotoReference(current.profile_id, "e".repeat(64));
    writeScenarioPhoto("another-profile", { photo_id: "foreign", state: "CONFIRMED", targets: { greenery: 3 }, receipt_sha256: "d".repeat(64), batches: [], created_at: "2026-09-14T00:00:00Z", deletion_state: "ORIGINAL_DISCARDED", original_retained: false, selected_candidate_ids: [] } satisfies Photo);
    window.sessionStorage.setItem("itda:phase5:current-recommendation:v2", JSON.stringify({ recommendation_run_id: "historical-mixed-purpose", preference_profile_id: current.profile_id }));
    const wire = scenarioWire(current);
    const router = await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "추천 장소 보기" }));
    await waitFor(() => expect(router.state.location.pathname).toContain("/recommendations/a-"));
    expect(wire.inputs[0]).toMatchObject({ visual_targets: {}, photo_receipt_sha256: null });
    expect(wire.runs).toHaveLength(1);
  });

  it("does not infer current photo preferences from historical trait or mood receipts", async () => {
    const current = profile({ profile_id: "profile-legacy-photo" });
    writeProfileReference(current.profile_id);
    writeConfirmedPhotoReference(current.profile_id, "e".repeat(64));
    writeConfirmedMoodReference(current.profile_id, "e".repeat(64), "f".repeat(64));
    const wire = scenarioWire(current);
    await renderProfile();
    expect(await screen.findByRole("button", { name: "추천 장소 보기" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "사진 취향을 반영해 추천 보기" })).toBeNull();
    expect(wire.inputs).toHaveLength(0);
  });

  it("recovers a generated-contract-valid 160-character profile ID", async () => {
    const maximumId = "p".repeat(160);
    writeProfileReference(maximumId);
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(profile({ profile_id: maximumId })));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith(
      `/v1/preference-profiles/${maximumId}`,
      expect.any(Object),
    );
  });

  it("shows the defined direct-entry empty state without making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await renderProfile();
    expect(await screen.findByRole("heading", { name: "아직 만든 여행 기대 프로필이 없어요." })).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("recreates a missing profile with one persisted request ID across a failed retry", async () => {
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-stale");
    const submissions: QuestionnaireSubmission[] = [];
    let postCount = 0;
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return jsonResponse(questionnaireArtifact);
      if (String(input).endsWith("profile-stale")) return jsonResponse({ detail: "not found" }, 404);
      const submission = JSON.parse(String(init?.body)) as QuestionnaireSubmission;
      submissions.push(submission);
      postCount += 1;
      if (postCount === 1) return jsonResponse({ detail: "temporary" }, 503);
      return jsonResponse(profile({ profile_id: "profile-rebuilt", request_id: submission.request_id }), 201);
    });
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "프로필 다시 만들기" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("프로필을 만들지 못했어요"));
    fireEvent.click(screen.getByRole("button", { name: "다시 시도하기" }));

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(submissions).toHaveLength(2);
    expect(submissions[0]?.request_id).toBe(submissions[1]?.request_id);
    expect(JSON.parse(window.localStorage.getItem(PROFILE_STORAGE_KEY) ?? "null").profile_id).toBe("profile-rebuilt");
  });

  it("surfaces profile-reference quota failure while showing a rebuilt in-memory profile", async () => {
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-stale");
    const nativeSetItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
      if (key === PROFILE_STORAGE_KEY) throw new DOMException("quota", "QuotaExceededError");
      return nativeSetItem.call(this, key, value);
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return jsonResponse(questionnaireArtifact);
        if (init?.method !== "POST") return jsonResponse({ detail: "not found" }, 404);
        const submission = JSON.parse(String(init.body)) as QuestionnaireSubmission;
        return jsonResponse(profile({ profile_id: "profile-memory", request_id: submission.request_id }), 201);
      }),
    );

    await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "프로필 다시 만들기" }));

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(await screen.findByText(STORAGE_MESSAGES.unavailable)).toBeTruthy();
  });

  it("fails closed on malformed output and retries an API failure without showing partial scores", async () => {
    writeProfileReference("profile-current");
    const malformed = { ...profile(), scores: [profile().scores[0]] };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(malformed)).mockResolvedValueOnce(jsonResponse(profile()));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("프로필 형식을 확인하지 못했어요"));
    expect(screen.queryByRole("meter")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "다시 시도하기" }));
    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
  });

  it("keeps a newer complete draft and offers recovery when the fetched profile echo is stale", async () => {
    const editedAnswers = { ...answers, q7: 2 } as const;
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers: editedAnswers });
    writeProfileReference("profile-current");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(profile())));

    await renderProfile();

    expect(await screen.findByRole("heading", { name: "기대 프로필을 다시 만들 수 있어요." })).toBeTruthy();
    expect(screen.queryByRole("meter")).toBeNull();
    expect(
      (JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as { answers: typeof editedAnswers }).answers.q7,
    ).toBe(2);
  });

  it("aborts and ignores a delayed profile GET after navigation leaves the route", async () => {
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-current");
    let resolveGet!: (response: Response) => void;
    const delayedGet = new Promise<Response>((resolve) => {
      resolveGet = resolve;
    });
    let requestSignal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith("/authenticity/info")) return Promise.resolve(jsonResponse({ candidate_sha256: null, regions: [] }));
        requestSignal = init?.signal ?? undefined;
        return delayedGet;
      }),
    );
    const router = await renderProfile();
    await waitFor(() => expect(requestSignal).toBeDefined());

    await act(async () => router.navigate("/start"));
    await screen.findByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" });
    expect(requestSignal?.aborted).toBe(true);
    await act(async () => {
      resolveGet(jsonResponse(profile()));
      await delayedGet;
    });

    expect(router.state.location.pathname).toBe("/start");
    expect(screen.queryByRole("meter")).toBeNull();
  });

  it("starts a fresh profile GET after StrictMode cleans up the first setup", async () => {
    writeProfileReference("profile-current");
    const signals: AbortSignal[] = [];
    let callCount = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_input: RequestInfo | URL, init?: RequestInit) => {
        callCount += 1;
        if (init?.signal) signals.push(init.signal);
        if (callCount === 1) return new Promise<Response>(() => undefined);
        return Promise.resolve(jsonResponse(profile()));
      }),
    );

    await renderStrictProfile();

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(callCount).toBe(2);
    expect(signals[0]?.aborted).toBe(true);
    expect(signals[1]?.aborted).toBe(false);
  });

  it("aborts and ignores a delayed retry GET after navigation leaves the route", async () => {
    writeProfileReference("profile-current");
    let resolveRetry!: (response: Response) => void;
    const delayedRetry = new Promise<Response>((resolve) => {
      resolveRetry = resolve;
    });
    let retrySignal: AbortSignal | undefined;
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ detail: "temporary" }, 503))
      .mockImplementationOnce((_input: RequestInfo | URL, init?: RequestInit) => {
        retrySignal = init?.signal ?? undefined;
        return delayedRetry;
      }).mockResolvedValue(jsonResponse({ candidate_sha256: null, regions: [] }));
    vi.stubGlobal("fetch", fetchMock);
    const router = await renderProfile();
    fireEvent.click(await screen.findByRole("button", { name: "다시 시도하기" }));
    await waitFor(() => expect(retrySignal).toBeDefined());

    await act(async () => router.navigate("/start"));
    await screen.findByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" });
    expect(retrySignal?.aborted).toBe(true);
    await act(async () => {
      resolveRetry(jsonResponse(profile()));
      await delayedRetry;
    });

    expect(router.state.location.pathname).toBe("/start");
    expect(screen.queryByRole("meter")).toBeNull();
  });

  it("keeps recommendation, photo and reset actions without the two profile edit buttons", async () => {
    writeProfileReference("profile-current");
    scenarioWire(profile());
    await renderProfile();
    await screen.findByRole("button", { name: "추천 장소 보기" });
    expect(screen.queryByRole("button", { name: "답변 수정하기" })).toBeNull();
    expect(screen.queryByRole("button", { name: "여행 조건 수정하기" })).toBeNull();
    expect(screen.getByRole("button", { name: "사진으로 추천받기" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "테스트 다시하기" })).toBeTruthy();
  });

  it("announces answer recalculation and focuses the three-axis heading after refetch", async () => {
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-current");
    let latestProfile = profile();
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return jsonResponse(questionnaireArtifact);
      if (init?.method === "POST") {
        const submission = JSON.parse(String(init.body)) as QuestionnaireSubmission;
        latestProfile = profile({ profile_id: "profile-answer-edited", request_id: submission.request_id, answers: submission.answers });
        return jsonResponse(latestProfile, 201);
      }
      return jsonResponse(latestProfile);
    });
    vi.stubGlobal("fetch", fetchMock);
    const router = await renderProfile();
    await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" });
    await act(async () => router.navigate("/quiz", { state: { questionOrdinal: 1, editingProfile: true } }));
    await screen.findByText(FRONTEND_QUESTIONNAIRE.questions[0]!.title_ko);
    fireEvent.click(screen.getAllByRole("radio")[1]);
    for (let ordinal = 1; ordinal < 12; ordinal += 1) {
      await screen.findByText(FRONTEND_QUESTIONNAIRE.questions[ordinal]!.title_ko);
      fireEvent.click(screen.getAllByRole("radio")[2]);
    }

    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(await screen.findByText("수정한 답변으로 기대 프로필을 다시 만들었어요.")).toBeTruthy();
    await waitFor(() =>
      expect(document.activeElement?.textContent).toBe("이번 여행에서 기대하는 시간"),
    );
  });

  it("cancels reset safely, then clears only IT-DA data after explicit confirmation", async () => {
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-current");
    window.localStorage.setItem("another-app", "keep");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(profile())));
    const router = await renderProfile();
    await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" });

    const trigger = screen.getByRole("button", { name: "테스트 다시하기" });
    fireEvent.click(trigger);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).not.toBeNull();

    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("button", { name: "모두 지우고 새로 시작하기" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/start"));
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem(PROFILE_STORAGE_KEY)).toBeNull();
    expect(window.localStorage.getItem("another-app")).toBe("keep");
  });
});

describe("/profile legacy questionnaire-v1 stored profiles", () => {
  const legacyV1Profile = {
    profile_id: "profile-legacy-v1",
    request_id: "request-legacy-v1",
    schema_version: "preference-profile-v1",
    questionnaire_version: "questionnaire-v1",
    scoring_version: "integer-bp-v1",
    description_template_version: "current-trip-expectation-v1",
    config_hash: "bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c",
    created_at: "2026-07-22T12:00:00Z",
    is_current_trip_expectation: true,
    description_ko: "레거시 프로필",
    trip_conditions: tripConditions,
    answers: { q1: 4, q2: 5, q3: 3, q4: 2, q5: 1, q6: 5, q7: 4, q8: 3, q9: 2 },
    scores: [
      { axis: "HISTORY_TRADITION", basis_points: 5_000, display_score: 50 },
      { axis: "EMOTION_IMAGE", basis_points: 5_000, display_score: 50 },
      { axis: "REST_IMMERSION", basis_points: 5_000, display_score: 50 },
    ],
  } as unknown as PreferenceProfile;

  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("serves a legacy v1 profile instead of rejecting it as an invalid contract", async () => {
    writeProfileReference("profile-legacy-v1");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(legacyV1Profile));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();

    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(screen.getAllByRole("meter")).toHaveLength(3);
    expect(screen.queryByText(STORAGE_MESSAGES.invalid)).toBeNull();
  });

  it("does not leak legacy Likert answers into a v2 draft", async () => {
    writeProfileReference("profile-legacy-v1");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(legacyV1Profile));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();

    await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" });
    // No v2 draft is seeded from v1 answers.
    expect(window.localStorage.getItem(DRAFT_STORAGE_KEY)).toBeNull();
  });

  it("never routes a v1 profile through the draft-mismatch rebuild path", async () => {
    writeProfileReference("profile-legacy-v1");
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(legacyV1Profile));
    vi.stubGlobal("fetch", fetchMock);

    await renderProfile();

    await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" });
    expect(screen.queryByText("기대 프로필을 다시 만들었어요")).toBeNull();
    expect(screen.queryByRole("button", { name: "다시 만들기" })).toBeNull();
  });
});

describe("/start profile edit mode", () => {
  beforeEach(() => {
    resetJourneyStorage();
    window.localStorage.clear();
    vi.unstubAllGlobals();
    writeDraft({ ...createEmptyDraft(), current_route: "/profile", trip_conditions: tripConditions, answers });
    writeProfileReference("profile-current");
  });

  it("keeps stored values on safe return and recalculates changed conditions with a new profile", async () => {
    const posted: QuestionnaireSubmission[] = [];
    let latestProfile = profile();
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return jsonResponse(questionnaireArtifact);
      if (init?.method !== "POST") return jsonResponse(latestProfile);
      const submission = JSON.parse(String(init?.body)) as QuestionnaireSubmission;
      posted.push(submission);
      latestProfile = profile({
        profile_id: "profile-edited",
        request_id: submission.request_id,
        trip_conditions: submission.trip_conditions,
      });
      return jsonResponse(latestProfile, 201);
    });
    vi.stubGlobal("fetch", fetchMock);
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/start?mode=edit"] });
    render(<RouterProvider router={router} />);

    expect(await screen.findByRole("button", { name: "수정 내용 반영하기" })).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: "친구" }));
    fireEvent.click(screen.getByRole("button", { name: "변경하지 않고 프로필로 돌아가기" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect((JSON.parse(window.localStorage.getItem(DRAFT_STORAGE_KEY) ?? "null") as { trip_conditions: typeof tripConditions }).trip_conditions.companion).toBe("SOLO");

    await act(async () => {
      await router.navigate("/start?mode=edit");
    });
    expect(await screen.findByRole("button", { name: "수정 내용 반영하기" })).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: "친구" }));
    fireEvent.click(screen.getByRole("button", { name: "수정 내용 반영하기" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(await screen.findByText("수정한 답변으로 기대 프로필을 다시 만들었어요.")).toBeTruthy();
    await waitFor(() =>
      expect(document.activeElement?.textContent).toBe("이번 여행에서 기대하는 시간"),
    );
    expect(posted.at(-1)?.trip_conditions.companion).toBe("FRIEND_OR_PARTNER");
    expect(JSON.parse(window.localStorage.getItem(PROFILE_STORAGE_KEY) ?? "null").profile_id).toBe("profile-edited");
  });

  it("keeps the edited profile usable and warns when its reference falls back to memory", async () => {
    let latestProfile = profile();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === "/v1/questionnaires/current") return jsonResponse(questionnaireArtifact);
        if (init?.method !== "POST") return jsonResponse(latestProfile);
        const submission = JSON.parse(String(init.body)) as QuestionnaireSubmission;
        latestProfile = profile({
          profile_id: "profile-memory-edited",
          request_id: submission.request_id,
          trip_conditions: submission.trip_conditions,
        });
        return jsonResponse(latestProfile, 201);
      }),
    );
    const nativeSetItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (this: Storage, key, value) {
      if (key === PROFILE_STORAGE_KEY) throw new DOMException("quota", "QuotaExceededError");
      return nativeSetItem.call(this, key, value);
    });
    const router = createMemoryRouter(appRoutes, { initialEntries: ["/start?mode=edit"] });
    render(<RouterProvider router={router} />);
    expect(await screen.findByRole("button", { name: "수정 내용 반영하기" })).toBeTruthy();

    fireEvent.click(screen.getByRole("radio", { name: "친구" }));
    fireEvent.click(screen.getByRole("button", { name: "수정 내용 반영하기" }));

    await waitFor(() => expect(router.state.location.pathname).toBe("/profile"));
    expect(await screen.findByRole("heading", { name: "여행에서의 진짜다움(진정성)이란?" })).toBeTruthy();
    expect(await screen.findByText(STORAGE_MESSAGES.unavailable)).toBeTruthy();
  });
});
