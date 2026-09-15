import { StrictMode } from "react";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "../../app/react-router-dom";
import type { Intent, Run } from "./api";
import { prepareScenario, readPreparedScenario } from "./preparedScenario";
import { ScenarioResultsPage } from "./ScenarioResultsPage";
import fixture from "./__fixtures__/prepared-scenario.json";

const run = fixture.run as Run, profile = fixture.profile as unknown as Intent;
const tokenKey = "itda.authenticity.session.v1";
const images: HTMLImageElement[] = [];
function TestImage() {
  const image = document.createElement("img");
  image.decode = vi.fn().mockResolvedValue(undefined);
  images.push(image);
  return image;
}
let fetchMock: ReturnType<typeof vi.fn<(url: string) => Promise<Response>>>;
beforeEach(() => {
  sessionStorage.setItem(tokenKey, crypto.randomUUID()); images.length = 0;
  vi.stubGlobal("Image", TestImage);
  fetchMock = vi.fn(async (url: string) => {
    const path = decodeURIComponent(url);
    let body: unknown;
    if (path === `/v1/authenticity/runs/${run.run_sha256}`) body = run;
    else if (path === `/v1/authenticity/profiles/${profile.profile_id}`) body = profile;
    else if (path === "/v1/authenticity/saved") body = [{ run_sha256: run.run_sha256, place_id: run.items[0]!.place_id }];
    else body = fixture.details.find(detail => path.endsWith(`/places/${detail.item.place_id}`));
    if (!body) throw new Error(`Unexpected request: ${path}`);
    return new Response(JSON.stringify(body));
  });
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); sessionStorage.clear(); });

function results() {
  const router = createMemoryRouter([{ path: "/recommendations/:runId", element: <ScenarioResultsPage /> }], { initialEntries: [`/recommendations/a-${run.run_sha256}`] });
  return render(<StrictMode><RouterProvider router={router} /></StrictMode>);
}

it("waits for every photo to decode, then renders all details on the first paint without fetching again", async () => {
  let done = false;
  const preparing = prepareScenario(run, profile, new AbortController().signal).then(() => { done = true; });
  await waitFor(() => expect(images).toHaveLength(5));
  expect(done).toBe(false); expect(readPreparedScenario(run.run_sha256)).toBeNull();
  images.forEach(image => image.dispatchEvent(new Event("load"))); await preparing;
  expect(images.every(image => vi.mocked(image.decode).mock.calls.length === 1)).toBe(true);
  const requests = fetchMock.mock.calls.length;
  const view = results();
  expect(view.container.querySelectorAll("[data-details-loaded=true]")).toHaveLength(5);
  expect(screen.queryByText("최신 분석으로 추천한 장소를 불러오고 있어요.")).toBeNull();
  expect(screen.queryByText("장소 정보를 불러오고 있어요.")).toBeNull();
  expect(screen.getAllByRole("link", { name: "지도에서 보기" })).toHaveLength(5);
  expect(fetchMock.mock.calls.some(([url]) => url.endsWith("/saved"))).toBe(false);
  await act(async () => {});
  expect(fetchMock.mock.calls).toHaveLength(requests);
  expect(readPreparedScenario(run.run_sha256)).toBeNull();
  view.unmount();
  results();
  expect(screen.getByText("최신 분석으로 추천한 장소를 불러오고 있어요.")).toBeTruthy();
  await waitFor(() => expect(document.querySelectorAll("[data-details-loaded=true]")).toHaveLength(5));
  expect(fetchMock.mock.calls.length).toBeGreaterThan(requests);
});

it("keeps aborted preparation and a changed session out of the handoff", async () => {
  const controller = new AbortController();
  const preparing = prepareScenario(run, profile, controller.signal);
  const rejection = expect(preparing).rejects.toHaveProperty("name", "AbortError");
  await waitFor(() => expect(images).toHaveLength(5));
  controller.abort(); await rejection;
  expect(images.every(image => image.onload === null && image.onerror === null)).toBe(true);
  expect(readPreparedScenario(run.run_sha256)).toBeNull();
  images.length = 0;
  const second = prepareScenario(run, profile, new AbortController().signal);
  await waitFor(() => expect(images).toHaveLength(5));
  images.forEach(image => image.dispatchEvent(new Event("load"))); await second;
  expect(readPreparedScenario("another-run")).toBeNull();
  sessionStorage.setItem(tokenKey, "another-session");
  expect(readPreparedScenario(run.run_sha256)).toBeNull();
});

it("settles stalled photos with an immediate failure state and a retry button, retaining place information", async () => {
  vi.useFakeTimers();
  const preparing = prepareScenario(run, profile, new AbortController().signal);
  await vi.advanceTimersByTimeAsync(8000); await preparing;
  expect(readPreparedScenario(run.run_sha256)?.failedPhotoUrls).toHaveLength(5);
  expect(vi.getTimerCount()).toBe(0);
  vi.useRealTimers();
  const view = results();
  expect(view.container.querySelectorAll("[data-details-loaded=true]")).toHaveLength(5);
  expect(screen.getAllByText("사진을 불러오지 못했어요")).toHaveLength(5);
  fireEvent.click(screen.getAllByRole("button", { name: "사진 다시 불러오기" })[0]!);
  expect(screen.getByRole("img").getAttribute("src")).toBe(fixture.details[0]!.photos[0]!.url);
});

it("does not turn a failed detail request into a partially loaded handoff", async () => {
  const original = fetchMock.getMockImplementation()!;
  fetchMock.mockImplementation(async url => String(url).includes("/places/")
    ? new Response(JSON.stringify({ detail: "장소 정보 연결 실패" }), { status: 503 })
    : original(url));
  await expect(prepareScenario(run, profile, new AbortController().signal)).rejects.toThrow("장소 정보 연결 실패");
  expect(readPreparedScenario(run.run_sha256)).toBeNull();
  expect(images).toHaveLength(0);
});
