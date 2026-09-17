// @vitest-environment node
import { afterEach, beforeEach, expect, it } from "vitest";
import { once } from "node:events";
import { existsSync } from "node:fs";
import type { Server } from "node:http";
// @ts-expect-error Standalone Node development server.
import { mockServer } from "../../mock/server.mjs";
import fixture from "../features/authenticity/__fixtures__/prepared-scenario.json";

let server: Server;
let origin: string;
beforeEach(async () => {
  server = mockServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterEach(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });

function browser() {
  let cookie = "", token = "";
  const request = async (path: string, method = "GET", body?: unknown) => {
    const response = await fetch(`${origin}/v1/${path}`, {
      method, headers: { cookie, Authorization: `Bearer ${token}`, ...(body instanceof FormData ? {} : { "Content-Type": "application/json" }) },
      body: body instanceof FormData ? body : body === undefined ? undefined : JSON.stringify(body),
    });
    cookie = response.headers.get("set-cookie")?.split(";")[0] ?? cookie;
    return { status: response.status, body: await response.json() };
  };
  return {
    request,
    async initialize() { token = (await request("authenticity/sessions", "POST")).body.token; },
  };
}

it("serves the current results, local photos, details and persisted save actions in an isolated browser session", async () => {
  const a = browser(), b = browser(); await a.initialize(); await b.initialize();
  const info = await a.request("authenticity/info"); expect(info.body.places).toBe(5);
  const input = { ...fixture.profile.submission, request_id: "preview-intent" };
  const profile = await a.request("authenticity/scenario-profiles", "POST", input);
  expect(profile.status).toBe(201); expect(profile.body.submission).toEqual(input);
  const create = { profile_id: profile.body.profile_id, request_id: "preview-run" };
  const result = await a.request("authenticity/runs", "POST", create);
  expect(result.status).toBe(201);
  expect(result.body).toMatchObject({ profile_id: profile.body.profile_id, intent_sha256: profile.body.intent_sha256, ranking_version: "scenario-axis-bridge-ranking.v1", result_count: 5 });
  expect((await a.request("authenticity/runs", "POST", create)).body).toEqual(result.body);
  expect((await a.request("authenticity/runs", "POST", { ...create, profile_id: "other" })).status).toBe(409);
  const runPath = `authenticity/runs/${result.body.run_sha256}`;
  expect((await a.request(runPath)).body).toEqual(result.body);
  expect((await b.request(runPath)).status).toBe(404);
  for (const item of result.body.items) {
    const detail = await a.request(`${runPath}/places/${encodeURIComponent(item.place_id)}`);
    expect(detail.body.item).toEqual(item);
    expect(detail.body.address).toBeTruthy(); expect(detail.body.photos.length).toBeGreaterThan(0);
    for (const photo of detail.body.photos) expect(existsSync(new URL(`../../public${photo.url}`, import.meta.url))).toBe(true);
  }
  const item = result.body.items[0];
  const savePath = `${runPath}/places/${encodeURIComponent(item.place_id)}/saved`;
  expect((await a.request(savePath, "PUT", { saved: true })).body).toEqual({ saved: true });
  expect((await a.request("authenticity/saved")).body).toMatchObject([{ place_id: item.place_id, run_sha256: result.body.run_sha256, name: item.name_ko }]);
  expect((await b.request("authenticity/saved")).body).toEqual([]);
  await a.request(savePath, "PUT", { saved: false });
  expect((await a.request("authenticity/saved")).body).toEqual([]);
  await a.request("mock/reset", "POST");
  expect((await a.request(runPath)).status).toBe(401);
});

it("supports empty, error, retry and preserved old runs without computing real recommendations", async () => {
  const a = browser(); await a.initialize();
  const profile = await a.request("authenticity/scenario-profiles", "POST", { ...fixture.profile.submission, request_id: "profile" });
  const create = { profile_id: profile.body.profile_id, request_id: "empty" };
  await a.request("mock/scenario", "POST", { scenario: "empty" });
  const empty = await a.request("authenticity/runs", "POST", create);
  expect(empty.body).toMatchObject({ state: "EMPTY", items: [], result_count: 0 });
  await a.request("mock/scenario", "POST", { scenario: "error" });
  expect((await a.request("authenticity/runs", "POST", { ...create, request_id: "retry" })).status).toBe(503);
  await a.request("mock/scenario", "POST", { scenario: "normal" });
  expect((await a.request("authenticity/runs", "POST", { ...create, request_id: "retry" })).body.result_count).toBe(5);
  expect((await a.request(`authenticity/runs/${empty.body.run_sha256}`)).body.state).toBe("EMPTY");
  expect((await a.request("authenticity/photos", "POST", { test: true })).status).toBe(415);
});

function upload() {
  const form = new FormData();
  form.append("files", new Blob(["synthetic preview bytes"], { type: "image/png" }), "preview.png");
  return form;
}

it("connects photo upload, automatic confirmation and fixed results without a model, isolating photo receipts", async () => {
  const a = browser(), b = browser(); await a.initialize(); await b.initialize();
  expect((await a.request("authenticity/info")).body.photo_enabled).toBe(true);
  const photo = await a.request("authenticity/photos", "POST", upload());
  expect(photo.status).toBe(201);
  expect(photo.body).toMatchObject({ state: "REVIEW", original_retained: false, targets: {} });
  expect(photo.body.batches[0].provider_id).toBe("synthetic-ui-mock");
  const path = `authenticity/photos/${photo.body.photo_id}`;
  expect((await b.request(path)).status).toBe(404);
  expect((await a.request(`${path}/confirm`, "POST", { candidate_ids: ["invented"] })).status).toBe(422);
  const ids = photo.body.batches.flatMap((batch: { candidates: { candidate_id: string }[] }) => batch.candidates.map(candidate => candidate.candidate_id));
  const confirmed = await a.request(`${path}/confirm`, "POST", { candidate_ids: ids });
  expect(confirmed.body.state).toBe("CONFIRMED");
  expect(Object.keys(confirmed.body.targets)).toHaveLength(8);
  const input = { ...fixture.profile.submission, request_id: "photo-profile", visual_input_kind: "CONFIRMED_PHOTO",
    photo_receipt_sha256: confirmed.body.receipt_sha256, visual_targets: confirmed.body.targets };
  expect((await b.request("authenticity/scenario-profiles", "POST", input)).status).toBe(422);
  expect((await a.request("authenticity/scenario-profiles", "POST", { ...input, visual_targets: {} })).status).toBe(422);
  const profile = await a.request("authenticity/scenario-profiles", "POST", input);
  expect(profile.status).toBe(201);
  expect(profile.body.submission).toEqual(input);
  const run = await a.request("authenticity/runs", "POST", { request_id: "photo-run", profile_id: profile.body.profile_id });
  expect(run.body.result_count).toBe(5);
  const replacement = await a.request("authenticity/photos", "POST", upload());
  expect(replacement.body.photo_id).not.toBe(photo.body.photo_id);
  expect((await a.request(`${path}/confirm`, "POST", { candidate_ids: [replacement.body.batches[0].candidates[0].candidate_id] })).status).toBe(422);
  expect((await a.request(path, "DELETE")).body.deleted).toBe(true);
  expect((await a.request(`${path}/confirm`, "POST", { candidate_ids: ids })).status).toBe(404);
  expect((await a.request("authenticity/scenario-profiles", "POST", { ...input, request_id: "deleted-photo" })).status).toBe(422);
  expect((await a.request(`authenticity/runs/${run.body.run_sha256}`)).status).toBe(200);
});

it("lets a photo error be retried after switching the mock back to normal", async () => {
  const a = browser(); await a.initialize();
  await a.request("mock/scenario", "POST", { scenario: "error" });
  expect((await a.request("authenticity/photos", "POST", upload())).status).toBe(503);
  await a.request("mock/scenario", "POST", { scenario: "normal" });
  expect((await a.request("authenticity/photos", "POST", upload())).status).toBe(201);
});
