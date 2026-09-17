import { randomUUID } from "node:crypto";
import fixture from "../src/features/authenticity/__fixtures__/prepared-scenario.json" with { type: "json" };
import { photoMock, hasConfirmedPhoto } from "./photos.mjs";
import { canonical, hash } from "./data.mjs";

// Published place snapshots and bundled photos, with fixed preview ranking.
// This mock never runs analysis or claims to apply the submitted travel filters.
export const previewInfo = {
  scope: "PUBLIC", places: fixture.details.length, photo_enabled: true,
  release_sha256: hash({ mock: "published-place-preview-v1" }),
  regions: [
    { code: "11", name: "서울특별시", places: 1 },
    { code: "26", name: "부산광역시", places: 1 },
    { code: "51", name: "강원특별자치도", places: 1 },
    { code: "44", name: "충청남도", places: 1 },
    { code: "52", name: "전북특별자치도", places: 1 },
  ],
};

export function authenticityMock({ req, url, parts, body, session, send }) {
  if (!url.pathname.startsWith("/v1/authenticity/")) return false;
  const reply = (status, value) => { send(status, value); return true; };
  const path = parts.slice(2);
  const method = req.method;
  session.authenticity ??= { token: null, profiles: new Map(), runs: new Map(), saved: new Map(), photos: new Map() };
  const data = session.authenticity;
  if (method === "GET" && path.join("/") === "info") return reply(200, previewInfo);
  if (method === "POST" && path.join("/") === "sessions") {
    data.token ??= randomUUID();
    return reply(200, { token: data.token, session_id: hash({ mockSession: data.token }), expires_at: new Date(Date.now() + 86400000).toISOString() });
  }
  if (!data.token || req.headers.authorization !== `Bearer ${data.token}`) return reply(401, { detail: "목업 세션이 만료됐어요. 추천 버튼을 다시 눌러 주세요." });
  if (photoMock({ path, method, body, data, scenario: session.scenario, reply })) return true;
  if (method === "DELETE" && path.join("/") === "session") {
    delete session.authenticity;
    return reply(200, { deleted: true });
  }
  if (method === "POST" && ["scenario-profiles", "runs"].includes(path[0]) && path.length === 1) {
    if (typeof body.request_id !== "string" || !body.request_id || body.request_id.length > 160) return reply(422, { detail: "Missing request_id" });
    const key = `${url.pathname}:${body.request_id}`;
    const previous = session.requests.get(key);
    if (previous) return canonical(previous.body) === canonical(body)
      ? reply(200, previous.response) : reply(409, { detail: "다른 입력에 사용한 목업 요청입니다." });
    if (session.requests.size >= 200) return reply(429, { detail: "목업 초기화 후 다시 시도해 주세요." });
    let response;
    if (path[0] === "scenario-profiles") {
      if (body.schema_version !== "scenario-expectation-bridge.v1" || !body.trip_conditions || !body.answers?.q12) return reply(422, { detail: "상황형 답변을 확인해 주세요." });
      if (!["NONE", "CONFIRMED_PHOTO"].includes(body.visual_input_kind)) return reply(422, { detail: "지원하지 않는 목업 사진 입력입니다." });
      if (body.visual_input_kind === "CONFIRMED_PHOTO" && !hasConfirmedPhoto(data, body)) return reply(422, { detail: "목업 사진을 다시 선택하고 분위기를 반영해 주세요." });
      const profile = structuredClone(fixture.profile);
      profile.submission = body;
      profile.created_at = new Date().toISOString();
      profile.intent_sha256 = hash({ mock: true, submission: body });
      profile.profile_id = hash({ token: data.token, intent: profile.intent_sha256 });
      data.profiles.set(profile.profile_id, profile);
      response = profile;
    } else {
      const profile = data.profiles.get(body.profile_id);
      if (!profile) return reply(404, { detail: "목업 프로필을 찾지 못했어요." });
      if (session.scenario === "error") return reply(503, { detail: "목업에서 선택한 서버 오류 상태입니다. 추천 상태를 정상으로 바꾸고 다시 시도해 주세요." });
      const run = structuredClone(fixture.run);
      Object.assign(run, { request_id: body.request_id, profile_id: profile.profile_id, intent_sha256: profile.intent_sha256 });
      if (session.scenario === "empty") Object.assign(run, { state: "EMPTY", result_count: 0, items: [] });
      run.run_sha256 = hash({ mock: true, token: data.token, request: body, scenario: session.scenario });
      const details = run.items.map(item => {
        const detail = structuredClone(fixture.details.find(row => row.item.place_id === item.place_id));
        detail.item = item;
        detail.limitations.unshift("UI 목업: 공개 장소 자료를 사용한 고정 예시이며, 현재 답변·지역·시설 조건으로 계산한 추천이 아닙니다.");
        return detail;
      });
      data.runs.set(run.run_sha256, { run, details });
      response = run;
    }
    session.requests.set(key, { body, response });
    return reply(201, response);
  }
  if (method === "GET" && path[0] === "profiles" && path.length === 2) {
    const profile = data.profiles.get(path[1]);
    return reply(profile ? 200 : 404, profile ?? { detail: "목업 프로필을 찾지 못했어요." });
  }
  if (method === "GET" && path.join("/") === "saved") return reply(200, [...data.saved.values()]);
  if (path[0] === "runs") {
    const record = data.runs.get(path[1]);
    if (!record) return reply(404, { detail: "목업 추천 결과를 찾지 못했어요. 프로필에서 다시 추천해 주세요." });
    if (method === "GET" && path.length === 2) return reply(200, record.run);
    if (path[2] === "places" && path.length >= 4) {
      const detail = record.details.find(row => row.item.place_id === path[3]);
      if (!detail) return reply(404, { detail: "목업 장소를 찾지 못했어요." });
      if (method === "GET" && path.length === 4) return reply(200, detail);
      if (method === "PUT" && path[4] === "saved" && path.length === 5) {
        if (typeof body.saved !== "boolean") return reply(422, { detail: "저장 여부를 확인해 주세요." });
        const key = `${path[1]}:${path[3]}`;
        if (body.saved) data.saved.set(key, { run_sha256: path[1], place_id: path[3], name: detail.item.name_ko, saved_at: new Date().toISOString() });
        else data.saved.delete(key);
        return reply(200, { saved: body.saved });
      }
      if (method === "POST" && path[4] === "feedback" && path.length === 5) return reply(200, { feedback_id: randomUUID() });
    }
  }
  return reply(404, { detail: "지원하지 않는 목업 경로입니다." });
}
