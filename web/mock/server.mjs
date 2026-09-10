import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { candidateHash, canonical, createProfile, createRun, questionnaire, regions } from "./data.mjs";

export function mockServer() {
  const sessions = new Map();
  return createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }); res.end(JSON.stringify(body)); };
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      if (url.pathname === "/healthz") return send(200, { mode: "synthetic-ui-mock" });
      let token = /(?:^|; )itda_mock_session=([a-f0-9-]+)/.exec(req.headers.cookie ?? "")?.[1];
      if (!sessions.has(token)) {
        token = randomUUID();
        if (sessions.size >= 100) sessions.delete(sessions.keys().next().value);
        sessions.set(token, { scenario: "normal", profiles: new Map(), runs: new Map(), requests: new Map() });
        res.setHeader("Set-Cookie", `itda_mock_session=${token}; Path=/; HttpOnly; SameSite=Strict`);
      }
      const session = sessions.get(token);
      const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
      // No file decoding, image persistence, database, or outbound requests.
      if (parts.some((part) => ["photo-jobs", "operating-information", "tourism-context", "trip-context"].includes(part))) {
        req.resume(); return send(503, { detail: { code: "MOCK_UNAVAILABLE", message: "UI 목업에서는 제공하지 않는 정보입니다." } });
      }
      let body = {};
      if (req.method === "POST") {
        let text = "";
        for await (const chunk of req) {
          text += chunk;
          if (Buffer.byteLength(text) > 64_000) return send(413, { detail: "Mock input too large" });
        }
        body = JSON.parse(text || "{}");
      }
      if (url.pathname === "/v1/mock/scenario") {
        if (req.method === "POST") {
          if (!["normal", "empty", "error"].includes(body.scenario)) return send(400, { detail: "Unknown scenario" });
          session.scenario = body.scenario;
        }
        return send(200, { scenario: session.scenario });
      }
      if (req.method === "POST" && url.pathname === "/v1/mock/reset") {
        sessions.delete(token); return send(200, { reset: true });
      }
      if (req.method === "GET" && url.pathname === "/v1/questionnaires/current") return send(200, questionnaire);
      if (req.method === "GET" && url.pathname === "/v1/recommendation-regions") return send(200, { candidate_sha256: candidateHash, regions });
      if (req.method === "POST" && ["/v1/preference-profiles", "/v1/recommendation-runs"].includes(url.pathname)) {
        if (typeof body.request_id !== "string" || !body.request_id || body.request_id.length > 160) return send(422, { detail: "Missing request_id" });
        const key = `${url.pathname}:${body.request_id}`;
        const existing = session.requests.get(key);
        if (existing) return canonical(existing.body) === canonical(body) ? send(200, existing.response) : send(409, { detail: { code: "IDEMPOTENCY_CONFLICT" } });
        if (session.requests.size >= 200) return send(429, { detail: "목업 초기화 후 다시 시도해 주세요." });
        let response;
        if (parts[1] === "preference-profiles") {
          response = createProfile(body); session.profiles.set(response.profile_id, response);
        } else {
          const failure = (code) => ({ detail: { code, message_ko: "UI 목업에서 선택한 테스트 상태입니다.", preference_profile_id: body.preference_profile_id, release_id: null, request_id: body.request_id } });
          if (session.scenario === "error") return send(503, failure("NO_ACTIVE_SCORED_RELEASE"));
          if (session.scenario === "empty") return send(422, failure("INSUFFICIENT_ELIGIBLE_CANDIDATES"));
          if (body.photo_job_id) return send(503, { detail: { code: "MOCK_UNAVAILABLE" } });
          const profile = session.profiles.get(body.preference_profile_id);
          if (!profile) return send(404, { detail: "Unknown mock profile" });
          const run = createRun(profile, body); session.runs.set(run.created.recommendation_run_id, run); response = run.created;
        }
        session.requests.set(key, { body, response }); return send(201, response);
      }
      if (req.method === "GET" && parts[1] === "preference-profiles" && parts.length === 3) {
        const profile = session.profiles.get(parts[2]); return send(profile ? 200 : 404, profile ?? {});
      }
      if (req.method === "GET" && parts[1] === "recommendation-runs") {
        const record = session.runs.get(parts[2]);
        if (!record) return send(404, { detail: "Unknown mock run" });
        if (parts.length === 3) return send(200, record.results);
        if (parts[3] === "places" && parts.length === 5) {
          const detail = record.details.find((row) => row.item.place_id === parts[4]); return send(detail ? 200 : 404, detail ?? {});
        }
        if (parts[3] === "comparison") {
          const ids = url.searchParams.getAll("place_id");
          const places = ids.map((id) => record.details.find((row) => row.item.place_id === id));
          if (ids.length < 2 || ids.length > 3 || new Set(ids).size !== ids.length || places.some((row) => !row)) return send(422, {});
          return send(200, { schema_version: "itda.grounded-recommendation-comparison.v1", recommendation_run_id: parts[2], release_sha256: candidateHash, places });
        }
      }
      if (req.method === "GET" && parts[1] === "saved-place-references" && parts.length === 4) {
        const item = [...session.runs.values()].flatMap((row) => row.results.run.items).find((row) => row.place_id === parts[3]);
        if (!item || parts[2] !== candidateHash) return send(404, {});
        return send(200, { place_id: item.place_id, place_name_ko: item.place_name_ko, saved_release_sha256: candidateHash, resolved_release_sha256: candidateHash, state: "CURRENT", state_reason: null });
      }
      return send(404, { detail: "Unsupported UI mock route" });
    } catch { return send(400, { detail: "Invalid mock request" }); }
  });
}
