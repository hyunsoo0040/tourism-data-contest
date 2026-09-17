import { randomUUID } from "node:crypto";
import fixture from "../src/features/authenticity/__fixtures__/scenario-photo.json" with { type: "json" };
import { canonical, hash } from "./data.mjs";

// Fixed synthetic observations. Uploaded bytes never enter these records.
export function photoMock({ path, method, body, data, scenario, reply }) {
  if (path[0] !== "photos") return false;
  if (method === "POST" && path.length === 1) {
    if (scenario === "error") return reply(503, { detail: "목업 사진 분석 오류입니다. 추천 상태를 정상으로 바꾼 뒤 다시 시도해 주세요." });
    if (data.photos.size >= 20) return reply(429, { detail: "목업 초기화 후 사진을 다시 선택해 주세요." });
    const photo = structuredClone(fixture.review);
    photo.photo_id = randomUUID();
    photo.created_at = new Date().toISOString();
    for (const batch of photo.batches) {
      batch.provider_id = "synthetic-ui-mock";
      batch.model = "fixed-preview-no-model-call";
      batch.job_id = hash({ mockPhoto: photo.photo_id });
      batch.candidates.forEach(candidate => { candidate.candidate_id = hash({ photo: photo.photo_id, dimension: candidate.observation.dimension }); });
      batch.candidate_set_sha256 = hash(batch.candidates);
    }
    data.photos.set(photo.photo_id, photo);
    return reply(201, photo);
  }
  const photo = data.photos.get(path[1]);
  if (!photo) return reply(404, { detail: "목업 사진을 찾지 못했어요. 사진을 다시 선택해 주세요." });
  if (method === "GET" && path.length === 2) return reply(200, photo);
  if (method === "DELETE" && path.length === 2) {
    data.photos.delete(path[1]);
    return reply(200, { deleted: true, original_retained: false });
  }
  if (method === "POST" && path.length === 3 && path[2] === "confirm") {
    const ids = body.candidate_ids;
    const candidates = photo.batches.flatMap(batch => batch.candidates);
    if (!Array.isArray(ids) || !ids.length || new Set(ids).size !== ids.length ||
      ids.some(id => !candidates.some(candidate => candidate.candidate_id === id))) return reply(422, { detail: "목업 사진의 분위기 항목을 확인해 주세요." });
    const selected = candidates.filter(candidate => ids.includes(candidate.candidate_id));
    photo.selected_candidate_ids = selected.map(candidate => candidate.candidate_id);
    photo.targets = Object.fromEntries(selected.map(candidate => [candidate.observation.dimension, candidate.observation.level]));
    photo.receipt_sha256 = hash({ mock: true, photo: photo.photo_id, targets: photo.targets });
    photo.state = "CONFIRMED";
    return reply(200, photo);
  }
  return reply(404, { detail: "지원하지 않는 목업 사진 경로입니다." });
}

export function hasConfirmedPhoto(data, body) {
  return [...data.photos.values()].some(photo => photo.state === "CONFIRMED" &&
    photo.receipt_sha256 === body.photo_receipt_sha256 && canonical(photo.targets) === canonical(body.visual_targets));
}
