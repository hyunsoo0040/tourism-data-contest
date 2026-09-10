import { createHash, randomUUID } from "node:crypto";
import questionnaireData from "../../contracts/questionnaire-v2.json" with { type: "json" };
import fixture from "../fixtures/grounded-synthetic-v5.json" with { type: "json" };

export const questionnaire = questionnaireData;
if (fixture.provenance !== "SYNTHETIC_UNIT_CASE_NOT_FIELD_DATA") throw new Error("Mock requires synthetic fixtures");
export const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : value !== null && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
export const hash = (value) => createHash("sha256").update(canonical(value)).digest("hex");
const without = (value, keys) => Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
// A small synthetic catalogue exercises the region selector; this is not a national data inventory.
export const regions = [{ region_code: "11", region_name: "서울특별시", place_count: 5 },
  { region_code: "26", region_name: "부산광역시", place_count: 5 },
  { region_code: "50", region_name: "제주특별자치도", place_count: 5 }];
export const candidateHash = fixture.results.run.authority.candidate_sha256;

export function createProfile(body) {
  if (!body || typeof body.request_id !== "string" || body.request_id.length > 160 || !body.trip_conditions || !body.answers) throw new Error("Invalid profile input");
  return {
    schema_version: "preference-profile-v2", profile_id: `mock-profile:${randomUUID()}`,
    request_id: body.request_id, created_at: new Date().toISOString(),
    ...Object.fromEntries(["questionnaire_version", "scoring_version", "config_hash", "description_template_version"].map((key) => [key, questionnaire[key]])),
    trip_conditions: body.trip_conditions, answers: body.answers,
    is_current_trip_expectation: true,
    description_ko: "UI 목업 프로필입니다. 세 축의 50점은 화면 확인용 고정값이며, 응답을 분석한 결과가 아닙니다.",
    scores: questionnaire.axis_tie_break.map((axis) => ({ axis, basis_points: 5000, display_score: 50 })),
  };
}

function markSynthetic(value) {
  if (!value || typeof value !== "object") return;
  if (value.evidence_id) {
    value.excerpt = value.quote = "가상 장소의 UI 테스트용 설명입니다. 실제 관광 자료가 아닙니다.";
    value.receipt.reason = "SYNTHETIC_UI_MOCK_NO_PROVIDER_CALL";
    if (value.place_match) value.place_match.evidence = ["UI 목업에서 만든 가상 일치 정보"];
  }
  for (const child of Object.values(value)) markSynthetic(child);
}

export function createRun(profile, body) {
  const copy = structuredClone(fixture);
  markSynthetic(copy);
  const { results } = copy;
  const run = results.run;
  const preferenceHash = hash(without(profile, ["schema_version", "profile_id", "request_id", "created_at", "description_ko", "is_current_trip_expectation", "scores"]));
  results.preference_profile_id = profile.profile_id;
  run.preference.profile_id = profile.profile_id;
  run.preference.input_sha256 = preferenceHash;
  run.preference.purpose = body.purpose ?? "SIGHTSEEING";
  run.preference.trip_input = body.grounded_input ?? { visit_date: null, visit_time: null, required_facilities: [] };
  for (const assessment of copy.assessments) assessment.bundle_sha256 = hash(without(assessment, ["bundle_sha256"]));
  for (const binding of run.candidate_bindings) binding.assessment_bundle_sha256 = copy.assessments.find((row) => row.place_id === binding.place_id).bundle_sha256;
  const names = ["가상 느린 정원", "가상 빛의 거리", "가상 이야기 공방", "가상 바람 산책길", "가상 작은 전시관"];
  run.items.forEach((item, index) => {
    item.place_name_ko = names[index];
    item.assessment_bundle_sha256 = run.candidate_bindings.find((row) => row.place_id === item.place_id).assessment_bundle_sha256;
    const region = regions.find((row) => row.region_code === body.grounded_input?.region_code) ?? regions[index % regions.length];
    item.region_code = `${region.region_code}000`;
    item.region_name = region.region_name;
    item.address_ko = `${region.region_name} · UI 테스트용 가상 주소`;
  });
  run.authority.candidate_assessment_sha256 = hash(run.candidate_bindings);
  run.input_digest = hash({ preference: run.preference, authority: run.authority });
  run.created_at = new Date().toISOString();
  run.canonical_sha256 = hash(without(run, ["run_id", "created_at", "canonical_sha256"]));
  run.run_id = `recommendation-run:${run.canonical_sha256.slice(0, 32)}`;
  copy.details.forEach((detail) => {
    detail.recommendation_run_id = run.run_id;
    detail.item = run.items.find((item) => item.place_id === detail.item.place_id);
    detail.assessment = copy.assessments.find((row) => row.place_id === detail.item.place_id);
  });
  return { results, details: copy.details, created: {
    schema_version: "itda.recommendation-run-created.v1", request_id: body.request_id,
    preference_profile_id: profile.profile_id, recommendation_run_id: run.run_id, preference_input_sha256: preferenceHash,
  } };
}
