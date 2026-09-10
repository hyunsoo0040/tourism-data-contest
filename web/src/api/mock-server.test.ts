import { expect, it } from "vitest";
// @ts-expect-error The standalone mock is a Node ESM development script.
import { createProfile, createRun, questionnaire } from "../../mock/data.mjs";
import { parseGroundedResults } from "./grounded-recommendation";
import { parseGroundedDetail } from "./grounded-detail";
import { profileSubmissionFingerprint } from "./api";

it("synthetic runs pass production receipt/detail validation and bind the submitted profile", async () => {
  const profile = createProfile({ request_id: "mock-test", trip_conditions: {}, answers: {} });
  expect(profile.scores.every((row: { display_score: number }) => row.display_score === 50)).toBe(true);
  expect(profile.config_hash).toBe(questionnaire.config_hash);
  for (const grounded_input of [null, { region_code: "11", visit_date: "2026-10-01", visit_time: "14:30", required_facilities: ["step_free_entry"] }]) {
    const record = createRun(profile, { request_id: "recommend-test", purpose: "SIGHTSEEING", grounded_input });
    expect(record.created.preference_input_sha256).toBe(await profileSubmissionFingerprint(profile.trip_conditions, profile));
    const results = await parseGroundedResults(record.results);
    expect(results.run.items).toHaveLength(5);
    for (const detail of record.details) {
      await parseGroundedDetail(detail, results, detail.item.place_id);
      expect(detail.item.place_name_ko).toMatch(/^가상/);
      expect(detail.item.evidence[0].quote).toContain("UI 테스트용");
    }
  }
});
