import { describe, expect, it } from "vitest";
import type { Photo } from "./api";
import fixture from "./__fixtures__/scenario-photo.json";
import { photoCandidateIds } from "./photoCandidates";

describe("automatic photo atmosphere", () => {
  it("includes all images and zero values, excludes unknowns, and deduplicates references", () => {
    const photo = structuredClone(fixture.review) as Photo;
    const batch = photo.batches[0]!;
    batch.candidates[0]!.observation.level = 0;
    batch.candidates[1]!.observation = { ...batch.candidates[1]!.observation, state: "UNKNOWN", level: null, certainty: "LOW" };
    const extra = structuredClone(batch.candidates[0]!);
    extra.candidate_id = "f".repeat(64);
    photo.batches.push({ ...batch, candidates: [extra, batch.candidates[0]!] });
    expect(photoCandidateIds(photo)).toEqual([
      ...batch.candidates.filter(candidate => candidate.observation.state === "OBSERVED").map(candidate => candidate.candidate_id),
      extra.candidate_id,
    ]);
  });

  it("does not carry forward a historical manual subset when reconfirming", () => {
    const photo = fixture.confirmed as Photo;
    expect(photoCandidateIds(photo)).toHaveLength(8);
    expect(photo.selected_candidate_ids).toHaveLength(1);
  });

  it("returns no references for absent photos or unavailable observations", () => {
    expect(photoCandidateIds(null)).toEqual([]);
    const photo = structuredClone(fixture.review) as Photo;
    photo.batches.forEach(batch => batch.candidates.forEach(candidate => {
      candidate.observation = { ...candidate.observation, state: "UNKNOWN", level: null, certainty: "LOW" };
    }));
    expect(photoCandidateIds(photo)).toEqual([]);
  });
});
