import type { Photo } from "./api";

/** Match the confirmation API: include every observed value, including zero. */
export function photoCandidateIds(photo: Photo | null): string[] {
  return [...new Set(photo?.batches.flatMap(batch => batch.candidates
    .filter(candidate => candidate.observation.state === "OBSERVED" && candidate.observation.level !== null)
    .map(candidate => candidate.candidate_id)) ?? [])];
}
