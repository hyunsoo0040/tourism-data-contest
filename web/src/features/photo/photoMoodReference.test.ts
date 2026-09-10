import { afterEach, expect, it, vi } from "vitest";
import { clearConfirmedPhotoReference, CONFIRMED_MOOD_REFERENCE_STORAGE_KEY, readConfirmedMoodReference,
  writeConfirmedMoodReference, writeConfirmedPhotoReference } from "./photoProjection";

afterEach(() => { vi.restoreAllMocks(); clearConfirmedPhotoReference("profile:mood"); sessionStorage.clear(); });

it("keeps only an owned opaque mood receipt and never upgrades a historical trait reference", () => {
  writeConfirmedPhotoReference("profile:mood", "a".repeat(64));
  expect(readConfirmedMoodReference("profile:mood")).toBeNull();
  expect(writeConfirmedMoodReference("profile:mood", "b".repeat(64), "c".repeat(64))).toBe(true);
  expect(readConfirmedMoodReference("profile:mood")?.receipt_id).toBe("c".repeat(64));
  expect(readConfirmedMoodReference("profile:other")).toBeNull();
  expect(Object.keys(JSON.parse(sessionStorage.getItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY)!)).sort())
    .toEqual(["family", "photo_job_id", "preference_profile_id", "receipt_id", "schema_version"]);
  clearConfirmedPhotoReference("profile:mood");
  expect(readConfirmedMoodReference("profile:mood")).toBeNull();
});

it("does not accept browser scores or resurrect a cleared valid storage item", () => {
  writeConfirmedMoodReference("profile:mood", "b".repeat(64), "c".repeat(64));
  const raw = JSON.parse(sessionStorage.getItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY)!);
  sessionStorage.setItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY, JSON.stringify({ ...raw, water: 100 }));
  expect(readConfirmedMoodReference("profile:mood")).toBeNull();
  expect(sessionStorage.getItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY)).toBeNull();
});
