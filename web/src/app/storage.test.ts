import { expect, test } from "vitest";

const RELEASE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    },
    removeItem(key: string) {
      values.delete(key);
    },
  };
}

const PHOTO_RECORD_KEYS = [
  "created_at",
  "job_id",
  "notice_version",
  "profile_id",
  "schema_version",
];

test("photo draft session record reads, writes, and clears only its feature key", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-28T00:00:00Z");
  const storage = memoryStorage({
    "itda.phase5.run.v1": "run-preserved",
  });

  const write = storageModule.writePhotoDraft(
    { jobId: "job-1", profileId: "profile-1", noticeVersion: "photo-consent-notice-v1" },
    storage,
    now,
  );
  expect(write.state).toBe("persisted");
  expect(write.record).toMatchObject({
    schema_version: storageModule.PHOTO_DRAFT_SCHEMA_VERSION,
    job_id: "job-1",
    profile_id: "profile-1",
    notice_version: "photo-consent-notice-v1",
  });

  const read = storageModule.readPhotoDraft("profile-1", storage, now);
  expect(read.state).toBe("valid");
  if (read.state === "valid") {
    expect(Object.keys(read.record).sort()).toEqual(PHOTO_RECORD_KEYS);
  }

  // Unrelated keys survive a clear.
  expect(storageModule.clearPhotoDraft(storage)).toBe(true);
  expect(storage.getItem("itda.phase5.run.v1")).toBe("run-preserved");
  expect(storage.getItem(storageModule.PHOTO_DRAFT_STORAGE_KEY)).toBeNull();
  expect(storageModule.readPhotoDraft("profile-1", storage, now).state).toBe("empty");
});

test("photo draft record stays session-only and under the 2KB cap with exact keys", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-28T00:00:00Z");
  const storage = memoryStorage();

  const write = storageModule.writePhotoDraft(
    { jobId: "job-opaque-1", profileId: "profile-x", noticeVersion: "photo-consent-notice-v1" },
    storage,
    now,
  );
  expect(write.state).toBe("persisted");
  const serialized = storage.getItem(storageModule.PHOTO_DRAFT_STORAGE_KEY) ?? "";
  expect(new TextEncoder().encode(serialized).byteLength).toBeLessThanOrEqual(2048);
  const record = JSON.parse(serialized) as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    expect(PHOTO_RECORD_KEYS).toContain(key);
  }
  // Disallowed content classes are absent from the serialized surface.
  expect(serialized).not.toMatch(/preview|blob|data:image|filename|candidate|provider/);
});

test("photo draft corrupt, expired, profile mismatch, and foreign-schema records clear only the feature key", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-28T00:00:00Z");
  const key = storageModule.PHOTO_DRAFT_STORAGE_KEY;

  // Corrupt JSON clears the feature key.
  const corrupt = memoryStorage({ [key]: "{", "itda.phase5.run.v1": "run-preserved" });
  expect(storageModule.readPhotoDraft("profile-1", corrupt, now)).toMatchObject({
    state: "corrupt",
    record: null,
  });
  expect(corrupt.getItem(key)).toBeNull();
  expect(corrupt.getItem("itda.phase5.run.v1")).toBe("run-preserved");

  // Oversized record is corrupt by definition.
  const oversized = memoryStorage({ [key]: `"${"x".repeat(2049)}"` });
  expect(storageModule.readPhotoDraft("profile-1", oversized, now).state).toBe("corrupt");

  // Expired record clears the feature key.
  const fresh = memoryStorage();
  storageModule.writePhotoDraft(
    { jobId: "job-2", profileId: "profile-1", noticeVersion: "v1" },
    fresh,
    now,
  );
  const retention = storageModule.PHOTO_DRAFT_RETENTION_MS;
  expect(storageModule.readPhotoDraft("profile-1", fresh, now + retention).state).toBe("valid");
  expect(storageModule.readPhotoDraft("profile-1", fresh, now + retention + 1)).toMatchObject({
    state: "expired",
    record: null,
  });
  expect(fresh.getItem(key)).toBeNull();

  // Profile mismatch clears the feature key (foreign profile never resumes).
  const mismatched = memoryStorage();
  storageModule.writePhotoDraft(
    { jobId: "job-3", profileId: "profile-A", noticeVersion: "v1" },
    mismatched,
    now,
  );
  expect(storageModule.readPhotoDraft("profile-B", mismatched, now)).toMatchObject({
    state: "profile_mismatch",
    record: null,
  });
  expect(mismatched.getItem(key)).toBeNull();
});

test("photo draft falls back to memory when storage is unavailable and never claims deletion", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-28T00:00:00Z");
  const denied = {
    getItem() {
      throw new DOMException("blocked", "SecurityError");
    },
    setItem() {
      throw new DOMException("quota", "QuotaExceededError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };

  const write = storageModule.writePhotoDraft(
    { jobId: "job-mem", profileId: "profile-1", noticeVersion: "v1" },
    denied,
    now,
  );
  expect(write.state).toBe("memory-fallback");
  expect(write.record).toMatchObject({ job_id: "job-mem" });

  const read = storageModule.readPhotoDraft("profile-1", denied, now);
  expect(read.state).toBe("unavailable");
  if (read.state === "unavailable") {
    expect(read.record).toMatchObject({ job_id: "job-mem" });
  }
  // Clear in fallback mode touches no server truth — boolean only.
  expect(storageModule.clearPhotoDraft(denied)).toBe(false);

  // Storage resolving to null (SSR/no window) also degrades to memory.
  const readNull = storageModule.readPhotoDraft("profile-1", undefined, now);
  expect(readNull.state).toBe("unavailable");
});

test("save control and storage enforce expiry, size, corrupt cleanup, and unrelated-key isolation", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-11T00:00:00Z");
  const storage = memoryStorage({
    [storageModule.PROFILE_STORAGE_KEY]: "profile-preserved",
    [storageModule.COMPARE_SELECTION_STORAGE_KEY]: "compare-preserved",
    "itda.phase5.run.v1": "run-preserved",
  });

  storageModule.writeSavedPlaceReference(
    { placeId: "place-valid", releaseSha256: RELEASE },
    storage,
    now,
  );
  expect(storageModule.readSavedPlaceReferences(storage, now)).toMatchObject({
    state: "valid",
    references: [{ place_id: "place-valid", release_sha256: RELEASE }],
  });
  expect(storageModule.readSavedPlaceReferences(storage, now + storageModule.STORAGE_RETENTION_MS)).toMatchObject({
    state: "valid",
    references: [{ place_id: "place-valid" }],
  });
  expect(storageModule.readSavedPlaceReferences(storage, now + storageModule.STORAGE_RETENTION_MS + 1)).toMatchObject({
    state: "cleaned",
    references: [],
    reason: "expired",
  });

  storage.setItem(storageModule.SAVED_PLACE_STORAGE_KEY, "{");
  expect(storageModule.readSavedPlaceReferences(storage, now)).toMatchObject({
    state: "cleaned",
    references: [],
    reason: "corrupt",
  });
  expect(storage.getItem(storageModule.SAVED_PLACE_STORAGE_KEY)).toBeNull();
  expect(storage.getItem(storageModule.PROFILE_STORAGE_KEY)).toBe("profile-preserved");
  expect(storage.getItem(storageModule.COMPARE_SELECTION_STORAGE_KEY)).toBe("compare-preserved");
  expect(storage.getItem("itda.phase5.run.v1")).toBe("run-preserved");

  storage.setItem(storageModule.SAVED_PLACE_STORAGE_KEY, `"${"x".repeat(32 * 1024)}"`);
  expect(storageModule.readSavedPlaceReferences(storage, now)).toMatchObject({
    state: "cleaned",
    references: [],
    reason: "corrupt",
  });
});

test("save control and storage use memory fallback for quota and security failures", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-11T00:00:00Z");
  const denied = {
    getItem() {
      throw new DOMException("blocked", "SecurityError");
    },
    setItem() {
      throw new DOMException("quota", "QuotaExceededError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };

  const write = storageModule.writeSavedPlaceReference(
    { placeId: "memory-only-place", releaseSha256: RELEASE },
    denied,
    now,
  );
  expect(write).toMatchObject({
    state: "memory-fallback",
    reference: { place_id: "memory-only-place", release_sha256: RELEASE },
    message: "저장한 장소를 이 브라우저에 기록하지 못했어요. 이 화면에서는 임시로 유지해요.",
  });
  expect(storageModule.readSavedPlaceReferences(denied, now)).toMatchObject({
    state: "unavailable",
    references: [{ place_id: "memory-only-place", release_sha256: RELEASE }],
  });

  expect(storageModule.removeSavedPlaceReference("memory-only-place", RELEASE, denied)).toMatchObject({
    state: "memory-fallback",
    references: [],
  });
});

test("denied compare storage never leaks memory selection across runs", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-11T00:00:00Z");
  const denied = {
    getItem() {
      throw new DOMException("blocked", "SecurityError");
    },
    setItem() {
      throw new DOMException("blocked", "SecurityError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };

  storageModule.writeCompareSelection(
    { runId: "run-a", releaseSha256: RELEASE, placeIds: ["place-a", "place-b"] },
    denied,
    now,
  );
  expect(storageModule.readCompareSelectionForRun("run-b", denied, now)).toMatchObject({
    state: "unavailable",
    selection: null,
  });
  expect(
    storageModule.readCompareSelectionForRun(
      "run-a",
      denied,
      now + storageModule.STORAGE_RETENTION_MS + 1,
    ),
  ).toMatchObject({ state: "unavailable", selection: null });
});

test("readable-empty partial storage preserves saved-place and compare fallbacks", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-11T00:00:00Z");
  const partial = {
    getItem() {
      return null;
    },
    setItem() {
      throw new DOMException("quota", "QuotaExceededError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };

  expect(
    storageModule.writeSavedPlaceReference(
      { placeId: "partial-storage-place", releaseSha256: RELEASE },
      partial,
      now,
    ),
  ).toMatchObject({ state: "memory-fallback" });
  expect(storageModule.readSavedPlaceReferences(partial, now)).toMatchObject({
    state: "unavailable",
    references: [{ place_id: "partial-storage-place", release_sha256: RELEASE }],
  });

  expect(
    storageModule.writeCompareSelection(
      { runId: "partial-storage-run", releaseSha256: RELEASE, placeIds: ["partial-storage-place"] },
      partial,
      now,
    ),
  ).toMatchObject({ state: "memory-fallback" });
  expect(storageModule.readCompareSelectionForRun("partial-storage-run", partial, now)).toMatchObject({
    state: "unavailable",
    selection: { run_id: "partial-storage-run", place_ids: ["partial-storage-place"] },
  });

  expect(
    storageModule.removeSavedPlaceReference("partial-storage-place", RELEASE, partial, now),
  ).toMatchObject({ state: "memory-fallback", references: [] });
  expect(storageModule.readSavedPlaceReferences(partial, now)).toMatchObject({
    state: "unavailable",
    references: [],
  });
  expect(storageModule.clearCompareSelection(partial)).toBe(false);
  expect(storageModule.readCompareSelectionForRun("partial-storage-run", partial, now)).toMatchObject({
    state: "unavailable",
    selection: null,
  });
});

test("memory fallback remains authoritative over stale readable storage and clears immediately", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-08-11T00:00:00Z");
  const staleSaved = JSON.stringify([
    {
      schema_version: "itda.saved-place.v1",
      place_id: "stale-place",
      release_sha256: RELEASE,
      saved_at: new Date(now).toISOString(),
    },
  ]);
  const staleCompare = JSON.stringify({
    schema_version: "itda.compare-selection.v1",
    run_id: "stale-run",
    release_sha256: RELEASE,
    place_ids: ["stale-place"],
    updated_at: new Date(now).toISOString(),
  });
  const storage = {
    getItem(key: string) {
      if (key === storageModule.SAVED_PLACE_STORAGE_KEY) return staleSaved;
      if (key === storageModule.COMPARE_SELECTION_STORAGE_KEY) return staleCompare;
      return null;
    },
    setItem() {
      throw new DOMException("quota", "QuotaExceededError");
    },
    removeItem() {
      throw new DOMException("blocked", "SecurityError");
    },
  };

  storageModule.writeSavedPlaceReference(
    { placeId: "fresh-place", releaseSha256: RELEASE },
    storage,
    now,
  );
  expect(storageModule.readSavedPlaceReferences(storage, now)).toMatchObject({
    state: "unavailable",
    references: [{ place_id: "fresh-place" }],
  });

  storageModule.writeCompareSelection(
    { runId: "fresh-run", releaseSha256: RELEASE, placeIds: ["fresh-place"] },
    storage,
    now,
  );
  expect(storageModule.readCompareSelectionForRun("fresh-run", storage, now)).toMatchObject({
    state: "unavailable",
    selection: { run_id: "fresh-run" },
  });
  expect(storageModule.clearCompareSelection(storage)).toBe(false);
  expect(storageModule.readCompareSelectionForRun("fresh-run", storage, now)).toMatchObject({
    state: "unavailable",
    selection: null,
  });
});

test("profile reference records accept both valid version combinations and reject mixed ones", async () => {
  const storageModule = await import("./storage");
  const now = 1_700_000_000_000;
  const updatedAt = new Date(now).toISOString();
  const write = (payload: Record<string, unknown>) => {
    const storage = memoryStorage({
      [storageModule.PROFILE_STORAGE_KEY]: JSON.stringify(payload),
    });
    return storageModule.readProfileReference(storage, now).state;
  };
  const base = {
    schema_version: "phase1-profile-reference-v1",
    updated_at: updatedAt,
    profile_id: "profile-ref-1",
  };

  expect(
    write({
      ...base,
      profile_schema_version: "preference-profile-v2",
      questionnaire_version: "questionnaire-v2",
      scoring_version: "choice-bp-v2",
      description_template_version: "current-trip-expectation-v1",
    }),
  ).toBe("valid");
  expect(
    write({
      ...base,
      profile_schema_version: "preference-profile-v1",
      questionnaire_version: "questionnaire-v1",
      scoring_version: "integer-bp-v1",
      description_template_version: "current-trip-expectation-v1",
    }),
  ).toBe("valid");

  // Mixed combinations are version-coupling violations, not recoverable.
  const mixed: Array<Record<string, unknown>> = [
    // legacy profile carrying the current scoring version
    {
      ...base,
      profile_schema_version: "preference-profile-v1",
      questionnaire_version: "questionnaire-v1",
      scoring_version: "choice-bp-v2",
      description_template_version: "current-trip-expectation-v1",
    },
    // current profile pinned to the legacy scoring version
    {
      ...base,
      profile_schema_version: "preference-profile-v2",
      questionnaire_version: "questionnaire-v2",
      scoring_version: "integer-bp-v1",
      description_template_version: "current-trip-expectation-v1",
    },
    // current profile declaring the legacy questionnaire generation
    {
      ...base,
      profile_schema_version: "preference-profile-v2",
      questionnaire_version: "questionnaire-v1",
      scoring_version: "choice-bp-v2",
      description_template_version: "current-trip-expectation-v1",
    },
  ];
  for (const payload of mixed) {
    expect(write(payload), JSON.stringify(payload)).toBe("incompatible");
  }

  // A real legacy localStorage record (v1 generation fields) stays valid.
  expect(
    write({
      schema_version: "phase1-profile-reference-v1",
      profile_schema_version: "preference-profile-v1",
      questionnaire_version: "questionnaire-v1",
      scoring_version: "integer-bp-v1",
      description_template_version: "current-trip-expectation-v1",
      updated_at: new Date(now - 1_000).toISOString(),
      profile_id: "legacy-stored-profile",
    }),
  ).toBe("valid");
});
