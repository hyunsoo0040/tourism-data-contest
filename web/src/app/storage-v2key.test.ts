import { expect, test } from "vitest";

/**
 * 07-02 v2-only draft storage: the draft key rotates to a v2 namespace so a
 * legacy questionnaire-v1 draft is discarded (never reinterpreted as v2),
 * while the stored profile-reference key stays readable per the 07-01
 * legacy-read contract and photo storage stays metadata-only.
 */
test("draft storage uses a v2 key and discards the legacy v1 draft key", async () => {
  const storageModule = await import("./storage");
  expect(storageModule.DRAFT_STORAGE_KEY).toBe("itda.phase2.draft.v2");
  expect(storageModule.LEGACY_V1_DRAFT_STORAGE_KEY).toBe("itda.phase1.draft.v1");
  expect(storageModule.DRAFT_STORAGE_KEY).not.toBe(storageModule.LEGACY_V1_DRAFT_STORAGE_KEY);
});

test("reading the draft removes a legacy v1 draft instead of adopting it", async () => {
  const storageModule = await import("./storage");
  const legacyDraft = JSON.stringify({
    schema_version: "phase1-draft-v1",
    questionnaire_version: "questionnaire-v1",
    updated_at: "2026-07-01T00:00:00Z",
    current_route: "/quiz",
    current_question: 5,
    trip_conditions: {},
    answers: { q1: 4 },
  });
  const values = new Map<string, string>([
    [storageModule.LEGACY_V1_DRAFT_STORAGE_KEY, legacyDraft],
  ]);
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };

  const read = storageModule.readDraft(storage);
  expect(read.state).toBe("empty");
  expect(values.has(storageModule.LEGACY_V1_DRAFT_STORAGE_KEY)).toBe(false);
  expect(values.has(storageModule.DRAFT_STORAGE_KEY)).toBe(false);
});

test("v2 drafts persist under the v2 key and legacy profile references stay readable", async () => {
  const storageModule = await import("./storage");
  const now = Date.parse("2026-09-01T00:00:00Z");
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };

  const draft = storageModule.writeDraft(
    {
      current_route: "/quiz",
      current_question: 3,
      trip_conditions: {},
      answers: { q1: 1, q2: 2 },
    },
    storage,
    now,
  );
  expect(draft.state).toBe("saved");
  expect(values.has(storageModule.DRAFT_STORAGE_KEY)).toBe(true);
  expect(storageModule.readDraft(storage, now)).toMatchObject({ state: "recovered" });

  // Stored v1 profile references remain readable (legacy-read contract):
  // seed the exact legacy record shape and read it back through the
  // version-coupled validator.
  values.set(
    storageModule.PROFILE_STORAGE_KEY,
    JSON.stringify({
      schema_version: "phase1-profile-reference-v1",
      profile_schema_version: "preference-profile-v1",
      questionnaire_version: "questionnaire-v1",
      scoring_version: "integer-bp-v1",
      description_template_version: "current-trip-expectation-v1",
      updated_at: new Date(now).toISOString(),
      profile_id: "legacy-stored-profile",
    }),
  );
  expect(storageModule.readProfileReference(storage, now)).toMatchObject({
    state: "valid",
    profile: { profile_id: "legacy-stored-profile", questionnaire_version: "questionnaire-v1" },
  });
});
