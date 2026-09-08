import {
  COMPARE_SELECTION_SCHEMA_VERSION,
  DESCRIPTION_TEMPLATE_VERSION,
  DRAFT_SCHEMA_VERSION,
  PHOTO_DRAFT_SCHEMA_VERSION,
  PROFILE_REFERENCE_SCHEMA_VERSION,
  PROFILE_SCHEMA_VERSION,
  QUESTIONNAIRE_VERSION,
  SCORING_VERSION,
  compareSelectionRecordSchema,
  draftRecordSchema,
  photoDraftRecordSchema,
  profileReferenceRecordSchema,
  type CompareSelectionRecord,
  type DraftContents,
  type DraftRecord,
  type PhotoDraftRecord,
  type ProfileReferenceRecord,
} from "./schemas";

/**
 * Draft storage is questionnaire-v2-only (07-02): the draft key moved to a
 * v2 namespace so a legacy questionnaire-v1 draft is discarded rather than
 * reinterpreted. Stored v1 profile references remain readable via
 * PROFILE_STORAGE_KEY (07-01 legacy-read contract); only drafts rotate.
 */
export const LEGACY_V1_DRAFT_STORAGE_KEY = "itda.phase1.draft.v1" as const;
export const DRAFT_STORAGE_KEY = "itda.phase2.draft.v2" as const;
export const PROFILE_STORAGE_KEY = "itda.phase1.profile.v1" as const;
export const PENDING_PROFILE_SUBMISSION_KEY = "itda.phase1.pending-profile.v1" as const;
export const COMPARE_SELECTION_STORAGE_KEY = "itda.phase5.compare-selection.v1" as const;
export const SAVED_PLACE_STORAGE_KEY = "itda.phase5.saved-places.v1" as const;
export const PHOTO_DRAFT_STORAGE_KEY = "itda.phase6.photo-draft.v1" as const;
export { PHOTO_DRAFT_SCHEMA_VERSION } from "./schemas";
export const STORAGE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_STORAGE_RECORD_BYTES = 32 * 1024;
export const SAVED_PLACE_SCHEMA_VERSION = "phase5-saved-place-v1" as const;
export const MAX_SAVED_PLACE_REFERENCES = 100;
export const PHOTO_DRAFT_RETENTION_MS = 24 * 60 * 60 * 1000;
export const MAX_PHOTO_DRAFT_RECORD_BYTES = 2048;

export const STORAGE_MESSAGES = {
  recovered: "이어 작성할 여행 조건이 있어요.",
  invalid: "저장된 진행 내용을 불러오지 못해 이 단계부터 다시 시작해요.",
  unavailable:
    "이 브라우저에서는 진행 내용을 저장할 수 없어요. 새로고침하면 답변이 사라질 수 있어요.",
  reset: "저장된 여행 내용을 지웠어요.",
} as const;

export const COMPARE_STORAGE_MESSAGES = {
  corrupt: "비교 선택 정보를 읽지 못해 정리했어요.",
  crossRun: "다른 추천 실행의 비교 선택을 정리했어요.",
  unavailable: "비교 선택을 이 브라우저에 저장하지 못했어요.",
} as const;

export const SAVED_PLACE_STORAGE_MESSAGES = {
  cleanup:
    "일부 저장 정보를 읽지 못했어요. 읽을 수 없는 저장 항목만 정리했어요.",
  unavailable:
    "저장한 장소를 이 브라우저에 기록하지 못했어요. 이 화면에서는 임시로 유지해요.",
  limit: "저장한 장소가 너무 많아 새 항목을 추가하지 못했어요.",
} as const;

export type StoragePort = Pick<Storage, "getItem" | "setItem" | "removeItem">;

export type PhotoDraftReadResult =
  | { state: "empty"; record: null }
  | { state: "valid"; record: PhotoDraftRecord }
  | { state: "corrupt" | "expired" | "profile_mismatch"; record: null }
  | { state: "unavailable"; record: PhotoDraftRecord | null };

export type PhotoDraftWriteResult =
  | { state: "persisted"; record: PhotoDraftRecord }
  | { state: "memory-fallback"; record: PhotoDraftRecord };

export type DraftReadResult =
  | { state: "empty"; draft: null }
  | { state: "recovered"; draft: DraftRecord }
  | { state: "corrupt" | "expired"; draft: null; message: typeof STORAGE_MESSAGES.invalid }
  | {
      state: "unavailable";
      draft: DraftRecord | null;
      message: typeof STORAGE_MESSAGES.unavailable;
    };

export type DraftWriteResult =
  | { state: "saved"; draft: DraftRecord }
  | {
      state: "unavailable";
      draft: DraftRecord;
      message: typeof STORAGE_MESSAGES.unavailable;
    };

export type ProfileReadResult =
  | { state: "empty"; profile: null }
  | { state: "valid"; profile: ProfileReferenceRecord }
  | {
      state: "corrupt" | "incompatible" | "expired";
      profile: null;
      message: typeof STORAGE_MESSAGES.invalid;
    }
  | {
      state: "unavailable";
      profile: ProfileReferenceRecord | null;
      message: typeof STORAGE_MESSAGES.unavailable;
    };

export type ProfileWriteResult =
  | { state: "persisted"; profile: ProfileReferenceRecord }
  | {
      state: "memory-fallback";
      profile: ProfileReferenceRecord;
      message: typeof STORAGE_MESSAGES.unavailable;
    };

export type PendingProfileSubmission = {
  schema_version: "phase1-pending-profile-v1";
  request_id: string;
  payload_sha256: string;
  updated_at: string;
};

export type CompareSelectionReadResult =
  | { state: "empty"; selection: null }
  | { state: "valid"; selection: CompareSelectionRecord }
  | {
      state: "cleared" | "corrupt" | "expired";
      selection: null;
      message: typeof COMPARE_STORAGE_MESSAGES.corrupt | typeof COMPARE_STORAGE_MESSAGES.crossRun;
    }
  | {
      state: "unavailable";
      selection: CompareSelectionRecord | null;
      message: typeof COMPARE_STORAGE_MESSAGES.unavailable;
    };

export type CompareSelectionWriteResult =
  | { state: "persisted"; selection: CompareSelectionRecord }
  | {
      state: "memory-fallback";
      selection: CompareSelectionRecord;
      message: typeof COMPARE_STORAGE_MESSAGES.unavailable;
    };

export type SavedPlaceReference = {
  schema_version: typeof SAVED_PLACE_SCHEMA_VERSION;
  place_id: string;
  release_sha256: string;
  saved_at: string;
};

export type SavedPlaceReadResult =
  | { state: "empty"; references: [] }
  | { state: "valid"; references: SavedPlaceReference[] }
  | {
      state: "cleaned";
      references: SavedPlaceReference[];
      reason: "corrupt" | "expired";
      message?: typeof SAVED_PLACE_STORAGE_MESSAGES.cleanup;
    }
  | {
      state: "unavailable";
      references: SavedPlaceReference[];
      message: typeof SAVED_PLACE_STORAGE_MESSAGES.unavailable;
    };

export type SavedPlaceWriteResult =
  | {
      state: "persisted";
      reference: SavedPlaceReference;
      references: SavedPlaceReference[];
    }
  | {
      state: "memory-fallback";
      reference: SavedPlaceReference;
      references: SavedPlaceReference[];
      message: typeof SAVED_PLACE_STORAGE_MESSAGES.unavailable;
    }
  | {
      state: "rejected";
      reference: SavedPlaceReference;
      references: SavedPlaceReference[];
      message: typeof SAVED_PLACE_STORAGE_MESSAGES.limit;
    };

export type SavedPlaceRemoveResult =
  | { state: "persisted"; references: SavedPlaceReference[] }
  | {
      state: "memory-fallback";
      references: SavedPlaceReference[];
      message: typeof SAVED_PLACE_STORAGE_MESSAGES.unavailable;
    };

let inMemoryDraft: DraftRecord | null = null;
let inMemoryProfileReference: ProfileReferenceRecord | null = null;
let inMemoryPendingProfileSubmission: PendingProfileSubmission | null = null;
let inMemoryCompareSelection: CompareSelectionRecord | null = null;
let inMemorySavedPlaceReferences: SavedPlaceReference[] = [];
let inMemoryCompareSelectionFallback = false;
let inMemorySavedPlaceFallback = false;
let inMemoryPhotoDraft: PhotoDraftRecord | null = null;
let inMemoryPhotoDraftFallback = false;

function resolveStorage(storage?: StoragePort): StoragePort | null {
  if (storage !== undefined) return storage;
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * The photo draft is session-only: its default mount is sessionStorage, never
 * localStorage. Injection keeps tests and callers explicit; SSR resolves to
 * null and the caller degrades to the in-memory copy.
 */
function resolveSessionStorage(storage?: StoragePort): StoragePort | null {
  if (storage !== undefined) return storage;
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function isExpired(updatedAt: string, now: number): boolean {
  return now - Date.parse(updatedAt) > STORAGE_RETENTION_MS;
}

function removeAffectedKey(storage: StoragePort, key: string): boolean {
  try {
    storage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function parseStoredJson(raw: string): unknown {
  if (new TextEncoder().encode(raw).byteLength > MAX_STORAGE_RECORD_BYTES) {
    throw new Error("storage record exceeds the bounded payload size");
  }
  return JSON.parse(raw) as unknown;
}

function isPendingProfileSubmission(value: unknown): value is PendingProfileSubmission {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    JSON.stringify(keys) ===
      JSON.stringify(["payload_sha256", "request_id", "schema_version", "updated_at"]) &&
    record.schema_version === "phase1-pending-profile-v1" &&
    typeof record.request_id === "string" &&
    record.request_id.trim().length > 0 &&
    record.request_id.length <= 160 &&
    typeof record.payload_sha256 === "string" &&
    /^[0-9a-f]{64}$/.test(record.payload_sha256) &&
    typeof record.updated_at === "string" &&
    Number.isFinite(Date.parse(record.updated_at))
  );
}

function isSavedPlaceReference(value: unknown): value is SavedPlaceReference {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    JSON.stringify(Object.keys(record).sort()) ===
      JSON.stringify(["place_id", "release_sha256", "saved_at", "schema_version"]) &&
    record.schema_version === SAVED_PLACE_SCHEMA_VERSION &&
    typeof record.place_id === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(record.place_id) &&
    typeof record.release_sha256 === "string" &&
    /^[0-9a-f]{64}$/.test(record.release_sha256) &&
    typeof record.saved_at === "string" &&
    Number.isFinite(Date.parse(record.saved_at))
  );
}

function savedPlaceReferenceKey(reference: Pick<SavedPlaceReference, "place_id" | "release_sha256">) {
  return `${reference.release_sha256}:${reference.place_id}`;
}

function persistSavedPlaceReferences(
  references: SavedPlaceReference[],
  storage: StoragePort | null,
): "persisted" | "memory-fallback" {
  inMemorySavedPlaceReferences = references;
  if (storage === null) {
    inMemorySavedPlaceFallback = true;
    return "memory-fallback";
  }
  try {
    if (references.length === 0) {
      storage.removeItem(SAVED_PLACE_STORAGE_KEY);
    } else {
      const serialized = JSON.stringify(references);
      if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
        inMemorySavedPlaceFallback = true;
        return "memory-fallback";
      }
      storage.setItem(SAVED_PLACE_STORAGE_KEY, serialized);
    }
    inMemorySavedPlaceFallback = false;
    return "persisted";
  } catch {
    inMemorySavedPlaceFallback = true;
    return "memory-fallback";
  }
}

export function readSavedPlaceReferences(
  storage?: StoragePort,
  now = Date.now(),
): SavedPlaceReadResult {
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return {
      state: "unavailable",
      references: [...inMemorySavedPlaceReferences],
      message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
    };
  }

  if (inMemorySavedPlaceFallback) {
    const references = inMemorySavedPlaceReferences.filter(
      (reference) => isSavedPlaceReference(reference) && !isExpired(reference.saved_at, now),
    );
    inMemorySavedPlaceReferences = references;
    return {
      state: "unavailable",
      references: [...references],
      message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
    };
  }

  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(SAVED_PLACE_STORAGE_KEY);
  } catch {
    return {
      state: "unavailable",
      references: [...inMemorySavedPlaceReferences],
      message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
    };
  }
  if (raw === null) {
    if (inMemorySavedPlaceFallback) {
      const hadInMemoryReferences = inMemorySavedPlaceReferences.length > 0;
      const fallbackReferences = inMemorySavedPlaceReferences.filter(
        (reference) => isSavedPlaceReference(reference) && !isExpired(reference.saved_at, now),
      );
      inMemorySavedPlaceReferences = fallbackReferences;
      if (fallbackReferences.length > 0) {
        return {
          state: "unavailable",
          references: [...fallbackReferences],
          message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
        };
      }
      if (hadInMemoryReferences) {
        inMemorySavedPlaceFallback = false;
      } else {
        return {
          state: "unavailable",
          references: [],
          message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
        };
      }
    }
    inMemorySavedPlaceReferences = [];
    return { state: "empty", references: [] };
  }

  let parsed: unknown;
  try {
    parsed = parseStoredJson(raw);
  } catch {
    inMemorySavedPlaceReferences = [];
    if (!removeAffectedKey(resolvedStorage, SAVED_PLACE_STORAGE_KEY)) {
      return {
        state: "unavailable",
        references: [],
        message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
      };
    }
    return {
      state: "cleaned",
      references: [],
      reason: "corrupt",
      message: SAVED_PLACE_STORAGE_MESSAGES.cleanup,
    };
  }

  if (!Array.isArray(parsed) || parsed.length > MAX_SAVED_PLACE_REFERENCES) {
    inMemorySavedPlaceReferences = [];
    if (!removeAffectedKey(resolvedStorage, SAVED_PLACE_STORAGE_KEY)) {
      return {
        state: "unavailable",
        references: [],
        message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
      };
    }
    return {
      state: "cleaned",
      references: [],
      reason: "corrupt",
      message: SAVED_PLACE_STORAGE_MESSAGES.cleanup,
    };
  }

  const valid = parsed.filter(isSavedPlaceReference);
  const unique = valid.filter(
    (reference, index) =>
      valid.findIndex((candidate) => savedPlaceReferenceKey(candidate) === savedPlaceReferenceKey(reference)) === index,
  );
  const references = unique.filter((reference) => !isExpired(reference.saved_at, now));
  inMemorySavedPlaceReferences = references;
  inMemorySavedPlaceFallback = false;
  const hadCorrupt = valid.length !== parsed.length || unique.length !== valid.length;
  const hadExpired = references.length !== unique.length;
  if (!hadCorrupt && !hadExpired) {
    return references.length === 0
      ? { state: "empty", references: [] }
      : { state: "valid", references };
  }

  if (persistSavedPlaceReferences(references, resolvedStorage) === "memory-fallback") {
    return {
      state: "unavailable",
      references,
      message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
    };
  }
  return {
    state: "cleaned",
    references,
    reason: hadCorrupt ? "corrupt" : "expired",
    ...(hadCorrupt ? { message: SAVED_PLACE_STORAGE_MESSAGES.cleanup } : {}),
  };
}

export function writeSavedPlaceReference(
  input: { placeId: string; releaseSha256: string },
  storage?: StoragePort,
  now = Date.now(),
): SavedPlaceWriteResult {
  const reference: SavedPlaceReference = {
    schema_version: SAVED_PLACE_SCHEMA_VERSION,
    place_id: input.placeId,
    release_sha256: input.releaseSha256,
    saved_at: new Date(now).toISOString(),
  };
  if (!isSavedPlaceReference(reference)) throw new Error("saved place reference is invalid");

  const read = readSavedPlaceReferences(storage, now);
  const existing = read.references.find(
    (candidate) => savedPlaceReferenceKey(candidate) === savedPlaceReferenceKey(reference),
  );
  const storedReference = existing ?? reference;
  const references = existing === undefined ? [...read.references, reference] : [...read.references];
  if (references.length > MAX_SAVED_PLACE_REFERENCES) {
    return {
      state: "rejected",
      reference: storedReference,
      references: read.references,
      message: SAVED_PLACE_STORAGE_MESSAGES.limit,
    };
  }
  const serialized = JSON.stringify(references);
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
    return {
      state: "rejected",
      reference: storedReference,
      references: read.references,
      message: SAVED_PLACE_STORAGE_MESSAGES.limit,
    };
  }

  const persisted = persistSavedPlaceReferences(references, resolveStorage(storage));
  return persisted === "persisted"
    ? { state: "persisted", reference: storedReference, references }
    : {
        state: "memory-fallback",
        reference: storedReference,
        references,
        message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
      };
}

export function removeSavedPlaceReference(
  placeId: string,
  releaseSha256: string,
  storage?: StoragePort,
  now = Date.now(),
): SavedPlaceRemoveResult {
  const read = readSavedPlaceReferences(storage, now);
  const references = read.references.filter(
    (reference) =>
      reference.place_id !== placeId || reference.release_sha256 !== releaseSha256,
  );
  const persisted = persistSavedPlaceReferences(references, resolveStorage(storage));
  return persisted === "persisted"
    ? { state: "persisted", references }
    : {
        state: "memory-fallback",
        references,
        message: SAVED_PLACE_STORAGE_MESSAGES.unavailable,
      };
}

export function hasSavedPlaceReference(
  references: readonly SavedPlaceReference[],
  placeId: string,
  releaseSha256: string,
) {
  return references.some(
    (reference) =>
      reference.place_id === placeId && reference.release_sha256 === releaseSha256,
  );
}

export function createEmptyDraft(): DraftContents {
  return {
    current_route: "/start",
    current_question: 1,
    trip_conditions: {},
    answers: {},
  };
}

export function readDraft(storage?: StoragePort, now = Date.now()): DraftReadResult {
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return {
      state: "unavailable",
      draft: inMemoryDraft,
      message: STORAGE_MESSAGES.unavailable,
    };
  }

  // Legacy v1 drafts never carry questionnaire-v2 state; discard the legacy
  // key without interpreting it, then read the v2 draft normally.
  try {
    if (resolvedStorage.getItem(LEGACY_V1_DRAFT_STORAGE_KEY) !== null) {
      resolvedStorage.removeItem(LEGACY_V1_DRAFT_STORAGE_KEY);
    }
  } catch {
    // A blocked legacy key must not block the v2 draft read.
  }

  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(DRAFT_STORAGE_KEY);
  } catch {
    return {
      state: "unavailable",
      draft: inMemoryDraft,
      message: STORAGE_MESSAGES.unavailable,
    };
  }

  if (raw === null) {
    return { state: "empty", draft: null };
  }

  try {
    const draft = draftRecordSchema.parse(parseStoredJson(raw));
    if (isExpired(draft.updated_at, now)) {
      inMemoryDraft = null;
      if (!removeAffectedKey(resolvedStorage, DRAFT_STORAGE_KEY)) {
        return { state: "unavailable", draft: null, message: STORAGE_MESSAGES.unavailable };
      }
      return { state: "expired", draft: null, message: STORAGE_MESSAGES.invalid };
    }
    inMemoryDraft = draft;
    return { state: "recovered", draft };
  } catch {
    inMemoryDraft = null;
    if (!removeAffectedKey(resolvedStorage, DRAFT_STORAGE_KEY)) {
      return { state: "unavailable", draft: null, message: STORAGE_MESSAGES.unavailable };
    }
    return { state: "corrupt", draft: null, message: STORAGE_MESSAGES.invalid };
  }
}

export function writeDraft(
  contents: DraftContents,
  storage?: StoragePort,
  now = Date.now(),
): DraftWriteResult {
  const draft = draftRecordSchema.parse({
    ...contents,
    schema_version: DRAFT_SCHEMA_VERSION,
    questionnaire_version: QUESTIONNAIRE_VERSION,
    updated_at: new Date(now).toISOString(),
  });
  const serialized = JSON.stringify(draft);
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
    throw new Error("draft exceeds the bounded payload size");
  }

  inMemoryDraft = draft;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return { state: "unavailable", draft, message: STORAGE_MESSAGES.unavailable };
  }
  try {
    resolvedStorage.setItem(DRAFT_STORAGE_KEY, serialized);
    return { state: "saved", draft };
  } catch {
    return { state: "unavailable", draft, message: STORAGE_MESSAGES.unavailable };
  }
}

export function readProfileReference(
  storage?: StoragePort,
  now = Date.now(),
): ProfileReadResult {
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return {
      state: "unavailable",
      profile: inMemoryProfileReference,
      message: STORAGE_MESSAGES.unavailable,
    };
  }

  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(PROFILE_STORAGE_KEY);
  } catch {
    return {
      state: "unavailable",
      profile: inMemoryProfileReference,
      message: STORAGE_MESSAGES.unavailable,
    };
  }
  if (raw === null) {
    if (inMemoryProfileReference !== null && !isExpired(inMemoryProfileReference.updated_at, now)) {
      return {
        state: "unavailable",
        profile: inMemoryProfileReference,
        message: STORAGE_MESSAGES.unavailable,
      };
    }
    inMemoryProfileReference = null;
    return { state: "empty", profile: null };
  }

  let parsed: unknown;
  try {
    parsed = parseStoredJson(raw);
  } catch {
    inMemoryProfileReference = null;
    if (!removeAffectedKey(resolvedStorage, PROFILE_STORAGE_KEY)) {
      return { state: "unavailable", profile: null, message: STORAGE_MESSAGES.unavailable };
    }
    return { state: "corrupt", profile: null, message: STORAGE_MESSAGES.invalid };
  }

  const parsedProfile = profileReferenceRecordSchema.safeParse(parsed);
  if (!parsedProfile.success) {
    inMemoryProfileReference = null;
    if (!removeAffectedKey(resolvedStorage, PROFILE_STORAGE_KEY)) {
      return { state: "unavailable", profile: null, message: STORAGE_MESSAGES.unavailable };
    }
    return { state: "incompatible", profile: null, message: STORAGE_MESSAGES.invalid };
  }

  const profile = parsedProfile.data;
  if (
    inMemoryProfileReference !== null &&
    inMemoryProfileReference.profile_id !== profile.profile_id &&
    !isExpired(inMemoryProfileReference.updated_at, now) &&
    Date.parse(inMemoryProfileReference.updated_at) >= Date.parse(profile.updated_at)
  ) {
    return {
      state: "unavailable",
      profile: inMemoryProfileReference,
      message: STORAGE_MESSAGES.unavailable,
    };
  }
  if (isExpired(profile.updated_at, now)) {
    inMemoryProfileReference = null;
    if (!removeAffectedKey(resolvedStorage, PROFILE_STORAGE_KEY)) {
      return { state: "unavailable", profile: null, message: STORAGE_MESSAGES.unavailable };
    }
    return { state: "expired", profile: null, message: STORAGE_MESSAGES.invalid };
  }

  inMemoryProfileReference = profile;
  return { state: "valid", profile };
}

export function writeProfileReference(
  profileId: string,
  storage?: StoragePort,
  now = Date.now(),
): ProfileWriteResult {
  const profile = profileReferenceRecordSchema.parse({
    schema_version: PROFILE_REFERENCE_SCHEMA_VERSION,
    profile_schema_version: PROFILE_SCHEMA_VERSION,
    questionnaire_version: QUESTIONNAIRE_VERSION,
    scoring_version: SCORING_VERSION,
    description_template_version: DESCRIPTION_TEMPLATE_VERSION,
    updated_at: new Date(now).toISOString(),
    profile_id: profileId,
  });
  const serialized = JSON.stringify(profile);
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
    throw new Error("profile reference exceeds the bounded payload size");
  }
  inMemoryProfileReference = profile;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return {
      state: "memory-fallback",
      profile,
      message: STORAGE_MESSAGES.unavailable,
    };
  }
  try {
    resolvedStorage.setItem(PROFILE_STORAGE_KEY, serialized);
    return { state: "persisted", profile };
  } catch {
    return {
      state: "memory-fallback",
      profile,
      message: STORAGE_MESSAGES.unavailable,
    };
  }
}

export function readPendingProfileSubmission(
  payloadSha256: string,
  storage?: StoragePort,
  now = Date.now(),
): PendingProfileSubmission | null {
  if (!/^[0-9a-f]{64}$/.test(payloadSha256)) return null;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return inMemoryPendingProfileSubmission?.payload_sha256 === payloadSha256
      ? inMemoryPendingProfileSubmission
      : null;
  }
  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY);
  } catch {
    return inMemoryPendingProfileSubmission?.payload_sha256 === payloadSha256
      ? inMemoryPendingProfileSubmission
      : null;
  }
  if (raw === null) return null;
  try {
    const pending = parseStoredJson(raw);
    if (!isPendingProfileSubmission(pending) || isExpired(pending.updated_at, now)) {
      inMemoryPendingProfileSubmission = null;
      removeAffectedKey(resolvedStorage, PENDING_PROFILE_SUBMISSION_KEY);
      return null;
    }
    inMemoryPendingProfileSubmission = pending;
    return pending.payload_sha256 === payloadSha256 ? pending : null;
  } catch {
    inMemoryPendingProfileSubmission = null;
    removeAffectedKey(resolvedStorage, PENDING_PROFILE_SUBMISSION_KEY);
    return null;
  }
}

export function writePendingProfileSubmission(
  payloadSha256: string,
  requestId: string,
  storage?: StoragePort,
  now = Date.now(),
): PendingProfileSubmission {
  const pending: PendingProfileSubmission = {
    schema_version: "phase1-pending-profile-v1",
    request_id: requestId,
    payload_sha256: payloadSha256,
    updated_at: new Date(now).toISOString(),
  };
  if (!isPendingProfileSubmission(pending)) {
    throw new Error("pending profile submission is invalid");
  }
  const serialized = JSON.stringify(pending);
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
    throw new Error("pending profile submission exceeds the bounded payload size");
  }
  inMemoryPendingProfileSubmission = pending;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage !== null) {
    try {
      resolvedStorage.setItem(PENDING_PROFILE_SUBMISSION_KEY, serialized);
    } catch {
      // The in-memory copy still protects same-mount retries when storage is unavailable.
    }
  }
  return pending;
}

export function clearPendingProfileSubmission(
  requestId: string,
  storage?: StoragePort,
): boolean {
  const resolvedStorage = resolveStorage(storage);
  const matchesMemory = inMemoryPendingProfileSubmission?.request_id === requestId;
  if (matchesMemory) inMemoryPendingProfileSubmission = null;
  if (resolvedStorage === null) return false;
  try {
    const raw = resolvedStorage.getItem(PENDING_PROFILE_SUBMISSION_KEY);
    if (raw === null) return true;
    const pending = parseStoredJson(raw);
    if (isPendingProfileSubmission(pending) && pending.request_id !== requestId) return false;
    resolvedStorage.removeItem(PENDING_PROFILE_SUBMISSION_KEY);
    return true;
  } catch {
    return false;
  }
}

export function readCompareSelectionForRun(
  runId: string,
  storage?: StoragePort,
  now = Date.now(),
): CompareSelectionReadResult {
  const resolvedStorage = resolveStorage(storage);
  const validMemorySelection = () => {
    if (
      inMemoryCompareSelection === null ||
      inMemoryCompareSelection.run_id !== runId ||
      isExpired(inMemoryCompareSelection.updated_at, now)
    ) {
      inMemoryCompareSelection = null;
      return null;
    }
    return inMemoryCompareSelection;
  };
  if (resolvedStorage === null) {
    const selection = validMemorySelection();
    return {
      state: "unavailable",
      selection,
      message: COMPARE_STORAGE_MESSAGES.unavailable,
    };
  }

  if (inMemoryCompareSelectionFallback) {
    const selection = validMemorySelection();
    return {
      state: "unavailable",
      selection,
      message: COMPARE_STORAGE_MESSAGES.unavailable,
    };
  }

  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(COMPARE_SELECTION_STORAGE_KEY);
  } catch {
    return {
      state: "unavailable",
      selection: validMemorySelection(),
      message: COMPARE_STORAGE_MESSAGES.unavailable,
    };
  }
  if (raw === null) {
    if (inMemoryCompareSelectionFallback) {
      const selection = validMemorySelection();
      if (selection !== null) {
        return {
          state: "unavailable",
          selection,
          message: COMPARE_STORAGE_MESSAGES.unavailable,
        };
      }
      inMemoryCompareSelectionFallback = false;
    }
    inMemoryCompareSelection = null;
    return { state: "empty", selection: null };
  }

  try {
    const selection = compareSelectionRecordSchema.parse(parseStoredJson(raw));
    if (isExpired(selection.updated_at, now)) {
      inMemoryCompareSelection = null;
      removeAffectedKey(resolvedStorage, COMPARE_SELECTION_STORAGE_KEY);
      return { state: "expired", selection: null, message: COMPARE_STORAGE_MESSAGES.corrupt };
    }
    if (selection.run_id !== runId) {
      inMemoryCompareSelection = null;
      removeAffectedKey(resolvedStorage, COMPARE_SELECTION_STORAGE_KEY);
      return { state: "cleared", selection: null, message: COMPARE_STORAGE_MESSAGES.crossRun };
    }
    inMemoryCompareSelection = selection;
    inMemoryCompareSelectionFallback = false;
    return { state: "valid", selection };
  } catch {
    inMemoryCompareSelection = null;
    if (!removeAffectedKey(resolvedStorage, COMPARE_SELECTION_STORAGE_KEY)) {
      return {
        state: "unavailable",
        selection: null,
        message: COMPARE_STORAGE_MESSAGES.unavailable,
      };
    }
    return { state: "corrupt", selection: null, message: COMPARE_STORAGE_MESSAGES.corrupt };
  }
}

export function readCompareSelection(
  runId: string,
  releaseSha256: string,
  storage?: StoragePort,
  now = Date.now(),
): CompareSelectionReadResult {
  const read = readCompareSelectionForRun(runId, storage, now);
  if (read.selection === null || read.selection.release_sha256 === releaseSha256) return read;
  clearCompareSelection(storage);
  return { state: "cleared", selection: null, message: COMPARE_STORAGE_MESSAGES.crossRun };
}

export function writeCompareSelection(
  input: { runId: string; releaseSha256: string; placeIds: readonly string[] },
  storage?: StoragePort,
  now = Date.now(),
): CompareSelectionWriteResult {
  const selection = compareSelectionRecordSchema.parse({
    schema_version: COMPARE_SELECTION_SCHEMA_VERSION,
    run_id: input.runId,
    release_sha256: input.releaseSha256,
    place_ids: [...input.placeIds],
    updated_at: new Date(now).toISOString(),
  });
  const serialized = JSON.stringify(selection);
  if (new TextEncoder().encode(serialized).byteLength > MAX_STORAGE_RECORD_BYTES) {
    throw new Error("compare selection exceeds the bounded payload size");
  }
  inMemoryCompareSelection = selection;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    inMemoryCompareSelectionFallback = true;
    return {
      state: "memory-fallback",
      selection,
      message: COMPARE_STORAGE_MESSAGES.unavailable,
    };
  }
  try {
    resolvedStorage.setItem(COMPARE_SELECTION_STORAGE_KEY, serialized);
    inMemoryCompareSelectionFallback = false;
    return { state: "persisted", selection };
  } catch {
    inMemoryCompareSelectionFallback = true;
    return {
      state: "memory-fallback",
      selection,
      message: COMPARE_STORAGE_MESSAGES.unavailable,
    };
  }
}

export function clearCompareSelection(storage?: StoragePort): boolean {
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    inMemoryCompareSelection = null;
    inMemoryCompareSelectionFallback = true;
    return false;
  }
  const removed = removeAffectedKey(resolvedStorage, COMPARE_SELECTION_STORAGE_KEY);
  if (removed) {
    inMemoryCompareSelection = null;
    inMemoryCompareSelectionFallback = false;
  } else {
    inMemoryCompareSelection = null;
    inMemoryCompareSelectionFallback = true;
  }
  return removed;
}

function isPhotoDraftExpired(createdAt: string, now: number): boolean {
  return now - Date.parse(createdAt) > PHOTO_DRAFT_RETENTION_MS;
}

/**
 * Read the bounded photo job reference for the current profile. Corrupt,
 * oversized, expired, foreign-schema, and profile-mismatch records clear ONLY
 * the feature key and never probe other keys; unavailable storage falls back
 * to the in-memory copy. No code path claims server-side deletion.
 */
export function readPhotoDraft(
  profileId: string,
  storage?: StoragePort,
  now = Date.now(),
): PhotoDraftReadResult {
  const resolvedStorage = resolveSessionStorage(storage);
  if (resolvedStorage === null) {
    if (inMemoryPhotoDraft !== null && inMemoryPhotoDraft.profile_id === profileId &&
        !isPhotoDraftExpired(inMemoryPhotoDraft.created_at, now)) {
      return { state: "unavailable", record: inMemoryPhotoDraft };
    }
    inMemoryPhotoDraft = null;
    return { state: "unavailable", record: null };
  }

  if (inMemoryPhotoDraftFallback) {
    if (
      inMemoryPhotoDraft !== null &&
      inMemoryPhotoDraft.profile_id === profileId &&
      !isPhotoDraftExpired(inMemoryPhotoDraft.created_at, now)
    ) {
      return { state: "unavailable", record: inMemoryPhotoDraft };
    }
    inMemoryPhotoDraft = null;
    return { state: "unavailable", record: null };
  }

  let raw: string | null;
  try {
    raw = resolvedStorage.getItem(PHOTO_DRAFT_STORAGE_KEY);
  } catch {
    inMemoryPhotoDraftFallback = true;
    if (
      inMemoryPhotoDraft !== null &&
      inMemoryPhotoDraft.profile_id === profileId &&
      !isPhotoDraftExpired(inMemoryPhotoDraft.created_at, now)
    ) {
      return { state: "unavailable", record: inMemoryPhotoDraft };
    }
    inMemoryPhotoDraft = null;
    return { state: "unavailable", record: null };
  }
  if (raw === null) {
    inMemoryPhotoDraft = null;
    return { state: "empty", record: null };
  }

  let parsed: unknown;
  try {
    if (new TextEncoder().encode(raw).byteLength > MAX_PHOTO_DRAFT_RECORD_BYTES) {
      throw new Error("photo draft exceeds the bounded payload size");
    }
    parsed = JSON.parse(raw);
  } catch {
    inMemoryPhotoDraft = null;
    removeAffectedKey(resolvedStorage, PHOTO_DRAFT_STORAGE_KEY);
    return { state: "corrupt", record: null };
  }

  const parsedRecord = photoDraftRecordSchema.safeParse(parsed);
  if (!parsedRecord.success) {
    inMemoryPhotoDraft = null;
    removeAffectedKey(resolvedStorage, PHOTO_DRAFT_STORAGE_KEY);
    return { state: "corrupt", record: null };
  }

  const record = parsedRecord.data;
  if (record.profile_id !== profileId) {
    // A foreign profile's reference is unreadable here: clear only this key.
    inMemoryPhotoDraft = null;
    removeAffectedKey(resolvedStorage, PHOTO_DRAFT_STORAGE_KEY);
    return { state: "profile_mismatch", record: null };
  }
  if (isPhotoDraftExpired(record.created_at, now)) {
    inMemoryPhotoDraft = null;
    removeAffectedKey(resolvedStorage, PHOTO_DRAFT_STORAGE_KEY);
    return { state: "expired", record: null };
  }
  inMemoryPhotoDraft = record;
  return { state: "valid", record };
}

/**
 * Write the bounded photo job reference to sessionStorage. Failure keeps the
 * in-memory copy so the current tab can resume; nothing is disabled and no
 * server deletion is claimed or requested.
 */
export function writePhotoDraft(
  input: { jobId: string; profileId: string; noticeVersion: string },
  storage?: StoragePort,
  now = Date.now(),
): PhotoDraftWriteResult {
  const record = photoDraftRecordSchema.parse({
    schema_version: PHOTO_DRAFT_SCHEMA_VERSION,
    job_id: input.jobId,
    profile_id: input.profileId,
    notice_version: input.noticeVersion,
    created_at: new Date(now).toISOString(),
  });
  const serialized = JSON.stringify(record);
  if (new TextEncoder().encode(serialized).byteLength > MAX_PHOTO_DRAFT_RECORD_BYTES) {
    throw new Error("photo draft exceeds the bounded payload size");
  }

  inMemoryPhotoDraft = record;
  const resolvedStorage = resolveSessionStorage(storage);
  if (resolvedStorage === null) {
    inMemoryPhotoDraftFallback = true;
    return { state: "memory-fallback", record };
  }
  try {
    resolvedStorage.setItem(PHOTO_DRAFT_STORAGE_KEY, serialized);
    inMemoryPhotoDraftFallback = false;
    return { state: "persisted", record };
  } catch {
    inMemoryPhotoDraftFallback = true;
    return { state: "memory-fallback", record };
  }
}

/**
 * Clear only the photo draft feature key. Returns true only when a real
 * removal from readable storage succeeded; fallback mode returns false. No
 * server call is implied or made.
 */
export function clearPhotoDraft(storage?: StoragePort): boolean {
  inMemoryPhotoDraft = null;
  const resolvedStorage = resolveSessionStorage(storage);
  if (resolvedStorage === null) {
    inMemoryPhotoDraftFallback = true;
    return false;
  }
  const removed = removeAffectedKey(resolvedStorage, PHOTO_DRAFT_STORAGE_KEY);
  inMemoryPhotoDraftFallback = !removed;
  return removed;
}

export function resetJourneyStorage(storage?: StoragePort):
  | { state: "reset"; message: typeof STORAGE_MESSAGES.reset }
  | { state: "unavailable"; message: typeof STORAGE_MESSAGES.unavailable } {
  inMemoryDraft = null;
  inMemoryProfileReference = null;
  inMemoryPendingProfileSubmission = null;
  inMemoryCompareSelection = null;
  const resolvedStorage = resolveStorage(storage);
  if (resolvedStorage === null) {
    return { state: "unavailable", message: STORAGE_MESSAGES.unavailable };
  }
  try {
    resolvedStorage.removeItem(DRAFT_STORAGE_KEY);
    resolvedStorage.removeItem(LEGACY_V1_DRAFT_STORAGE_KEY);
    resolvedStorage.removeItem(PROFILE_STORAGE_KEY);
    resolvedStorage.removeItem(PENDING_PROFILE_SUBMISSION_KEY);
    resolvedStorage.removeItem(COMPARE_SELECTION_STORAGE_KEY);
    return { state: "reset", message: STORAGE_MESSAGES.reset };
  } catch {
    return { state: "unavailable", message: STORAGE_MESSAGES.unavailable };
  }
}
