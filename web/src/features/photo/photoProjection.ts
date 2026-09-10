export const CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY =
  "itda.phase6.confirmed-photo-reference.v1" as const;
const SCHEMA_VERSION = "itda.phase6.confirmed-photo-reference.v1" as const;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export const CONFIRMED_MOOD_REFERENCE_STORAGE_KEY = "itda.photo-mood-reference.v1";
export type ConfirmedMoodReference = {
  schema_version: "itda.photo-mood-reference.v1";
  family: "photo-mood-v1";
  preference_profile_id: string;
  photo_job_id: string;
  receipt_id: string;
};
let memoryMoodReference: ConfirmedMoodReference | null = null;

function parseMoodReference(raw: string | null): ConfirmedMoodReference | null {
  if (raw === null || raw.length > 1024) return null;
  try {
    const row = JSON.parse(raw) as Record<string, unknown>;
    if (!row || Array.isArray(row) || Object.keys(row).sort().join(",") !== "family,photo_job_id,preference_profile_id,receipt_id,schema_version" ||
      row.schema_version !== "itda.photo-mood-reference.v1" || row.family !== "photo-mood-v1" ||
      typeof row.preference_profile_id !== "string" || row.preference_profile_id.length < 1 || row.preference_profile_id.length > 160 ||
      typeof row.photo_job_id !== "string" || !SHA256_PATTERN.test(row.photo_job_id) ||
      typeof row.receipt_id !== "string" || !SHA256_PATTERN.test(row.receipt_id)) return null;
    return row as ConfirmedMoodReference;
  } catch { return null; }
}

/** Opaque navigation reference only. The backend re-reads the owned immutable
 * confirmation; sessionStorage never grants numerical mood authority. */
export function readConfirmedMoodReference(profileId: string): ConfirmedMoodReference | null {
  let reference: ConfirmedMoodReference | null;
  try {
    const raw = window.sessionStorage.getItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY);
    reference = parseMoodReference(raw);
    if (raw !== null && reference === null) window.sessionStorage.removeItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY);
  } catch { reference = memoryMoodReference; }
  return reference?.preference_profile_id === profileId ? reference : null;
}

export function writeConfirmedMoodReference(profileId: string, photoJobId: string, receiptId: string): boolean {
  const reference = parseMoodReference(JSON.stringify({ schema_version: "itda.photo-mood-reference.v1",
    family: "photo-mood-v1", preference_profile_id: profileId, photo_job_id: photoJobId, receipt_id: receiptId }));
  if (!reference) return false;
  memoryMoodReference = reference;
  try { window.sessionStorage.setItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY, JSON.stringify(reference)); }
  catch { /* The current mounted flow retains only this opaque reference. */ }
  return true;
}

export function clearConfirmedMoodReference(profileId: string): void {
  if (readConfirmedMoodReference(profileId) === null && memoryMoodReference?.preference_profile_id !== profileId) return;
  memoryMoodReference = null;
  try { window.sessionStorage.removeItem(CONFIRMED_MOOD_REFERENCE_STORAGE_KEY); } catch { return; }
}

export type ConfirmedPhotoReference = {
  schema_version: typeof SCHEMA_VERSION;
  preference_profile_id: string;
  photo_job_id: string;
};

let memoryReference: ConfirmedPhotoReference | null = null;

function parseReference(raw: string | null): ConfirmedPhotoReference | null {
  if (raw === null || raw.length > 512) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    const reference = parsed as Record<string, unknown>;
    const keys = Object.keys(reference).sort();
    if (
      keys.length !== 3 ||
      keys[0] !== "photo_job_id" ||
      keys[1] !== "preference_profile_id" ||
      keys[2] !== "schema_version" ||
      reference.schema_version !== SCHEMA_VERSION ||
      typeof reference.preference_profile_id !== "string" ||
      reference.preference_profile_id.length === 0 ||
      reference.preference_profile_id.length > 160 ||
      typeof reference.photo_job_id !== "string" ||
      !SHA256_PATTERN.test(reference.photo_job_id)
    ) {
      return null;
    }
    return reference as ConfirmedPhotoReference;
  } catch {
    return null;
  }
}

export function readConfirmedPhotoReference(profileId: string): string | null {
  let stored: ConfirmedPhotoReference | null = null;
  try {
    const raw = window.sessionStorage.getItem(CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY);
    stored = parseReference(raw);
    if (raw !== null && stored === null) {
      window.sessionStorage.removeItem(CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY);
    }
  } catch {
    stored = null;
  }
  const reference = stored ?? memoryReference;
  if (reference?.preference_profile_id !== profileId) return null;
  return reference.photo_job_id;
}

export function writeConfirmedPhotoReference(profileId: string, photoJobId: string): boolean {
  const reference = parseReference(
    JSON.stringify({
      schema_version: SCHEMA_VERSION,
      preference_profile_id: profileId,
      photo_job_id: photoJobId,
    }),
  );
  if (reference === null) return false;
  memoryReference = reference;
  try {
    window.sessionStorage.setItem(
      CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY,
      JSON.stringify(reference),
    );
  } catch {
    return true;
  }
  return true;
}

export function clearConfirmedPhotoReference(profileId: string): void {
  clearConfirmedMoodReference(profileId);
  const current = readConfirmedPhotoReference(profileId);
  if (current === null) return;
  memoryReference = null;
  try {
    window.sessionStorage.removeItem(CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY);
  } catch {
    return;
  }
}
