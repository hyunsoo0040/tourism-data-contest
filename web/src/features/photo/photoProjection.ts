export const CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY =
  "itda.phase6.confirmed-photo-reference.v1" as const;
const SCHEMA_VERSION = "itda.phase6.confirmed-photo-reference.v1" as const;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

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
  const current = readConfirmedPhotoReference(profileId);
  if (current === null) return;
  memoryReference = null;
  try {
    window.sessionStorage.removeItem(CONFIRMED_PHOTO_REFERENCE_STORAGE_KEY);
  } catch {
    return;
  }
}
