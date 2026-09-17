import type { PreferenceProfile } from "../../api/api";

// A single navigation handoff in memory; history stores only its opaque key.
let prepared: { key: string; profile: PreferenceProfile; expiresAt: number } | null = null;

export function prepareProfileNavigation(profile: PreferenceProfile): string {
  const key = crypto.randomUUID();
  prepared = { key, profile, expiresAt: Date.now() + 60_000 };
  return key;
}

export function readPreparedProfileNavigation(key: string | undefined, profileId: string | undefined): PreferenceProfile | null {
  if (prepared && prepared.expiresAt <= Date.now()) prepared = null;
  if (!prepared || prepared.key !== key || prepared.profile.profile_id !== profileId) return null;
  return prepared.profile;
}

export function clearPreparedProfileNavigation(profile: PreferenceProfile) {
  if (prepared?.profile === profile) prepared = null;
}
