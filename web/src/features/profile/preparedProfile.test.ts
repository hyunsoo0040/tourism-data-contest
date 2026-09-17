import { afterEach, expect, it, vi } from "vitest";
import type { PreferenceProfile } from "../../api/api";
import { clearPreparedProfileNavigation, prepareProfileNavigation, readPreparedProfileNavigation } from "./preparedProfile";

const profile = { profile_id: "prepared-profile" } as PreferenceProfile;
afterEach(() => { clearPreparedProfileNavigation(profile); vi.useRealTimers(); });

it("hands a result only to its navigation key and current profile reference", () => {
  const key = prepareProfileNavigation(profile);
  expect(readPreparedProfileNavigation(undefined, undefined)).toBeNull();
  expect(readPreparedProfileNavigation("old-key", profile.profile_id)).toBeNull();
  expect(readPreparedProfileNavigation(key, "other-profile")).toBeNull();
  expect(readPreparedProfileNavigation(key, profile.profile_id)).toBe(profile);
  clearPreparedProfileNavigation(profile);
  expect(readPreparedProfileNavigation(key, profile.profile_id)).toBeNull();
});

it("expires an unused result so later visits must fetch the profile again", () => {
  vi.useFakeTimers();
  const key = prepareProfileNavigation(profile);
  vi.advanceTimersByTime(60_000);
  expect(readPreparedProfileNavigation(key, profile.profile_id)).toBeNull();
});
