import { PHOTO_FALLBACK_COPY } from "./PhotoJobStatus";

/**
 * Polite, nonblocking notice shown when the browser refused the bounded
 * session reference. The journey stays fully usable in the current tab; the
 * notice never disables an action and never claims server-side deletion or
 * cleanup truth. Session-only storage is the invariant — nothing is written
 * to localStorage.
 */
export function PhotoStorageNotice() {
  return (
    <p role="status" aria-live="polite" aria-atomic="true" className="privacy-note">
      {PHOTO_FALLBACK_COPY.storageUnavailable}
    </p>
  );
}
