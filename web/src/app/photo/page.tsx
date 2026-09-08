import { SpaHost } from "../spa-host";

/**
 * `/photo` — upstream photo shell (사진 기능.html) wired to the existing
 * consent/upload/poll/review/confirm/delete/fallback flow through the SPA
 * host.
 */
export default function PhotoPage() {
  return <SpaHost />;
}
