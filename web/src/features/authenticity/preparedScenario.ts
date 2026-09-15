import { api, currentToken, escapeId, JourneyError, type Detail, type Intent, type Run } from "./api";
import { photoUrl } from "./PlacePhotos";

export type PreparedScenario = {
  run: Run;
  profile: Intent;
  details: Record<string, Detail>;
  saved: string[];
  savedError: string | null;
  failedPhotoUrls: string[];
  images: Record<string, Record<string, HTMLImageElement>>;
};

// A single, short-lived handoff in memory. Never persist answers, evidence or
// bearer tokens in browser history, and never reuse a different session's data.
let handoff: { owner: string; expires: number; value: PreparedScenario } | null = null;
export function readPreparedScenario(runId: string | null): PreparedScenario | null {
  if (handoff && (handoff.owner !== currentToken() || handoff.expires < Date.now())) handoff = null;
  return handoff?.value.run.run_sha256 === runId ? handoff.value : null;
}
export function clearPreparedScenario(value: PreparedScenario) {
  if (handoff?.value === value) handoff = null;
}

function preloadPhoto(url: string, signal: AbortSignal): Promise<HTMLImageElement | null> {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    const image = new Image();
    let settled = false;
    const finish = (loaded: boolean) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      image.onload = image.onerror = null;
      if (!loaded) image.src = "";
      if (signal.aborted) reject(signal.reason);
      else resolve(loaded ? image : null);
    };
    const abort = () => finish(false);
    // A failed or stalled external photo must not hold the whole result forever.
    const timer = window.setTimeout(() => finish(false), 8000);
    image.onload = () => {
      if (typeof image.decode === "function") void image.decode().then(() => finish(true), () => finish(false));
      else finish(true);
    };
    image.onerror = () => finish(false);
    signal.addEventListener("abort", abort, { once: true });
    image.src = url;
  });
}

export async function prepareScenario(run: Run, profile: Intent, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  const owner = currentToken();
  const controller = new AbortController();
  const abort = () => controller.abort(signal.reason);
  signal.addEventListener("abort", abort, { once: true });
  const options = { signal: controller.signal };
  try {
    // The existing read verifies the pinned run on the server once, before
    // requesting all five details concurrently. It used to happen after navigation.
    const verified = await api<Run>(`/runs/${escapeId(run.run_sha256)}`, options);
    if (verified.run_sha256 !== run.run_sha256 || verified.profile_id !== profile.profile_id || verified.intent_sha256 !== profile.intent_sha256) {
      throw new Error("현재 답변과 추천 결과의 연결을 확인하지 못했어요. 다시 시도해 주세요.");
    }
    const [details, saved] = await Promise.all([
      Promise.all(verified.items.map(async item => {
        const detail = await api<Detail>(`/runs/${escapeId(run.run_sha256)}/places/${escapeId(item.place_id)}`, options);
        if (detail.item.place_id !== item.place_id || detail.item.assessment_sha256 !== item.assessment_sha256) {
          throw new Error("추천한 장소와 상세 정보의 연결을 확인하지 못했어요. 다시 시도해 주세요.");
        }
        return detail;
      })),
      api<{ run_sha256: string; place_id: string }[]>("/saved", options)
        .then(rows => ({ ids: rows.filter(row => row.run_sha256 === run.run_sha256).map(row => row.place_id), error: null as string | null }))
        .catch(reason => {
          if (controller.signal.aborted || reason instanceof JourneyError && reason.status === 401) throw reason;
          return { ids: [], error: "저장한 장소 목록을 불러오지 못했어요. 다시 불러오면 확인할 수 있어요." };
        }),
    ]);
    const photos = details.flatMap(detail => [...new Set(detail.photos.map(photo => photoUrl(photo.url)).filter((url): url is string => url !== null))]
      .map(url => ({ placeId: detail.item.place_id, url })));
    const loaded = await Promise.all(photos.map(photo => preloadPhoto(photo.url, controller.signal)));
    signal.throwIfAborted();
    if (!owner || owner !== currentToken()) throw new JourneyError(401, "여행 세션이 변경되었습니다. 다시 시도해 주세요.");
    handoff = { owner, expires: Date.now() + 60_000, value: {
      run: verified, profile, details: Object.fromEntries(details.map(detail => [detail.item.place_id, detail])),
      saved: saved.ids, savedError: saved.error, failedPhotoUrls: photos.filter((_, index) => !loaded[index]).map(photo => photo.url),
      images: Object.fromEntries(details.map(detail => [detail.item.place_id, Object.fromEntries(photos.flatMap((photo, index) =>
        photo.placeId === detail.item.place_id && loaded[index] ? [[photo.url, loaded[index]!]] : []))])),
    } };
  } finally {
    signal.removeEventListener("abort", abort);
    controller.abort();
  }
}
