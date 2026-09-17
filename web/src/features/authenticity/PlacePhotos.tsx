"use client";

import { useLayoutEffect, useRef, useState } from "react";
import styles from "./PlacePhotos.module.css";

const licenseNames: Record<string, string> = {
  KOGL_TYPE_0: "공공누리 제0유형",
  KOGL_TYPE_1: "공공누리 제1유형 · 출처표시",
  KOGL_TYPE_2: "공공누리 제2유형 · 출처표시·비상업적 이용",
  KOGL_TYPE_3: "공공누리 제3유형 · 출처표시·변경금지",
  KOGL_TYPE_4: "공공누리 제4유형 · 출처표시·비상업적 이용·변경금지",
};
const noDerivatives = (license?: string) => ["KOGL_TYPE_3", "KOGL_TYPE_4", "Type3", "Type4"].includes(license ?? "");

export function photoUrl(value?: string): string | null {
  if (!value) return null;
  if (value.startsWith("/tourism/") && !value.includes("..")) return value;
  try {
    const url = new URL(value);
    if (url.protocol === "http:" && url.hostname === "tong.visitkorea.or.kr") url.protocol = "https:";
    return url.protocol === "https:" ? url.href : null;
  } catch { return null; }
}

// Move the already-decoded image into its frame before paint. Recreating an img
// would revalidate no-cache photos and reintroduce loading after navigation.
function PreparedPhoto({ image, alt }: { image: HTMLImageElement; alt: string }) {
  const host = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    const frame = host.current!;
    image.className = styles.image!;
    image.alt = alt;
    frame.appendChild(image);
    return () => { if (image.parentNode === frame) frame.removeChild(image); };
  }, [image, alt]);
  return <span ref={host} style={{ display: "contents" }} />;
}

export function PlacePhotos({ name, photos, loading = false, unavailable = false, size = "card", gallery = true, captionMode = "full", preparedImages, failedUrls = [] }: {
  name: string;
  photos: readonly Readonly<Record<string, string>>[];
  loading?: boolean;
  unavailable?: boolean;
  size?: "card" | "full";
  gallery?: boolean;
  captionMode?: "full" | "source-only";
  preparedImages?: Readonly<Record<string, HTMLImageElement>>;
  failedUrls?: readonly string[];
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [failed, setFailed] = useState<Set<string>>(() => new Set(failedUrls));
  const all = photos.flatMap<Record<string, string>>(photo => {
    const url = photoUrl(photo.url);
    return url ? [{ ...photo, url }] : [];
  }).filter((photo, index, rows) => rows.findIndex(p => p.url === photo.url) === index);
  const available = all.filter(photo => !failed.has(photo.url));
  const active = available.find(photo => photo.url === selected) ?? available[0];
  const position = active ? all.findIndex(photo => photo.url === active.url) + 1 : 0;
  const original = photoUrl(active?.original_url ?? active?.url);
  const attribution = active?.attribution_ko || "공식 관광사진";
  const restricted = active?.license && !["KOGL_TYPE_0", "KOGL_TYPE_1"].includes(active.license);
  const source = photoUrl(active?.source_url);
  const captionDetails = [
    (captionMode === "full" || restricted) && (licenseNames[active?.license ?? ""] ?? active?.license),
    gallery && all.length > 1 && `${position}/${all.length}`,
  ].filter(Boolean).join(" · ");

  return <figure className={styles.gallery} data-size={size} aria-label={`${name} 사진`}>
    <div className={styles.frame} data-preserve-original={noDerivatives(active?.license) || undefined}>
      {active ? preparedImages?.[active.url] ? <PreparedPhoto image={preparedImages[active.url]!} alt={`${name}의 공식 관광사진 ${position}`} /> : <img className={styles.image} src={active.url}
        alt={`${name}의 공식 관광사진 ${position}`} loading="lazy" decoding="async"
        onError={() => setFailed(previous => new Set(previous).add(active.url))} />
        : <div className={styles.empty} role={loading ? "status" : undefined}>
          <span>{loading ? "사진을 불러오고 있어요" : unavailable ? "사진 정보를 확인하지 못했어요" : all.length ? "사진을 불러오지 못했어요" : "확인된 공식 사진이 아직 없어요"}</span>
          {all.length > 0 && <button type="button" onClick={() => setFailed(new Set())}>사진 다시 불러오기</button>}
        </div>}
    </div>
    {active && <>
      {gallery && available.length > 1 && <div className={styles.thumbnails} aria-label={`${name} 사진 선택`}>
        {available.map(photo => <button key={photo.url} type="button" className={styles.thumbnail}
          data-preserve-original={noDerivatives(photo.license) || undefined}
          aria-label={`${name} 사진 ${all.findIndex(p => p.url === photo.url) + 1} 보기`}
          aria-pressed={photo.url === active.url} onClick={() => setSelected(photo.url)}>
          <img src={photo.url} alt="" loading="lazy" decoding="async" />
        </button>)}
      </div>}
      <figcaption className={styles.caption}>
        <span>{captionMode === "source-only" && !restricted ? attribution.split(" · ")[0] : attribution}</span>
        <span>{captionDetails}
          {source && <>{captionDetails && " · "}<a href={source} target="_blank" rel="noreferrer">출처</a></>}
          {original && <>{(captionDetails || source) && " · "}<a href={original} target="_blank" rel="noreferrer">원본 사진</a></>}
        </span>
      </figcaption>
    </>}
  </figure>;
}
