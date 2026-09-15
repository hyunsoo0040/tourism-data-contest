import type { Detail } from "./api";

export function placeIntroduction(detail: Detail) {
  const source = detail.evidence
    .filter(e => e.role === "OFFICIAL_DESCRIPTION" && (e.excerpt?.trim().length ?? 0) >= 40)
    .sort((a, b) => (b.excerpt?.length ?? 0) - (a.excerpt?.length ?? 0))[0];
  if (!source?.excerpt) return null;
  const text = source.excerpt.replace(/<[^>]*>/g, " ").replace(/&nbsp;|&#160;/g, " ")
    .replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
  return { text, retrievedAt: source.retrieved_at };
}

export function placeMapUrl(name: string, address: string) {
  return `https://map.naver.com/p/search/${encodeURIComponent([name, address].filter(Boolean).join(" "))}`;
}

export function kakaoMapSearchUrl(name: string, address: string) {
  return `https://map.kakao.com/link/search/${encodeURIComponent([name, address].filter(Boolean).join(" "))}`;
}
