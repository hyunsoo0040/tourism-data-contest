import type { Detail } from "./api";
import { placeIntroduction, placeMapUrl } from "./placeMetadata";
import styles from "./Journey.module.css";

export function PlaceInformation({ detail, expanded = false }: { detail: Detail; expanded?: boolean }) {
  const intro = placeIntroduction(detail);
  return <section className={styles.placeInformation} aria-label={`${detail.item.name_ko} 장소 정보`}>
    {intro ? <>
      <p className={styles.description}>{expanded || intro.text.length <= 200 ? intro.text : `${intro.text.slice(0, 200)}…`}</p>
      <p className={styles.small}>한국관광공사 · 공식 관광정보 · 자료 확인 {intro.retrievedAt.slice(0, 10)}</p>
    </> : <p className={styles.small}>확인된 장소 소개가 아직 없어요.</p>}
    <p className={styles.address}>{detail.address || "주소 미확인"}
      <a href={placeMapUrl(detail.item.name_ko, detail.address)} target="_blank" rel="noreferrer">지도에서 보기</a>
    </p>
  </section>;
}
