import { useEffect, useRef } from "react";

import { useJourneyAnnouncements } from "../../app/AppShell";

export type ComparePlaceReference = {
  placeId: string;
  placeName: string;
  regionName?: string | null;
};

type CompareTrayProps = {
  selectedPlaces: readonly ComparePlaceReference[];
  announcement: string;
  onRemove: (placeId: string) => void;
  onCompare: () => void;
};

const LIMIT_NOTE_ID = "compare-limit-note";

export function CompareTray({
  selectedPlaces,
  announcement,
  onRemove,
  onCompare,
}: CompareTrayProps) {
  const trayRef = useRef<HTMLElement>(null);
  const announcements = useJourneyAnnouncements();
  const count = selectedPlaces.length;
  const helper =
    count === 0
      ? "비교할 장소 2~3곳을 선택하세요."
      : count === 1
        ? "한 곳을 더 선택하세요."
        : count === 3
          ? "최대 3곳까지 비교할 수 있어요."
          : "선택한 장소를 비교할 수 있어요.";

  useEffect(() => {
    if (announcement !== "") announcements?.announceInteraction(announcement);
  }, [announcement, announcements]);

  return (
    <aside
      ref={trayRef}
      className="compare-tray"
      aria-label="비교 선택"
      tabIndex={-1}
      style={{
        position: "sticky",
        bottom: 0,
        marginTop: "var(--space-lg)",
        paddingBlock: "var(--space-md)",
        paddingBottom: "calc(var(--space-md) + env(safe-area-inset-bottom))",
        borderTop: "1px solid var(--line)",
        background: "var(--surface)",
        zIndex: 2,
      }}
    >
      <div className="compare-tray__heading">
        <strong>장소 비교</strong>
        <span aria-label={`비교 선택 ${count}곳, 최대 3곳`}>{count}/3</span>
      </div>
      {selectedPlaces.length > 0 ? (
        <ul className="compare-tray__selection" aria-label="비교에 선택한 장소">
          {selectedPlaces.map((place) => (
            <li key={place.placeId}>
              <span>{place.placeName}{place.regionName && <small className="recommendation-location"> · {place.regionName}</small>}</span>
              <button
                type="button"
                className="button button--secondary"
                aria-label={`${place.placeName}${place.regionName ? ` · ${place.regionName}` : ""} 비교에서 빼기`}
                onClick={() => {
                  onRemove(place.placeId);
                  requestAnimationFrame(() => trayRef.current?.focus());
                }}
              >
                빼기
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <p id={count === 3 ? LIMIT_NOTE_ID : undefined}>{helper}</p>
      <button
        type="button"
        className="button button--primary"
        disabled={count < 2 || count > 3}
        onClick={onCompare}
      >
        선택한 장소 비교하기
      </button>
      {announcements === null ? (
        <p
          className="visually-hidden"
          role="status"
          aria-label="비교 선택 알림"
          aria-live="polite"
          aria-atomic="true"
        >
          {announcement}
        </p>
      ) : null}
    </aside>
  );
}
