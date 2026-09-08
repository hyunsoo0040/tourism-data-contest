import { useEffect, useState } from "react";

import {
  resolveSavedPlaceReference,
  type SavedPlaceProjection,
} from "../../api/api";
import { useJourneyAnnouncements } from "../../app/AppShell";
import type { SavedPlaceReference } from "../../app/storage";

type SavedRow =
  | { state: "loading"; reference: SavedPlaceReference }
  | { state: "resolved"; reference: SavedPlaceReference; projection: SavedPlaceProjection }
  | { state: "temporary-failure"; reference: SavedPlaceReference };

function rowName(row: SavedRow) {
  return row.state === "resolved" ? row.projection.place_name_ko : row.reference.place_id;
}

function stateCopy(row: SavedRow) {
  if (row.state === "loading") return "저장 정보를 확인하고 있어요.";
  if (row.state === "temporary-failure") {
    return "지금은 저장 정보를 불러올 수 없어요. 저장 항목은 그대로 유지됩니다.";
  }
  if (row.projection.state === "CURRENT") return "현재 저장 릴리스에서 확인했어요.";
  if (row.projection.state === "STALE") {
    return "저장 당시 릴리스는 현재 공개 기준이 아니에요.";
  }
  return "저장 당시 정보를 확인할 수 없어요.";
}

export function SavedSection({
  references,
  cleanupNotice = "",
  onRemove,
  resolveReference = resolveSavedPlaceReference,
}: {
  references: SavedPlaceReference[];
  cleanupNotice?: string;
  onRemove: (reference: SavedPlaceReference) => void;
  resolveReference?: (
    releaseSha256: string,
    placeId: string,
  ) => Promise<SavedPlaceProjection>;
}) {
  const [rows, setRows] = useState<SavedRow[]>(() =>
    references.map((reference) => ({ state: "loading", reference })),
  );
  const [announcement, setAnnouncement] = useState("");
  const announcements = useJourneyAnnouncements();

  useEffect(() => {
    const message = announcement || cleanupNotice;
    if (message !== "") announcements?.announceInteraction(message);
  }, [announcement, announcements, cleanupNotice]);

  useEffect(() => {
    let cancelled = false;
    setRows(references.map((reference) => ({ state: "loading", reference })));
    void Promise.all(
      references.map(async (reference): Promise<SavedRow> => {
        try {
          const projection = await resolveReference(
            reference.release_sha256,
            reference.place_id,
          );
          return { state: "resolved", reference, projection };
        } catch {
          return { state: "temporary-failure", reference };
        }
      }),
    ).then((resolvedRows) => {
      if (!cancelled) setRows(resolvedRows);
    });
    return () => {
      cancelled = true;
    };
  }, [references, resolveReference]);

  if (references.length === 0) {
    return (
      <section className="saved-section" aria-labelledby="saved-empty-heading">
        <h2 id="saved-empty-heading">아직 저장한 장소가 없어요.</h2>
        <p>추천 카드에서 저장하면 이 브라우저에서 다시 볼 수 있어요.</p>
        <a className="button button--secondary" href="#recommendation-list">
          추천 5곳 보기
        </a>
        {cleanupNotice === "" ? null : (
          <p>{cleanupNotice}</p>
        )}
      </section>
    );
  }

  return (
    <section className="saved-section" aria-labelledby="saved-section-heading">
      <h2 id="saved-section-heading">저장한 장소</h2>
      <p>이 브라우저에 저장한 릴리스 기준으로 확인해요.</p>
      {cleanupNotice === "" ? null : (
        <p>{cleanupNotice}</p>
      )}
      <ul aria-label="저장한 장소 목록">
        {rows.map((row) => {
          const name = rowName(row);
          const machineState =
            row.state === "resolved" ? row.projection.state : row.state.toUpperCase();
          return (
            <li
              data-saved-state={machineState}
              key={`${row.reference.release_sha256}:${row.reference.place_id}`}
            >
              <strong>{name}</strong>
              <p>{stateCopy(row)}</p>
              <button
                aria-label={`${name} 저장에서 삭제`}
                className="button button--secondary"
                onClick={() => {
                  onRemove(row.reference);
                  setAnnouncement(`${name}을 저장에서 삭제했어요.`);
                }}
                type="button"
              >
                저장에서 삭제
              </button>
            </li>
          );
        })}
      </ul>
      {announcements === null ? (
        <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
          {announcement}
        </p>
      ) : null}
    </section>
  );
}
