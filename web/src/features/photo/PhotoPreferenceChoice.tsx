/**
 * Optional-photo entry choice for the profile screen.
 *
 * The no-photo journey stays the primary, immediate action; the photo path is
 * an outlined, equal-width option. This component owns no recommendation
 * semantics — both decisions are delegated through callbacks so the existing
 * no-photo authority remains the single implementation.
 */

export const PHOTO_ENTRY_COPY = {
  eyebrow: "선택 사진 취향",
  heading: "사진으로 이번 여행 취향을 더할까요?",
  body: "선택 사항이에요. 사진 없이도 지금 만든 기대 프로필로 추천 5곳을 바로 볼 수 있어요.",
  noPhoto: "사진 없이 추천 5곳 보기",
  photoPath: "사진으로 취향 더하기",
} as const;

export function PhotoPreferenceChoice({
  onNoPhoto,
  onPhotoPath,
  noPhotoSlot,
}: {
  onNoPhoto: () => void;
  onPhotoPath: () => void;
  noPhotoSlot?: React.ReactNode;
}) {
  return (
    <section
      className="profile-state"
      aria-labelledby="photo-preference-entry-heading"
      style={{ padding: "var(--space-lg)" }}
    >
      <p className="eyebrow">{PHOTO_ENTRY_COPY.eyebrow}</p>
      <h1 id="photo-preference-entry-heading" tabIndex={-1}>
        {PHOTO_ENTRY_COPY.heading}
      </h1>
      <p>{PHOTO_ENTRY_COPY.body}</p>
      <div
        style={{
          display: "grid",
          gap: "var(--space-sm)",
          marginTop: "var(--space-md)",
        }}
      >
        {noPhotoSlot ?? (
          <button type="button" className="button button--primary" onClick={onNoPhoto}>
            {PHOTO_ENTRY_COPY.noPhoto}
          </button>
        )}
        <button type="button" className="button button--secondary" onClick={onPhotoPath}>
          {PHOTO_ENTRY_COPY.photoPath}
        </button>
      </div>
    </section>
  );
}
