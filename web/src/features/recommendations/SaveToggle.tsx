export function SaveToggle({
  placeId,
  placeName,
  selected,
  onToggle,
}: {
  placeId: string;
  placeName: string;
  selected: boolean;
  onToggle: (placeId: string) => void;
}) {
  const label = selected ? `${placeName} 저장됨` : `${placeName} 저장`;
  return (
    <button
      aria-label={label}
      aria-pressed={selected}
      className={`button button--secondary save-toggle${selected ? " save-toggle--selected" : ""}`}
      onClick={() => onToggle(placeId)}
      type="button"
    >
      {label}
    </button>
  );
}
