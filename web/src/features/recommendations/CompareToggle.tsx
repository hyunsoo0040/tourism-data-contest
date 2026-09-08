type CompareToggleProps = {
  placeId: string;
  placeName: string;
  selected: boolean;
  disabled: boolean;
  onToggle: (placeId: string) => void;
  maxNoteId: string;
};

export function CompareToggle({
  placeId,
  placeName,
  selected,
  disabled,
  onToggle,
  maxNoteId,
}: CompareToggleProps) {
  const label = selected
    ? `${placeName} 비교에서 빼기`
    : `${placeName} 비교에 추가`;
  return (
    <button
      type="button"
      className="button button--secondary compare-toggle"
      aria-label={label}
      aria-pressed={selected}
      aria-describedby={!selected && disabled ? maxNoteId : undefined}
      disabled={!selected && disabled}
      onClick={() => onToggle(placeId)}
    >
      {selected ? "비교에서 빼기" : "비교에 추가"}
    </button>
  );
}
