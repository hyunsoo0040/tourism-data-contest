type StickyActionBarProps = {
  primaryLabel: string;
  onPrimary: () => void;
  secondaryLabel: string;
  onSecondary: () => void;
  primaryDisabled?: boolean;
  busy?: boolean;
};

export function StickyActionBar({
  primaryLabel,
  onPrimary,
  secondaryLabel,
  onSecondary,
  primaryDisabled = false,
  busy = false,
}: StickyActionBarProps) {
  return (
    <div
      className="start-action-bar"
      style={{
        position: "sticky",
        bottom: 0,
        display: "flex",
        flexWrap: "wrap",
        gap: "var(--space-sm)",
        marginTop: "var(--space-lg)",
        paddingBlock: "var(--space-md)",
        paddingBottom: "calc(var(--space-md) + env(safe-area-inset-bottom))",
        borderTop: "1px solid var(--line)",
        background: "var(--surface)",
      }}
    >
      <button
        type="button"
        className="button button--secondary"
        onClick={onSecondary}
        disabled={busy}
      >
        {secondaryLabel}
      </button>
      <button
        type="button"
        className="button button--primary"
        onClick={onPrimary}
        disabled={primaryDisabled || busy}
        aria-busy={busy || undefined}
      >
        {primaryLabel}
      </button>
    </div>
  );
}
