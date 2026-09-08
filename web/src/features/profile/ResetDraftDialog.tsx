import { useEffect, useRef, useState, type RefObject } from "react";

export function ResetDraftDialog({
  open,
  onClose,
  onConfirm,
  triggerRef,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => boolean | Promise<boolean>;
  triggerRef: RefObject<HTMLButtonElement | null>;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const safeActionRef = useRef<HTMLButtonElement>(null);
  const hasOpenedRef = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const busyRef = useRef(false);
  busyRef.current = busy;

  useEffect(() => {
    if (!open) return;
    setError(false);
    safeActionRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled)") ?? [];
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose, open]);

  useEffect(() => {
    if (open) hasOpenedRef.current = true;
    else if (hasOpenedRef.current) {
      triggerRef.current?.focus();
      hasOpenedRef.current = false;
    }
  }, [open, triggerRef]);

  if (!open) return null;

  const confirm = async () => {
    setBusy(true);
    setError(false);
    const succeeded = await onConfirm();
    setBusy(false);
    if (succeeded) onClose();
    else setError(true);
  };

  return (
    <div className="dialog-backdrop" onMouseDown={(event) => { if (!busy && event.target === event.currentTarget) onClose(); }}>
      <div ref={dialogRef} className="reset-dialog" role="dialog" aria-modal="true" aria-labelledby="reset-dialog-title" aria-describedby="reset-dialog-description">
        <h2 id="reset-dialog-title">작성한 내용을 지울까요?</h2>
        <p id="reset-dialog-description">작성 중인 답변과 이번 여행 기대 프로필이 이 브라우저에서 삭제됩니다. 이 작업은 되돌릴 수 없어요.</p>
        {error ? <p className="field-error" role="alert">저장 내용을 모두 지우지 못했어요. 브라우저 저장 설정을 확인해 주세요.</p> : null}
        <div className="dialog-actions">
          <button ref={safeActionRef} type="button" className="button button--secondary" onClick={onClose} disabled={busy}>계속 작성하기</button>
          <button type="button" className="button button--destructive" onClick={() => void confirm()} disabled={busy} aria-busy={busy || undefined}>
            {busy ? "지우는 중…" : "모두 지우고 새로 시작하기"}
          </button>
        </div>
      </div>
    </div>
  );
}
