import { useEffect, useRef, useState, type RefObject } from "react";

/**
 * Safe-first destructive confirmation for photo deletion. Modal semantics,
 * Tab loop, Escape while idle, focus restoration to the trigger. The busy
 * copy and failure copy follow the frozen contract; the dialog never claims
 * deletion completion itself.
 */

export const DELETE_COPY = {
  trigger: "사진 사용 중단하고 삭제하기",
  heading: "사진 사용을 중단할까요?",
  description:
    "선택한 사진과 이 작업의 분석 제안을 삭제하도록 요청하고, 사진 없이 추천을 계속할 수 있어요. 삭제 확인이 끝나면 완료 상태를 알려드릴게요.",
  safe: "계속 사진 사용하기",
  destructive: "사진 삭제 요청하기",
  busy: "삭제 요청 중…",
  failure:
    "삭제 요청을 확인하지 못했어요. 사진 없이 추천은 계속할 수 있고, 서버의 만료·정리 절차는 별도로 진행돼요.",
} as const;

export function PhotoDeleteDialog({
  open,
  onClose,
  onConfirm,
  triggerRef,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => boolean | Promise<boolean>;
  triggerRef?: RefObject<HTMLButtonElement | null>;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const safeActionRef = useRef<HTMLButtonElement>(null);
  const hasOpenedRef = useRef(false);
  const busyRef = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  busyRef.current = busy;

  // Trigger focus restoration: closing the dialog (cancel, Escape, backdrop,
  // or confirmed success) returns focus to the destructive trigger.
  useEffect(() => {
    if (open) hasOpenedRef.current = true;
    else if (hasOpenedRef.current) {
      triggerRef?.current?.focus();
      hasOpenedRef.current = false;
    }
  }, [open, triggerRef]);

  // Reset the failure state only on the open transition; prop identity
  // changes mid-session must not wipe an in-progress failure report.
  const openRef = useRef(open);
  useEffect(() => {
    if (open && !openRef.current) setFailed(false);
    openRef.current = open;
  }, [open]);

  useEffect(() => {
    if (!open) return;
    safeActionRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const controls =
        dialogRef.current?.querySelectorAll<HTMLElement>("button:not(:disabled)") ?? [];
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (controls.length === 0) return;
      // Full manual cycle: native Tab focus movement is not guaranteed in
      // every environment, so both boundary directions are handled here.
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      } else if (!event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        controls[1]?.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose, open]);

  if (!open) return null;

  const confirm = async () => {
    setBusy(true);
    setFailed(false);
    const succeeded = await onConfirm();
    setBusy(false);
    if (succeeded) onClose();
    else setFailed(true);
  };

  return (
    <div
      className="dialog-backdrop"
      onMouseDown={(event) => {
        if (!busy && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="reset-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="photo-delete-dialog-title"
        aria-describedby="photo-delete-dialog-description"
      >
        <h2 id="photo-delete-dialog-title">{DELETE_COPY.heading}</h2>
        <p id="photo-delete-dialog-description">{DELETE_COPY.description}</p>
        {failed ? (
          <p className="field-error" role="alert">
            {DELETE_COPY.failure}
          </p>
        ) : null}
        <div className="dialog-actions">
          <button
            ref={safeActionRef}
            type="button"
            className="button button--secondary"
            onClick={onClose}
            disabled={busy}
          >
            {DELETE_COPY.safe}
          </button>
          <button
            type="button"
            className="button button--destructive"
            onClick={() => void confirm()}
            disabled={busy}
            aria-busy={busy || undefined}
          >
            {busy ? DELETE_COPY.busy : DELETE_COPY.destructive}
          </button>
        </div>
      </div>
    </div>
  );
}
