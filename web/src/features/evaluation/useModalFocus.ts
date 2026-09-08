import { useLayoutEffect, useRef, type KeyboardEvent, type RefObject } from "react";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not(:disabled)",
  "input:not(:disabled)",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

export function useModalFocus<T extends HTMLElement>({
  busy = false,
  onCancel,
  returnFocusRef,
}: {
  busy?: boolean;
  onCancel: () => void;
  returnFocusRef?: RefObject<HTMLElement | null>;
}) {
  const dialogRef = useRef<T>(null);
  const safeRef = useRef<HTMLButtonElement>(null);
  const invokingElementRef = useRef<HTMLElement | null>(null);

  useLayoutEffect(() => {
    invokingElementRef.current =
      returnFocusRef?.current ??
      (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    safeRef.current?.focus();
  }, [returnFocusRef]);

  useLayoutEffect(() => {
    if (busy) dialogRef.current?.focus();
  }, [busy]);

  const restoreFocus = () => {
    const returnTarget = returnFocusRef?.current ?? invokingElementRef.current;
    if (!returnTarget?.isConnected) return;
    returnTarget.focus();
    requestAnimationFrame(() => {
      if (returnTarget.isConnected) returnTarget.focus();
    });
  };

  const cancelAndRestore = () => {
    onCancel();
    restoreFocus();
  };

  const onKeyDown = (event: KeyboardEvent<T>) => {
    if (event.key === "Escape") {
      if (!busy) {
        event.preventDefault();
        cancelAndRestore();
      }
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ?? [],
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) {
      event.preventDefault();
      dialogRef.current?.focus();
      return;
    }
    const activeElement = document.activeElement;
    const activeElementIsUntabbableDialogContent =
      activeElement instanceof HTMLElement &&
      dialogRef.current?.contains(activeElement) === true &&
      !focusable.includes(activeElement);
    if (activeElement === dialogRef.current || activeElementIsUntabbableDialogContent) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
      return;
    }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return { cancelAndRestore, dialogRef, onKeyDown, restoreFocus, safeRef };
}
