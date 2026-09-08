import type { ReactNode } from "react";

/**
 * Action bar for the photo flow: mobile sticky above the safe area, inline on
 * desktop via the existing `.start-action-bar` responsive rules. Children are
 * rendered in DOM order; the no-photo continuation always stays reachable.
 */
export function PhotoActionBar({ children }: { children: ReactNode }) {
  return <div className="start-action-bar">{children}</div>;
}
