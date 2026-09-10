import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Outlet, useLocation } from "./react-router-dom";

import {
  DRAFT_STORAGE_KEY,
  STORAGE_MESSAGES,
  createEmptyDraft,
  readDraft,
  resetJourneyStorage,
  writeDraft,
} from "./storage";
import type { DraftContents, DraftRecord } from "./schemas";
import { resetGroundedTripInput } from "../features/journey/groundedTrip";

export type DraftUiState =
  | "hydrating"
  | "normal"
  | "recovered"
  | "corrupt"
  | "expired"
  | "unavailable"
  | "reset";

type JourneyDraftContextValue = {
  state: DraftUiState;
  draft: DraftRecord | null;
  updateDraft: (patch: Partial<DraftContents>) => DraftRecord;
  resetDraft: () => boolean;
  dismissNotice: () => void;
  reportStorageUnavailable: () => void;
};

const JourneyDraftContext = createContext<JourneyDraftContextValue | null>(null);

export type JourneyAnnouncementContextValue = {
  announcePage: (message: string) => void;
  announceInteraction: (message: string) => void;
};

const JourneyAnnouncementContext =
  createContext<JourneyAnnouncementContextValue | null>(null);

export function useJourneyAnnouncements(): JourneyAnnouncementContextValue | null {
  return useContext(JourneyAnnouncementContext);
}

export function useJourneyDraft(): JourneyDraftContextValue {
  const context = useContext(JourneyDraftContext);
  if (context === null) {
    throw new Error("useJourneyDraft must be used inside AppShell");
  }
  return context;
}

const RESET_NOTICE_DURATION_MS = 4_000;

function noticeForState(state: DraftUiState): string | null {
  if (state === "corrupt" || state === "expired") return STORAGE_MESSAGES.invalid;
  if (state === "unavailable") return STORAGE_MESSAGES.unavailable;
  if (state === "reset") return STORAGE_MESSAGES.reset;
  return null;
}

export function AppShell({ children }: { children?: ReactNode }) {
  const location = useLocation();
  const [state, setState] = useState<DraftUiState>("hydrating");
  const [resetNotice, setResetNotice] = useState<{ expiresAt: number } | null>(null);
  const [draft, setDraft] = useState<DraftRecord | null>(null);
  const [externalDraft, setExternalDraft] = useState<DraftRecord | null>(null);
  const [pageAnnouncement, setPageAnnouncement] = useState("");
  const [interactionAnnouncement, setInteractionAnnouncement] = useState("");
  const initialDraft = useRef<ReturnType<typeof readDraft> | null>(null);
  const hydrated = state !== "hydrating";
  // Quiz query changes advance a question within the same page.
  const focusLocation = location.pathname === "/quiz"
    ? location.pathname
    : `${location.pathname}${location.search}`;

  useEffect(() => {
    initialDraft.current ??= readDraft();
    const result = initialDraft.current;
    setDraft(result.draft);
    setState(result.state === "empty" ? "normal" : result.state);
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    const focusHeading = () => {
      const heading = document.querySelector<HTMLElement>("main h1");
      if (heading === null) return false;
      heading.focus();
      window.scrollTo?.({ top: 0 });
      return true;
    };
    if (focusHeading()) return;
    const observer = new MutationObserver(() => {
      if (focusHeading()) observer.disconnect();
    });
    const main = document.querySelector("main");
    if (main !== null) observer.observe(main, { childList: true, subtree: true });
    return () => {
      observer.disconnect();
    };
  }, [focusLocation, hydrated]);

  useEffect(() => {
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== DRAFT_STORAGE_KEY || event.newValue === null) return;
      const result = readDraft(event.storageArea ?? undefined);
      if (
        result.state === "recovered" &&
        (draft === null || Date.parse(result.draft.updated_at) > Date.parse(draft.updated_at))
      ) {
        setExternalDraft(result.draft);
      }
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, [draft]);

  const updateDraft = useCallback(
    (patch: Partial<DraftContents>) => {
      const current: DraftContents = draft
        ? {
            current_route: draft.current_route,
            current_question: draft.current_question,
            trip_conditions: draft.trip_conditions,
            answers: draft.answers,
          }
        : createEmptyDraft();
      const next: DraftContents = {
        ...current,
        ...patch,
        trip_conditions: patch.trip_conditions ?? current.trip_conditions,
        answers: patch.answers ?? current.answers,
      };
      const result = writeDraft(next);
      setDraft(result.draft);
      setState(result.state === "saved" ? "normal" : "unavailable");
      return result.draft;
    },
    [draft],
  );

  useEffect(() => {
    if (state !== "reset" || resetNotice === null) return;
    const dismissExpired = () => {
      if (Date.now() >= resetNotice.expiresAt) {
        setState((current) => current === "reset" ? "normal" : current);
      }
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") dismissExpired();
    };
    const timer = window.setTimeout(dismissExpired, Math.max(0, resetNotice.expiresAt - Date.now()));
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [resetNotice, state]);

  const resetDraft = useCallback(() => {
    const result = resetJourneyStorage();
    const groundedReset = resetGroundedTripInput();
    const nextState = result.state === "reset" && groundedReset ? "reset" : "unavailable";
    setDraft(null);
    setExternalDraft(null);
    setResetNotice(nextState === "reset" ? { expiresAt: Date.now() + RESET_NOTICE_DURATION_MS } : null);
    setState(nextState);
    return nextState === "reset";
  }, []);

  const dismissNotice = useCallback(() => {
    setState((current) => (current === "recovered" ? "normal" : current));
  }, []);

  const reportStorageUnavailable = useCallback(() => {
    setState("unavailable");
  }, []);

  const context = useMemo(
    () => ({ state, draft, updateDraft, resetDraft, dismissNotice, reportStorageUnavailable }),
    [dismissNotice, draft, reportStorageUnavailable, resetDraft, state, updateDraft],
  );
  const announcementContext = useMemo(
    () => ({
      announcePage: setPageAnnouncement,
      announceInteraction: setInteractionAnnouncement,
    }),
    [],
  );
  const notice = noticeForState(state);

  return (
    <JourneyDraftContext.Provider value={context}>
      <JourneyAnnouncementContext.Provider value={announcementContext}>
        <div className="public-app-shell" data-storage-state={state}>
          {notice ? (
            <p className="public-shell-notice" role="status" aria-live="polite">
              {notice}
            </p>
          ) : null}
          {externalDraft ? (
            <section className="public-shell-notice" aria-labelledby="other-tab-title">
              <p id="other-tab-title">다른 탭의 변경 내용을 불러올까요?</p>
              <div className="public-shell-notice__actions">
                <button
                  type="button"
                  onClick={() => {
                    setDraft(externalDraft);
                    setState("recovered");
                    setExternalDraft(null);
                  }}
                >
                  불러오기
                </button>
                <button type="button" onClick={() => setExternalDraft(null)}>
                  현재 내용 유지
                </button>
              </div>
            </section>
          ) : null}
          {state === "hydrating" ? (
            <main id="main-content" className="public-hydration-state" aria-label="저장된 여행 내용 불러오는 중" />
          ) : (
            (children ?? <Outlet />)
          )}
          <p
            className="visually-hidden"
            data-journey-live-region="page"
            aria-label="페이지 상태 알림"
            aria-live="polite"
            aria-atomic="true"
          >
            {pageAnnouncement}
          </p>
          <p
            className="visually-hidden"
            data-journey-live-region="interaction"
            aria-label="저장 및 비교 알림"
            aria-live="polite"
            aria-atomic="true"
          >
            {interactionAnnouncement}
          </p>
        </div>
      </JourneyAnnouncementContext.Provider>
    </JourneyDraftContext.Provider>
  );
}
