"use client";

/**
 * IT-DA route table (07-02 Next.js migration).
 *
 * Same paths as the previous react-router SPA; consumed by the App Router
 * host (spa-host.tsx) through BrowserHistoryRouter and by the Vitest suites
 * through createMemoryRouter. Public routes are children of AppShell so the
 * journey shell (draft context, stepper, live regions) wraps them exactly as
 * before; internal routes stay outside the public shell.
 */
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";

import { AppShell } from "./AppShell";
import { useLocation, useNavigate, type RouteObject } from "./react-router-dom";
import {
  EvaluatorApiError,
  createProfileReleaseClient,
  type ProfileReleaseBuildDraftReference,
} from "../features/evaluation/api";
import { EvidenceReview } from "../features/evaluation/EvidenceReview";
import { OperatorAdjudication } from "../features/evaluation/OperatorAdjudication";
import {
  ProfileReleaseConsole,
  newNonce,
  sha256Ascii,
  type ProfileReleaseBuildInput,
} from "../features/evaluation/ProfileReleaseConsole";
import { EvaluatorWorkspace } from "../features/evaluation/EvaluatorWorkspace";
import { ComparePage } from "../journey-pages/CompareJourneyPage";
import { PlaceDetailPage } from "../journey-pages/PlaceDetailJourneyPage";
import { PhotoJobRoute, PhotoPage } from "../journey-pages/PhotoJourneyPage";
import { DailyGlmDashboard } from "../features/operations/daily-glm/DailyGlmDashboard";
import { ProfilePage } from "../journey-pages/ProfileJourneyPage";
import { RecommendationsPage } from "../journey-pages/RecommendationsJourneyPage";
import { StartPage } from "../journey-pages/StartJourneyPage";
import { UpstreamMainPage } from "./upstream/UpstreamMainPage";
import { UpstreamQuizPage } from "./upstream/UpstreamQuizPage";
import { UpstreamStartPage } from "./upstream/UpstreamStartPage";

type ProfileReleaseRouteState = {
  buildDraft?: ProfileReleaseBuildDraftReference;
};

export function sanitizeBuildDraft(
  value: unknown,
): ProfileReleaseBuildDraftReference | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.draft_ref !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(candidate.draft_ref) ||
    typeof candidate.expires_at !== "string" ||
    !Number.isFinite(Date.parse(candidate.expires_at)) ||
    typeof candidate.nonce_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(candidate.nonce_sha256)
  ) {
    return undefined;
  }
  return {
    draft_ref: candidate.draft_ref,
    expires_at: candidate.expires_at,
    nonce_sha256: candidate.nonce_sha256,
  };
}

export async function prepareProfileReleaseBuilderRoute(
  buildInput: ProfileReleaseBuildInput,
  fetchImpl?: typeof fetch,
): Promise<{ pathname: string; state: ProfileReleaseRouteState }> {
  const client = createProfileReleaseClient({ fetchImpl });
  let reconciliationNonce = newNonce();
  let draftReference = newDraftReference();
  try {
    const buildDraft = await client.createBuildDraft({
      ...buildInput,
      reconciliation_nonce: reconciliationNonce,
      draft_ref: draftReference,
    });
    if (buildDraft.nonce_sha256 !== (await sha256Ascii(reconciliationNonce))) {
      throw new Error("server build draft nonce binding mismatch");
    }
    return {
      pathname: "/internal/profile-releases/builder",
      state: { buildDraft },
    };
  } finally {
    reconciliationNonce = "";
    draftReference = "";
    client.clear();
  }
}

export function newDraftReference(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function InternalRouteFocus({ children }: { children: ReactNode }) {
  const location = useLocation();
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (root === null) return;
    let frame = 0;
    const focusHeading = () => {
      const heading = root.querySelector<HTMLHeadingElement>("main h1");
      if (heading === null) return false;
      frame = requestAnimationFrame(() => heading.focus());
      return true;
    };
    if (focusHeading()) return () => cancelAnimationFrame(frame);
    const observer = new MutationObserver(() => {
      if (focusHeading()) observer.disconnect();
    });
    observer.observe(root, { childList: true, subtree: true });
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [location.pathname]);

  return <div ref={rootRef}>{children}</div>;
}

function ProfileReleaseBuilderEntry() {
  const navigate = useNavigate();
  const fileRef = useRef<HTMLInputElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const prepare = async (event: FormEvent) => {
    event.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (file === undefined) {
      setError("검토가 끝난 release 후보 JSON 파일을 선택하세요.");
      return;
    }
    setBusy(true);
    setError(null);
    let protectedInput: ProfileReleaseBuildInput | null = null;
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("invalid protected build input");
      }
      protectedInput = parsed as ProfileReleaseBuildInput;
      const prepared = await prepareProfileReleaseBuilderRoute(protectedInput);
      protectedInput = null;
      if (fileRef.current !== null) fileRef.current.value = "";
      setBusy(false);
      navigate(prepared.pathname, { replace: true, state: prepared.state });
    } catch (prepareError) {
      if (
        prepareError instanceof EvaluatorApiError &&
        (prepareError.status === 401 || prepareError.status === 403)
      ) {
        navigate("/internal/access", { replace: true });
        return;
      }
      setError("Release 후보를 보호 draft로 준비하지 못했습니다.");
    } finally {
      protectedInput = null;
      if (fileRef.current !== null) fileRef.current.value = "";
      setBusy(false);
    }
  };

  useEffect(() => {
    if (error === null) return;
    const frame = requestAnimationFrame(() => errorRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [error]);

  return (
    <InternalRouteFocus>
      <main className="evaluator-shell">
        <header className="evaluator-intro">
          <p className="eyebrow">Phase 3 · builder 전용 준비</p>
          <h1 tabIndex={-1}>DEV profile release 후보 준비</h1>
          <p>검토된 후보 파일은 메모리에서 server draft로 바뀐 뒤 즉시 폐기됩니다.</p>
        </header>
        {error ? (
          <p ref={errorRef} role="alert" tabIndex={-1}>
            {error}
          </p>
        ) : null}
        <form onSubmit={prepare}>
          <label htmlFor="profile-release-build-file">검토된 release 후보 JSON</label>
          <input
            accept="application/json,.json"
            id="profile-release-build-file"
            ref={fileRef}
            type="file"
          />
          <button className="button button--primary" disabled={busy} type="submit">
            {busy ? "보호 draft 준비 중" : "보호 draft 준비하기"}
          </button>
        </form>
      </main>
    </InternalRouteFocus>
  );
}

function InternalProtectedRoute({
  children,
}: {
  children: (onAuthorizationLost: () => void) => ReactNode;
}) {
  const navigate = useNavigate();
  const onAuthorizationLost = useCallbackAuthLost(navigate);
  return <InternalRouteFocus>{children(onAuthorizationLost)}</InternalRouteFocus>;
}

function useCallbackAuthLost(navigate: ReturnType<typeof useNavigate>) {
  return () => navigate("/internal/access", { replace: true });
}

function InternalAccessEntry() {
  return (
    <InternalRouteFocus>
      <main className="evaluator-shell evaluator-shell--forbidden">
        <header className="evaluator-intro">
          <p className="eyebrow">IT-DA · 내부 역할 세션</p>
          <h1 tabIndex={-1}>내부 작업 접근 확인</h1>
          <p>이전 역할의 자료는 지워졌습니다. 다시 인증된 내부 작업 링크에서 시작하세요.</p>
        </header>
      </main>
    </InternalRouteFocus>
  );
}

function ProfileReleaseRoute({
  role,
}: {
  role: "builder" | "approver" | "activator";
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const onAuthorizationLost = useCallbackAuthLost(navigate);
  const state = location.state as ProfileReleaseRouteState | null;
  const buildDraft = role === "builder" ? sanitizeBuildDraft(state?.buildDraft) : undefined;
  useEffect(() => {
    const historyState = window.history.state as Record<string, unknown> | null;
    window.history.replaceState(
      {
        ...(historyState ?? {}),
        usr: buildDraft === undefined ? null : { buildDraft },
      },
      "",
      `${location.pathname}${location.search}${location.hash}`,
    );
  }, [buildDraft, location.hash, location.pathname, location.search]);
  if (role === "builder" && buildDraft === undefined) {
    return <ProfileReleaseBuilderEntry />;
  }
  return (
    <InternalRouteFocus>
      <ProfileReleaseConsole
        buildDraft={buildDraft}
        onAuthorizationLost={onAuthorizationLost}
        role={role}
      />
    </InternalRouteFocus>
  );
}

/**
 * `/start` journey page: keeps the retained StartPage logic (edit-mode
 * profile resubmission) when the user arrives in edit mode, and renders the
 * upstream feature-chooser + travel-conditions surface otherwise.
 */
function UpstreamStartJourney() {
  const location = useLocation();
  const editMode = new URLSearchParams(location.search).get("mode") === "edit";
  return editMode ? <StartPage /> : <UpstreamStartPage />;
}

/**
 * `/profile` keeps the retained journey page: it renders the profile result
 * from the server profile with the upstream result vocabulary inside the
 * journey shell (stepper, live regions). Tests pin this behavior.
 */
function ProfileRouteSwitch() {
  return <ProfilePage />;
}

export const appRoutes: RouteObject[] = [
  {
    path: "/internal/evaluator/assignments/:assignmentId",
    element: (
      <InternalProtectedRoute>
        {(onAuthorizationLost) => (
          <EvaluatorWorkspace onAuthorizationLost={onAuthorizationLost} />
        )}
      </InternalProtectedRoute>
    ),
  },
  {
    path: "/internal/operator/assignments/:assignmentId",
    element: (
      <InternalProtectedRoute>
        {(onAuthorizationLost) => (
          <OperatorAdjudication
            onAuthorizationLost={onAuthorizationLost}
            role="operator"
          />
        )}
      </InternalProtectedRoute>
    ),
  },
  {
    path: "/internal/adjudicator/assignments/:assignmentId",
    element: (
      <InternalProtectedRoute>
        {(onAuthorizationLost) => (
          <OperatorAdjudication
            onAuthorizationLost={onAuthorizationLost}
            role="adjudicator"
          />
        )}
      </InternalProtectedRoute>
    ),
  },
  {
    path: "/internal/profile-releases/builder/evidence-review",
    element: (
      <InternalProtectedRoute>
        {(onAuthorizationLost) => (
          <EvidenceReview onAuthorizationLost={onAuthorizationLost} />
        )}
      </InternalProtectedRoute>
    ),
  },
  {
    path: "/internal/access",
    element: <InternalAccessEntry />,
  },
  {
    path: "/internal/operations/daily-glm",
    element: (
      <InternalRouteFocus>
        <DailyGlmDashboard />
      </InternalRouteFocus>
    ),
  },
  {
    path: "/internal/profile-releases/builder",
    element: <ProfileReleaseRoute role="builder" />,
  },
  {
    path: "/internal/profile-releases/approver",
    element: <ProfileReleaseRoute role="approver" />,
  },
  {
    path: "/internal/profile-releases/activator",
    element: <ProfileReleaseRoute role="activator" />,
  },
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <UpstreamMainPage /> },
      { path: "start", element: <UpstreamStartJourney /> },
      { path: "quiz", element: <UpstreamQuizPage /> },
      { path: "profile", element: <ProfilePage /> },
      { path: "photo", element: <PhotoPage /> },
      { path: "photo/jobs/:jobId", element: <PhotoJobRoute /> },
      { path: "photo/jobs/:jobId/review", element: <PhotoJobRoute /> },
      { path: "recommendations/:runId", element: <RecommendationsPage /> },
      { path: "recommendations/:runId/places/:placeId", element: <PlaceDetailPage /> },
      { path: "recommendations/:runId/compare", element: <ComparePage /> },
    ],
  },
];
