import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  ApiRequestError,
  fetchPreferenceProfile,
  type PreferenceProfile,
} from "../api/api";
import { FRONTEND_QUESTIONNAIRE } from "../content/questionnaire";
import type { QuestionnaireDefinition } from "../api/api";
import { useJourneyDraft } from "../app/AppShell";
import { useLocation, useNavigate } from "../app/react-router-dom";
import { questionnaireAnswersSchema, tripConditionsSchema } from "../app/schemas";
import { readProfileReference } from "../app/storage";
import { pickResultForProfile } from "../app/upstream/resultProjection";
import { quizNavigationState } from "../features/journey/quizNavigation";
import { ScenarioRecommendationCTA } from "../features/authenticity/ScenarioRecommendationCTA";
import { ProfileRecoveryState } from "../features/profile/ProfileRecoveryState";
import { ResetDraftDialog } from "../features/profile/ResetDraftDialog";
import { ThreeAxisProfile } from "../features/profile/ThreeAxisProfile";
import { PhotoMoodIntro } from "../features/profile/PhotoMoodIntro";
import { ProfileStoryButton } from "../features/profile/ProfileStoryButton";
import { createAndStorePreferenceProfile } from "../features/profile/profileSubmission";

type PageState = "loading" | "ready" | "empty" | "recovery" | "api-error" | "invalid";

function ProfileShell({ children }: { children: ReactNode }) {
  return (
    <div className="up-root">
      <div className="up-quiz" data-upstream-surface="profile">
        <header className="topbar">
          <a className="brand" href="/"><img className="brand-mark-image" src="/itda-logo-icon.png" alt="" /><strong className="brand-wordmark">IT-DA</strong></a>
          <nav>
            <a href="/#type">유형 보기</a>
            <a href="/start">다시 테스트</a>
            <a href="/">홈</a>
          </nav>
        </header>
        <main>{children}</main>
      </div>
    </div>
  );
}

export function ProfilePage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { draft, updateDraft, resetDraft, reportStorageUnavailable } = useJourneyDraft();
  const navigationState = location.state as {
    announcement?: string;
    focusProfile?: boolean;
  } | null;
  const [state, setState] = useState<PageState>("loading");
  const [profile, setProfile] = useState<PreferenceProfile | null>(null);
  const [upstreamContract, setUpstreamContract] = useState<QuestionnaireDefinition | null>(
    FRONTEND_QUESTIONNAIRE,
  );
  const [busy, setBusy] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [announcement, setAnnouncement] = useState(
    navigationState?.announcement ?? "",
  );
  const [retryKind, setRetryKind] = useState<"fetch" | "rebuild">("fetch");
  const profileIdRef = useRef<string | null>(null);
  const ctaRef = useRef<HTMLDivElement | null>(null);
  const meterHeadingRef = useRef<HTMLHeadingElement>(null);
  const stateHeadingRef = useRef<HTMLHeadingElement>(null);
  const resetTriggerRef = useRef<HTMLButtonElement>(null);
  const activeLoadRef = useRef<AbortController | null>(null);
  const draftRef = useRef(draft);
  const focusAfterHydrationRef = useRef(navigationState?.focusProfile === true);
  draftRef.current = draft;

  const completeTrip = tripConditionsSchema.safeParse(draft?.trip_conditions);
  const completeAnswers = questionnaireAnswersSchema.safeParse(draft?.answers);
  const hasCompleteDraft = completeTrip.success && completeAnswers.success;

  const readCompleteDraft = () => {
    const trip = tripConditionsSchema.safeParse(draftRef.current?.trip_conditions);
    const questionnaireAnswers = questionnaireAnswersSchema.safeParse(draftRef.current?.answers);
    return trip.success && questionnaireAnswers.success
      ? { tripConditions: trip.data, answers: questionnaireAnswers.data }
      : null;
  };

  const showProfile = (
    nextProfile: PreferenceProfile,
    options: { message?: string; restoreDraft?: boolean; focusMeter?: boolean } = {},
  ) => {
    setProfile(nextProfile);
    // Result visuals and answer labels use the frontend presentation; scores stay server-owned.
    setUpstreamContract(FRONTEND_QUESTIONNAIRE);
    // Drafts are v2-only: a restored draft must carry answers that parse under
    // the current questionnaire generation. Legacy v1 profiles stay displayed
    // (scores, description, CTA) but never seed a v2 draft.
    const restoreableAnswers = questionnaireAnswersSchema.safeParse(nextProfile.answers);
    if (options.restoreDraft && restoreableAnswers.success) {
      updateDraft({
        current_route: "/profile",
        trip_conditions: nextProfile.trip_conditions,
        answers: restoreableAnswers.data,
      });
    }
    setState("ready");
    if (options.message) setAnnouncement(options.message);
    if (options.focusMeter) {
      window.setTimeout(() => meterHeadingRef.current?.focus(), 0);
    }
  };

  const loadProfile = async (profileId: string) => {
    activeLoadRef.current?.abort();
    const controller = new AbortController();
    activeLoadRef.current = controller;
    setState("loading");
    setRetryKind("fetch");
    try {
      const nextProfile = await fetchPreferenceProfile(profileId, { signal: controller.signal });
      if (controller.signal.aborted || activeLoadRef.current !== controller) return;
      // The draft echo/rebuild comparison applies only to current-generation
      // (questionnaire-v2) profiles; a legacy v1 profile has no comparable v2
      // draft and must not be forced through the rebuild path.
      const isCurrentProfile = questionnaireAnswersSchema.safeParse(nextProfile.answers).success;
      const currentDraft = readCompleteDraft();
      if (
        isCurrentProfile &&
        currentDraft !== null &&
        (JSON.stringify(currentDraft.tripConditions) !== JSON.stringify(tripConditionsSchema.parse(nextProfile.trip_conditions)) ||
          JSON.stringify(currentDraft.answers) !== JSON.stringify(questionnaireAnswersSchema.parse(nextProfile.answers)))
      ) {
        setProfile(null);
        setState("recovery");
        setRetryKind("rebuild");
        return;
      }
      const focusMeter = focusAfterHydrationRef.current;
      focusAfterHydrationRef.current = false;
      showProfile(nextProfile, { restoreDraft: currentDraft === null, focusMeter });
    } catch (error) {
      if (controller.signal.aborted || activeLoadRef.current !== controller) return;
      if (error instanceof ApiRequestError && error.status === 404) {
        setState(readCompleteDraft() === null ? "empty" : "recovery");
      } else if (error instanceof ApiRequestError && error.message === "프로필 형식을 확인하지 못했어요.") {
        setState("invalid");
      } else {
        setState("api-error");
      }
    } finally {
      if (activeLoadRef.current === controller) activeLoadRef.current = null;
    }
  };

  useEffect(() => {
    const cancelActiveLoad = () => {
      activeLoadRef.current?.abort();
      activeLoadRef.current = null;
    };
    const reference = readProfileReference();
    const storedProfile = reference.profile;
    if (storedProfile === null) {
      setState(hasCompleteDraft ? "recovery" : "empty");
      return cancelActiveLoad;
    }
    profileIdRef.current = storedProfile.profile_id;
    void loadProfile(storedProfile.profile_id);
    return cancelActiveLoad;
  }, []);

  useEffect(() => {
    if (state === "recovery" || state === "empty" || state === "api-error" || state === "invalid") {
      window.setTimeout(() => stateHeadingRef.current?.focus(), 0);
    }
  }, [state]);

  const rebuild = async () => {
    if (!completeTrip.success || !completeAnswers.success || busy) return;
    setBusy(true);
    setRetryKind("rebuild");
    try {
      const result = await createAndStorePreferenceProfile(completeTrip.data, completeAnswers.data);
      profileIdRef.current = result.profile.profile_id;
      showProfile(result.profile, {
        message: "기대 프로필을 다시 만들었어요.",
        focusMeter: true,
      });
      if (result.reference?.state === "memory-fallback") reportStorageUnavailable();
    } catch {
      setState("api-error");
      setAnnouncement("");
    } finally {
      setBusy(false);
    }
  };

  const retry = () => {
    if (retryKind === "rebuild") void rebuild();
    else if (profileIdRef.current) void loadProfile(profileIdRef.current);
  };

  const upstreamResult = useMemo(
    () =>
      profile !== null && upstreamContract !== null
        ? pickResultForProfile(upstreamContract, profile)
        : null,
    [profile, upstreamContract],
  );

  if (state === "loading") {
    return (
      <ProfileShell>
        <article className="panel profile-state" aria-labelledby="profile-loading-title">
          <p className="eyebrow">이번 여행의 기대 프로필</p>
          <h1 id="profile-loading-title" tabIndex={-1}>당신이 기대하는 여행의 시간</h1>
          <div className="profile-loading" aria-hidden="true"><span /><span /><span /></div>
          <p role="status" aria-live="polite">여행 기대를 정리하고 있어요.</p>
        </article>
      </ProfileShell>
    );
  }

  if (state !== "ready" || profile === null) {
    const recoveryState = state === "ready" ? "invalid" : state;
    return (
      <ProfileShell>
        <ProfileRecoveryState
          state={recoveryState}
          busy={busy}
          headingRef={stateHeadingRef}
          onPrimary={
            state === "empty"
              ? () => void navigate("/start")
              : state === "recovery"
                ? () => void rebuild()
                : retry
          }
          onReviewAnswers={state === "api-error" && hasCompleteDraft ? () => void navigate("/quiz", { state: quizNavigationState(1) }) : undefined}
        />
      </ProfileShell>
    );
  }

  return (
    <ProfileShell>
      <section className="panel result visible profile-result" aria-labelledby="profile-result-heading">
        <p className="eyebrow">Result</p>
        <div className="profile-authenticity-intro">
          <h1 id="profile-result-heading" tabIndex={-1}>여행에서의 진짜다움(진정성)이란?</h1>
          <p>
            관광에서 말하는 진짜다움은 단순히 ‘진짜인지 가짜인지’를 판단하는 것이 아닙니다.
            같은 장소를 방문하더라도 무엇을 중요하게 바라보고 어떤 의미를 부여하느냐에 따라,
            그 장소에서 느끼는 진짜다움은 사람마다 다를 수 있습니다.
          </p>
        </div>
        <p className="visually-hidden" role="status" aria-live="polite">{announcement}</p>
        {upstreamResult !== null ? (
          <>
            <div className="result-hero">
              <div className={`type-badge ${upstreamResult.badgeClass}`}>
                <b>{upstreamResult.name}</b>
                <p>{upstreamResult.description}</p>
              </div>
              <div className="character-stage">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={upstreamResult.image} alt={`${upstreamResult.character} 캐릭터 이미지`} />
              </div>
              <div className="match-card">
                <div className="character-card">
                  <span>{upstreamResult.role.split("|")[0]!.trim()} | {upstreamResult.axisLabel}</span>
                  <b>{upstreamResult.character}</b>
                  <p>{upstreamResult.lens}</p>
                </div>
              </div>
            </div>
            <div className="keyword-list">
              {upstreamResult.keywords.map((keyword) => <span key={keyword}>{keyword}</span>)}
            </div>
            <div className="recommend-box">{upstreamResult.recommend}</div>
          </>
        ) : null}

        <section className="profile-support-grid" aria-label="세부 취향 결과">
          <ThreeAxisProfile scores={profile.scores} headingRef={meterHeadingRef} tieBreak={upstreamContract?.axis_tie_break} />
        </section>

        <div className="result-actions profile-actions profile-primary-action profile-actions--primary" ref={ctaRef}>
          {upstreamContract !== null ? <ProfileStoryButton profile={profile} questionnaire={upstreamContract} /> : null}
          <button ref={resetTriggerRef} type="button" className="control" onClick={() => setDialogOpen(true)}>테스트 다시하기</button>
          <ScenarioRecommendationCTA profile={profile} />
        </div>
      </section>
      <PhotoMoodIntro onOpenPhoto={() => void navigate("/photo")} />
      <ResetDraftDialog
        open={dialogOpen}
        triggerRef={resetTriggerRef}
        onClose={() => setDialogOpen(false)}
        onConfirm={() => {
          const succeeded = resetDraft();
          if (succeeded) void navigate("/start", { state: { announcement: "저장된 여행 내용을 지웠어요." } });
          return succeeded;
        }}
      />
    </ProfileShell>
  );
}
