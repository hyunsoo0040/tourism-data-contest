import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  ApiRequestError,
  fetchPreferenceProfile,
  type PreferenceProfile,
} from "../api/api";
import questionnaireArtifact from "../../../contracts/questionnaire-v2.json";
import type { QuestionnaireDefinition } from "../api/api";
import { useJourneyDraft } from "../app/AppShell";
import { useLocation, useNavigate } from "../app/react-router-dom";
import { questionnaireAnswersSchema, tripConditionsSchema } from "../app/schemas";
import { clearPhotoDraft, readPhotoDraft, readProfileReference } from "../app/storage";
import { pickResultForProfile } from "../app/upstream/resultProjection";
import { PhotoPreferenceFlow } from "../features/photo/PhotoPreferenceFlow";
import {
  confirmPhotoJobTraitsRequest,
  createPhotoJobRequest,
  getPhotoJobRequest,
  getPhotoJobTraitsRequest,
  putPhotoJobImageRequest,
  requestPhotoDeletionRequest,
  submitPhotoJobRequest,
} from "../features/photo/photoClient";
import { CalculationDetails } from "../features/profile/CalculationDetails";
import { InputSummary } from "../features/profile/InputSummary";
import { ProfileNarrative } from "../features/profile/ProfileNarrative";
import { ProfileRecommendationCTA } from "../features/profile/ProfileRecommendationCTA";
import { ProfileRecoveryState } from "../features/profile/ProfileRecoveryState";
import { ResetDraftDialog } from "../features/profile/ResetDraftDialog";
import { ThreeAxisProfile } from "../features/profile/ThreeAxisProfile";
import { createAndStorePreferenceProfile } from "../features/profile/profileSubmission";
import {
  clearConfirmedPhotoReference,
  readConfirmedPhotoReference,
  writeConfirmedPhotoReference,
} from "../features/photo/photoProjection";

type PageState = "loading" | "ready" | "empty" | "recovery" | "api-error" | "invalid";

function ProfileShell({ children }: { children: ReactNode }) {
  return (
    <div className="up-root">
      <div className="up-quiz" data-upstream-surface="profile">
        <header className="topbar">
          <a className="brand" href="/"><span>잇</span>IT-DA</a>
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
    autoRecommend?: boolean;
    openPhotoPanel?: boolean;
  } | null;
  const [state, setState] = useState<PageState>("loading");
  const [profile, setProfile] = useState<PreferenceProfile | null>(null);
  const [upstreamContract, setUpstreamContract] = useState<QuestionnaireDefinition | null>(
    questionnaireArtifact as unknown as QuestionnaireDefinition,
  );
  const [busy, setBusy] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [announcement, setAnnouncement] = useState(
    navigationState?.announcement ?? "",
  );
  const [retryKind, setRetryKind] = useState<"fetch" | "rebuild">("fetch");
  const [photoPanelOpen, setPhotoPanelOpen] = useState(
    navigationState?.openPhotoPanel === true,
  );
  const [confirmedPhotoJobId, setConfirmedPhotoJobId] = useState<string | null>(null);
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
    setConfirmedPhotoJobId(readConfirmedPhotoReference(nextProfile.profile_id));
    const photoDraft = readPhotoDraft(nextProfile.profile_id);
    if (
      photoDraft.state === "valid" ||
      (photoDraft.state === "unavailable" && photoDraft.record !== null)
    ) {
      setPhotoPanelOpen(true);
    }
    // The upstream result shell (type badge, character, keywords) projects the
    // stored profile through the canonical contract copy. The committed v2
    // artifact is byte-identical to the served contract (07-01 contract tests
    // pin this), so the shell derives from the same authority without an
    // extra request.
    setUpstreamContract(questionnaireArtifact as unknown as QuestionnaireDefinition);
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
        (JSON.stringify(currentDraft.tripConditions) !== JSON.stringify(nextProfile.trip_conditions) ||
          JSON.stringify(currentDraft.answers) !== JSON.stringify(nextProfile.answers))
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

  useEffect(() => {
    if (state !== "ready" || navigationState?.autoRecommend !== true || profile === null) return;
    let attempts = 0;
    const clickWhenReady = () => {
      const button = ctaRef.current?.querySelector<HTMLButtonElement>("button.button--primary");
      if (button !== undefined && button !== null && !button.disabled) {
        button.click();
        return;
      }
      attempts += 1;
      if (attempts < 100) window.setTimeout(clickWhenReady, 25);
    };
    const timer = window.setTimeout(clickWhenReady, 0);
    return () => window.clearTimeout(timer);
  }, [state, navigationState?.autoRecommend, profile]);

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
          <h1 id="profile-loading-title" tabIndex={-1}>당신이 기대하는 경주의 시간</h1>
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
          onReviewAnswers={state === "api-error" && hasCompleteDraft ? () => void navigate("/quiz?q=1") : undefined}
        />
      </ProfileShell>
    );
  }

  const editQuestion = (ordinal: number) => {
    // Legacy v1 answers can never re-enter the v2 quiz flow: editing starts a
    // fresh v2 questionnaire. Trip conditions are generation-independent and
    // stay; only the v1 answers are dropped, never re-submitted.
    const isCurrentProfile = profile !== null && questionnaireAnswersSchema.safeParse(profile.answers).success;
    if (isCurrentProfile) {
      updateDraft({ current_route: "/quiz", current_question: ordinal });
      void navigate(`/quiz?q=${ordinal}`, { state: { editingProfile: true } });
      return;
    }
    resetDraft();
    const conditions = tripConditionsSchema.safeParse(profile?.trip_conditions);
    if (conditions.success) {
      updateDraft({
        current_route: "/quiz",
        current_question: ordinal,
        trip_conditions: conditions.data,
      });
    }
    void navigate(`/quiz?q=${ordinal}`);
  };

  return (
    <ProfileShell>
      <section className="panel result visible profile-result" aria-labelledby="profile-result-heading">
        <p className="eyebrow">Result</p>
        <h1 id="profile-result-heading" tabIndex={-1}>당신이 기대하는 경주의 시간</h1>
        <p className="profile-scope">이 결과는 평소 성격이나 여행 만족도를 예측하지 않아요. 지금 입력한 여행 조건과 답변을 정리한 값이에요.</p>
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
                <b>{upstreamResult.match}%</b>
                <span>대표 유형 적합도</span>
                <div className="character-card">
                  <span>{upstreamResult.role}</span>
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
          <ThreeAxisProfile scores={profile.scores} headingRef={meterHeadingRef} />
          <ProfileNarrative description={profile.description_ko} />
          <InputSummary
            profile={profile}
            onEditTrip={() => {
              updateDraft({ current_route: "/start" });
              void navigate("/start?mode=edit");
            }}
            onEditQuestion={editQuestion}
          />
          <CalculationDetails profile={profile} />
        </section>

        <div className="result-actions profile-primary-action" ref={ctaRef}>
          <ProfileRecommendationCTA profile={profile} photoJobId={confirmedPhotoJobId} />
        </div>

        <details
          className="profile-photo-panel"
          open={photoPanelOpen}
          onToggle={(event) => setPhotoPanelOpen(event.currentTarget.open)}
        >
          <summary>
            <span><b>사진으로 더 정확하게</b> <small>선택 사항</small></span>
            <span aria-hidden="true">+</span>
          </summary>
          <div className="profile-photo-panel__body">
            <p>좋아했던 여행 사진 1–3장으로 원하는 분위기를 보강할 수 있어요. 사진 없이도 바로 추천을 볼 수 있습니다.</p>
            <PhotoPreferenceFlow
              profileId={profile.profile_id}
              startAtConsent
              consentHeadingLevel={2}
              client={{
                createPhotoJob: createPhotoJobRequest as unknown as (input: {
                  consent_accepted: boolean;
                  consent_version: string;
                }) => Promise<{ job_id: string; state: string }>,
                getPhotoJob: getPhotoJobRequest,
                getPhotoJobTraits: getPhotoJobTraitsRequest,
                requestPhotoDeletion: requestPhotoDeletionRequest as never,
                putPhotoJobImage: putPhotoJobImageRequest,
                submitPhotoJob: submitPhotoJobRequest,
                confirmPhotoJobTraits: confirmPhotoJobTraitsRequest as never,
              }}
              onNoPhoto={() => {
                setConfirmedPhotoJobId(null);
                clearConfirmedPhotoReference(profile.profile_id);
                setPhotoPanelOpen(false);
              }}
              onConfirmed={(confirmed, jobId) => {
                if (
                  confirmed.length === 0 ||
                  !writeConfirmedPhotoReference(profile.profile_id, jobId)
                ) return;
                setConfirmedPhotoJobId(jobId);
                clearPhotoDraft();
                setPhotoPanelOpen(false);
                setAnnouncement(`사진 취향 ${confirmed.length}개를 추천에 반영할 준비가 됐어요.`);
              }}
            />
          </div>
        </details>

        <div className="result-actions profile-actions">
          <button type="button" className="control" onClick={() => editQuestion(1)}>답변 수정하기</button>
          <button type="button" className="control" onClick={() => void navigate("/start?mode=edit")}>여행 조건 수정하기</button>
          <button ref={resetTriggerRef} type="button" className="control" onClick={() => setDialogOpen(true)}>처음부터 다시</button>
        </div>
      </section>
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
