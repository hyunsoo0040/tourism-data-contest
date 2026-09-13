import { useEffect, useRef, useState } from "react";

import { fetchPreferenceProfile, type PreferenceProfile } from "../api/api";
import { useNavigate, useParams } from "../app/react-router-dom";
import { clearPhotoDraft, readProfileReference } from "../app/storage";
import { PhotoPreferenceFlow } from "../features/photo/PhotoPreferenceFlow";
import { PHOTO_FALLBACK_COPY } from "../features/photo/PhotoJobStatus";
import { ProfileRecommendationCTA } from "../features/profile/ProfileRecommendationCTA";
import {
  clearConfirmedPhotoReference,
  readConfirmedMoodReference,
  writeConfirmedMoodReference,
} from "../features/photo/photoProjection";
import {
  confirmPhotoJobTraitsRequest,
  confirmPhotoJobMoodsRequest,
  createPhotoJobRequest,
  getPhotoJobRequest,
  getPhotoJobTraitsRequest,
  getPhotoJobMoodsRequest,
  putPhotoJobImageRequest,
  requestPhotoDeletionRequest,
  submitPhotoJobRequest,
} from "../features/photo/photoClient";

/**
 * Optional photo subflow host for /photo, /photo/jobs/:jobId, and
 * /photo/jobs/:jobId/review.
 *
 * Profile identity comes from the server-owned stored profile reference;
 * direct entry with an absent/foreign/malformed reference renders the bounded
 * fallback and never probes other jobs. Route job references are only adopted
 * when they match the session record; everything else stays bounded.
 */

function DirectEntryFallback({ onNoPhoto }: { onNoPhoto: () => void }) {
  return (
    <article className="profile-state" role="status" aria-live="polite" aria-atomic="true">
      <h1 tabIndex={-1}>{PHOTO_FALLBACK_COPY.directEntry}</h1>
      <button
        type="button"
        className="button button--primary"
        style={{ width: "100%", marginTop: "var(--space-md)" }}
        onClick={onNoPhoto}
      >
        사진 없이 추천 5곳 보기
      </button>
    </article>
  );
}

export function PhotoPage() {
  const navigate = useNavigate();
  const params = useParams<{ jobId?: string }>();
  const routeJobId = params.jobId ?? null;
  const [profile, setProfile] = useState<PreferenceProfile | null>(null);
  const [bounded, setBounded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [confirmedPhotoJobId, setConfirmedPhotoJobId] = useState<string | null>(null);
  const headingFocusedRef = useRef(false);
  const profileId = profile?.profile_id ?? null;

  const goNoPhoto = () =>
    void navigate("/profile", { state: { focusProfile: true, autoRecommend: true } });

  useEffect(() => {
    if (!headingFocusedRef.current) {
      headingFocusedRef.current = true;
      const heading = document.querySelector<HTMLElement>("main h1");
      heading?.focus();
    }
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setBounded(false);
    setConfirmedPhotoJobId(null);
    void (async () => {
      // Profile identity is server-owned; without a stored reference the
      // photo subflow cannot start, so direct entry stays bounded.
      const reference = readProfileReferenceSafely();
      if (reference === null) {
        if (active) {
          setBounded(true);
          setLoading(false);
        }
        return;
      }
      try {
        const nextProfile = await fetchPreferenceProfile(reference);
        if (!active) return;
        setProfile(nextProfile);
        const confirmed = readConfirmedMoodReference(nextProfile.profile_id);
        if (routeJobId !== null && confirmed?.photo_job_id === routeJobId) {
          setConfirmedPhotoJobId(routeJobId);
        }
      } catch {
        if (active) setBounded(true);
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [routeJobId]);

  if (loading) {
    return <UpstreamPhotoShell>{null}</UpstreamPhotoShell>;
  }

  if (bounded || profile === null || profileId === null) {
    return (
      <UpstreamPhotoShell>
        <DirectEntryFallback onNoPhoto={goNoPhoto} />
      </UpstreamPhotoShell>
    );
  }

  if (confirmedPhotoJobId !== null) {
    return (
      <UpstreamPhotoShell>
        <section className="profile-state photo-recommendation-ready" id="recommend">
          <p className="eyebrow">Photo Recommendation</p>
          <h2>사진 분위기 분석을 완료했어요</h2>
          <p>확정한 사진 분위기를 반영해 어울리는 여행지 5곳을 추천받을 수 있어요.</p>
          <div className="result-actions">
            <ProfileRecommendationCTA profile={profile} photoJobId={confirmedPhotoJobId} onClearPhoto={() => {
              clearConfirmedPhotoReference(profileId);
              goNoPhoto();
            }} />
          </div>
        </section>
      </UpstreamPhotoShell>
    );
  }

  return (
    <UpstreamPhotoShell>
      <PhotoPreferenceFlow
      key={profileId}
      profileId={profileId}
      startAtConsent={routeJobId === null}
      consentHeadingLevel={2}
      client={{
        createPhotoJob: createPhotoJobRequest as unknown as (input: {
          consent_accepted: boolean;
          consent_version: string;
        }) => Promise<{ job_id: string; state: string }>,
        getPhotoJob: getPhotoJobRequest,
        getPhotoJobTraits: getPhotoJobTraitsRequest,
        getPhotoJobMoods: getPhotoJobMoodsRequest,
        confirmPhotoJobMoods: confirmPhotoJobMoodsRequest,
        requestPhotoDeletion: requestPhotoDeletionRequest as never,
        putPhotoJobImage: putPhotoJobImageRequest,
        submitPhotoJob: submitPhotoJobRequest,
        confirmPhotoJobTraits: confirmPhotoJobTraitsRequest as never,
      }}
      onNoPhoto={() => {
        clearConfirmedPhotoReference(profileId);
        goNoPhoto();
      }}
      onJobCreated={(jobId) => {
        window.history.replaceState(null, "", `/photo/jobs/${encodeURIComponent(jobId)}`);
      }}
      onConfirmed={() => {
        clearConfirmedPhotoReference(profileId);
        clearPhotoDraft();
        goNoPhoto();
      }}
      onMoodConfirmed={(confirmed, jobId) => {
        if (!writeConfirmedMoodReference(profileId, jobId, confirmed.receipt_id)) return;
        clearPhotoDraft();
        setConfirmedPhotoJobId(jobId);
      }}
      />
    </UpstreamPhotoShell>
  );
}

/**
 * Upstream 사진 기능.html shell chrome (upstream hero, notice, and scoped
 * presentation) wrapping the retained /v1-backed photo flow. The flow's
 * consent, upload, polling, trait review, confirm, deletion, and fallback
 * semantics are unchanged; only the visual container is upstream-styled.
 */
function UpstreamPhotoShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="up-root">
      <div className="up-photo" data-upstream-surface="photo">
        <header className="topbar">
          <a className="brand" href="/" aria-label="IT-DA 소개로 이동">
            <img className="brand-mark-image" src="/itda-logo-icon.png" alt="" />
            <strong className="brand-wordmark">IT-DA</strong>
          </a>
          <a className="back-link" href="/profile">취향 결과로 돌아가기</a>
        </header>

        <main>
          <section className="photo-page" aria-labelledby="photo-page-heading">
            <div className="photo-page-panel">
              <header className="photo-intro">
                <p className="eyebrow">Photo Preference</p>
                <h1 id="photo-page-heading">
                  마음에 남은 장면을<br />
                  <span>이번 여행의 힌트로</span>
                </h1>
                <p>
                  직접 찍은 여행 사진 1~3장을 골라 주세요. 대충 무슨 멋있는 멘트
                </p>
                <ul className="photo-format-list" aria-label="사진 입력 요약">
                  <li>선택 입력</li>
                  <li>최대 3장</li>
                  <li>JPEG · PNG · WEBP</li>
                </ul>
              </header>

              <div className="photo-workspace-layout">
                <section className="workspace" id="upload" aria-label="사진 입력 단계">
                  {children ?? (
                    <div className="photo-shell-loading" role="status" aria-live="polite">
                      <span className="photo-shell-loading__icon" aria-hidden="true" />
                      <p>사진 입력 단계를 준비하고 있어요.</p>
                    </div>
                  )}
                </section>

                <aside className="photo-guide" aria-labelledby="photo-guide-heading">
                  <div className="photo-guide__visual" aria-hidden="true">
                    <svg viewBox="0 0 40 40" focusable="false">
                      <path d="M10 13.5h5l2-3h6l2 3h5a4 4 0 0 1 4 4v11a4 4 0 0 1-4 4H10a4 4 0 0 1-4-4v-11a4 4 0 0 1 4-4Z" />
                      <circle cx="20" cy="23" r="6" />
                    </svg>
                  </div>
                  <p className="photo-guide__kicker">한 장이면 충분해요</p>
                  <h2 id="photo-guide-heading">사진은 이렇게 반영돼요</h2>
                  <ol className="photo-guide__steps">
                    <li>
                      <span>1</span>
                      <div><strong>장면 고르기</strong><p>좋아했던 여행의 분위기가 잘 보이는 사진을 선택해요.</p></div>
                    </li>
                    <li>
                      <span>2</span>
                      <div><strong>분위기 확인</strong><p>분석이 제안한 인상 중 마음에 드는 것만 남겨요.</p></div>
                    </li>
                    <li>
                      <span>3</span>
                      <div><strong>추천에 더하기</strong><p>직접 확정한 분위기만 장소 추천에 참고해요.</p></div>
                    </li>
                  </ol>
                  <p className="photo-guide__privacy">
                    사진 입력은 선택 사항이며, 사진 없이도 바로 추천을 이어갈 수 있어요.
                  </p>
                </aside>
              </div>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}

function readProfileReferenceSafely(): string | null {
  try {
    const reference = readProfileReference();
    return reference.state === "valid" ? reference.profile.profile_id : null;
  } catch {
    return null;
  }
}

export function PhotoJobRoute() {
  // /photo/jobs/:jobId and /photo/jobs/:jobId/review share the flow host;
  // the flow itself derives polling/review state from the bounded session
  // record. A route job reference that does not match the record stays
  // bounded (never probes).
  return <PhotoPage />;
}
