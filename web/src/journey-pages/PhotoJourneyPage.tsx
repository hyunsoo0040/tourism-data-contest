import { useEffect, useRef, useState } from "react";

import { fetchPreferenceProfile, type PreferenceProfile } from "../api/api";
import { useNavigate, useParams } from "../app/react-router-dom";
import { clearPhotoDraft, readProfileReference } from "../app/storage";
import { PhotoPreferenceFlow } from "../features/photo/PhotoPreferenceFlow";
import { PHOTO_FALLBACK_COPY } from "../features/photo/PhotoJobStatus";
import { ProfileRecommendationCTA } from "../features/profile/ProfileRecommendationCTA";
import {
  clearConfirmedPhotoReference,
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
            <ProfileRecommendationCTA profile={profile} photoJobId={confirmedPhotoJobId} />
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
          <a className="brand" href="/"><img className="brand-mark-image" src="/itda-logo-icon.png" alt="" /><strong className="brand-wordmark">IT-DA</strong></a>
          <nav>
            <a href="#upload">사진 업로드</a>
            <a href="#recommend">유사 분위기 추천</a>
            <a href="/">메인으로</a>
          </nav>
          <div className="source-pill">KTO 관광사진·공모전 수상작 활용</div>
        </header>
        <main>
          <section className="hero">
            <div>
              <p className="eyebrow">Photo Mood Input</p>
              <h1>좋아했던 여행 사진으로<br />분위기를 입력하세요</h1>
              <p>
                취향 테스트만으로 표현하기 어려운 색감, 밝기, 여백, 자연감, 도시감 같은 감각을 사진으로 보완합니다.
                사진은 경험 유형을 판정하는 기준이 아니라, 원하는 분위기를 더 쉽게 알려주는 보조 입력입니다.
              </p>
            </div>
            <div className="notice">
              <b>추천 방식</b>
              업로드한 이미지는 화면 안에서 미리보기와 분위기 신호로만 사용됩니다. 실제 서비스에서는 한국관광공사 관광사진 및 공모전 수상작 자료와 비교해 유사한 분위기의 장소를 제안하는 구조로 확장할 수 있습니다.
            </div>
          </section>
          <section className="workspace" id="upload">
            {children}
          </section>
        </main>
        <nav className="mobile-tabs" aria-label="모바일 사진 입력 이동">
          <a href="#upload">입력</a>
          <a href="#recommend">추천</a>
          <a href="/quiz">테스트</a>
          <a href="/">홈</a>
        </nav>
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
