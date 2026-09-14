import { useEffect, useRef, useState } from "react";
import type { PreferenceProfile } from "../../api/api";
import { useNavigate } from "../../app/react-router-dom";
import { travelRegionName, useTravelRegions } from "../../api/recommendation-regions";
import { readGroundedTripInput } from "../journey/groundedTrip";
import { JourneyError } from "./api";
import { RecommendationProgress, type RecommendationProgressState } from "./RecommendationProgress";
import { readScenarioPhoto, recommendScenario, scenarioResultsPath, writeScenarioPhoto } from "./scenario";

export function ScenarioRecommendationCTA({ profile, withoutPhoto = false }: { profile: PreferenceProfile; withoutPhoto?: boolean }) {
  const navigate = useNavigate();
  const regionCode = readGroundedTripInput().region_code;
  const regions = useTravelRegions(regionCode != null);
  const [photo, setPhoto] = useState(() => withoutPhoto ? null : readScenarioPhoto(profile.profile_id));
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<RecommendationProgressState | null>(null);
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    setPhoto(withoutPhoto ? null : readScenarioPhoto(profile.profile_id));
    return () => { request.current?.abort(); request.current = null; };
  }, [profile.profile_id, withoutPhoto]);
  async function submit() {
    if (request.current) return;
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    const startedAt = Date.now(); setProgress({ stage: "PREFERENCES", startedAt });
    try {
      const run = await recommendScenario(profile, photo, controller.signal, stage => {
        if (!controller.signal.aborted) setProgress({ stage, startedAt });
      });
      if (!controller.signal.aborted) navigate(scenarioResultsPath(run.run_sha256));
    } catch (reason) {
      if (controller.signal.aborted) return;
      setError(reason instanceof JourneyError && reason.status === 401
        ? "여행 연결 시간이 만료됐어요. 사진을 사용했다면 다시 확인하고, 추천 버튼을 다시 눌러 주세요."
        : reason instanceof Error ? reason.message : "추천을 불러오지 못했어요. 답변은 유지되며 다시 시도할 수 있어요.");
    } finally {
      if (request.current === controller) { request.current = null; setBusy(false); setProgress(null); }
    }
  }
  return <>
    <p className="recommendation-region-choice" style={{ flexBasis: "100%" }}>여행 지역: <strong>{travelRegionName(regionCode, regions.regions)}</strong>{" · "}<a href="/start?mode=edit">지역·조건 변경</a></p>
    <p className="recommendation-region-choice" style={{ flexBasis: "100%" }}>취향에 맞는 볼거리·체험을 추천해요.</p>
    {error && <section className="profile-state" role="alert" style={{ flexBasis: "100%" }}><p>{error}</p><a href="/quiz">답변 확인</a></section>}
    <button type="button" className="button button--primary" disabled={busy} aria-busy={busy} onClick={submit}>
      {busy ? "추천을 준비하고 있어요…" : photo ? "사진 취향을 반영해 추천 보기" : "바로 추천 보기"}
    </button>
    {photo && <button type="button" className="control" disabled={busy} onClick={() => {
      try { writeScenarioPhoto(profile.profile_id, null); setPhoto(null); } catch { setError("사진 선택을 해제하지 못했어요. 브라우저 저장 설정을 확인해 주세요."); }
    }}>사진 선택 해제</button>}
    {busy && progress && <RecommendationProgress {...progress} />}
  </>;
}
