import { useEffect, useRef, useState } from "react";
import { fetchPreferenceProfile, type PreferenceProfile } from "../../api/api";
import { readProfileReference } from "../../app/storage";
import { Link, useNavigate } from "../../app/react-router-dom";
import { PhotoCameraIcon, PhotoWorkspace } from "../photo/PhotoWorkspace";
import { api, ensureSession, escapeId, json, type Info, type Photo } from "./api";
import { readScenarioPhoto, recommendScenario, scenarioResultsPath, writeScenarioPhoto } from "./scenario";
import "./scenario.css";
import { RecommendationProgress, type RecommendationProgressState } from "./RecommendationProgress";

const labels: Record<string, string> = { greenery: "녹지", water: "물", open_composition: "트인 구도", traditional_appearance: "전통적 외관", contemporary_design: "현대적 디자인", warm_light: "따뜻한 빛", vivid_color: "선명한 색", night_lighting: "야간 조명" };

export function ScenarioPhotoPage() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState<PreferenceProfile | null>(null), [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const [photo, setPhoto] = useState<Photo | null>(null), [chosen, setChosen] = useState<string[]>([]), [urls, setUrls] = useState<string[]>([]);
  const [consent, setConsent] = useState(false), [attempt, setAttempt] = useState(0);
  const [progress, setProgress] = useState<RecommendationProgressState | null>(null);
  const picker = useRef<HTMLInputElement>(null), active = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError(null);
    const id = readProfileReference().profile?.profile_id;
    if (!id) { setLoading(false); return; }
    fetchPreferenceProfile(id, { signal: controller.signal }).then(value => {
      if (controller.signal.aborted) return;
      setProfile(value); const previous = readScenarioPhoto(value.profile_id); setPhoto(previous); setChosen(previous?.selected_candidate_ids ?? []);
    }).catch(() => { if (!controller.signal.aborted) setError("취향 결과를 불러오지 못했어요. 프로필을 다시 확인해 주세요."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    api<Info>("/info", { signal: controller.signal }).then(info => { if (!controller.signal.aborted) setEnabled(info.photo_enabled); }).catch(() => {});
    return () => { controller.abort(); active.current?.abort(); active.current = null; };
  }, [attempt]);
  useEffect(() => () => urls.forEach(URL.revokeObjectURL), [urls]);
  async function run(action: (signal: AbortSignal) => Promise<void>) {
    if (active.current) return;
    const controller = new AbortController(); active.current = controller; setBusy(true); setError(null);
    try { await action(controller.signal); }
    catch (reason) { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "사진 처리를 완료하지 못했어요. 사진 없이도 추천을 받을 수 있어요."); }
    finally { if (active.current === controller) { active.current = null; setBusy(false); setProgress(null); } }
  }
  async function upload() {
    const files = Array.from(picker.current?.files ?? []);
    if (!files.length || !profile) return;
    if (files.length > 3 || files.some(file => file.size > 10 * 1024 * 1024 || !["image/jpeg", "image/png", "image/webp"].includes(file.type))) {
      setError("JPG, PNG, WebP 사진을 최대 3장, 장당 10MB 이하로 선택해 주세요."); return;
    }
    await run(async signal => {
      await ensureSession(); signal.throwIfAborted();
      const form = new FormData(); files.forEach(file => form.append("files", file));
      const next = await api<Photo>("/photos", { method: "POST", body: form, signal }); signal.throwIfAborted();
      writeScenarioPhoto(profile.profile_id, null); setChosen([]);
      setPhoto(next); setUrls(files.map(URL.createObjectURL));
    });
    if (picker.current) picker.current.value = "";
  }
  async function recommend(usePhoto: boolean) {
    if (!profile) return;
    await run(async signal => {
      let confirmed: Photo | null = null;
      const startedAt = Date.now(); setProgress({ stage: "PREFERENCES", startedAt });
      if (usePhoto && photo) {
        if (!chosen.length) throw new Error("반영할 분위기를 하나 이상 선택해 주세요.");
        confirmed = await api<Photo>(`/photos/${escapeId(photo.photo_id)}/confirm`, { method: "POST", body: json({ candidate_ids: chosen }), signal });
        signal.throwIfAborted(); writeScenarioPhoto(profile.profile_id, confirmed); setPhoto(confirmed);
      } else writeScenarioPhoto(profile.profile_id, null);
      const result = await recommendScenario(profile, confirmed, signal, stage => {
        if (!signal.aborted) setProgress({ stage, startedAt });
      });
      if (!signal.aborted) navigate(scenarioResultsPath(result.run_sha256));
    });
  }
  return <div className="up-root"><div className="up-photo" data-upstream-surface="photo">
    <header className="topbar"><a className="brand main-page-logo" href="/"><img className="brand-mark-image" src="/itda-logo-icon.png" alt="" /><strong className="brand-wordmark">IT-DA</strong></a></header>
    <main><PhotoWorkspace>
      {loading ? <p role="status">사진에 연결할 취향을 확인하고 있어요.</p> : !profile ? <section className="profile-state"><p>먼저 상황형 테스트를 마치고 취향 결과를 확인해 주세요.</p><Link className="button button--primary" to="/start">취향 테스트 시작</Link><button className="control" onClick={() => setAttempt(value => value + 1)}>다시 확인</button></section> : <>
        <section className="profile-state photo-picker"><h2>사진으로 전하는 취향</h2>
          <p>위치 메타데이터를 제거한 뒤 분위기를 분석하며, 서버에 원본을 보관하지 않아요.</p>
          <label className="scenario-photo-consent"><input type="checkbox" checked={consent} disabled={busy} onChange={event => setConsent(event.target.checked)} />사진을 분위기 분석에 사용하는 데 동의해요.</label>
          <input ref={picker} type="file" className="photo-picker__input" aria-label="여행 분위기 참고 사진" accept="image/jpeg,image/png,image/webp" multiple disabled={busy || !enabled || !consent} onChange={upload} />
          <button type="button" className="button button--secondary photo-picker__trigger" disabled={busy || !enabled || !consent} onClick={() => picker.current?.click()}><span className="photo-picker__trigger-icon"><PhotoCameraIcon /></span><span className="photo-picker__trigger-copy"><strong>사진 고르기</strong><small>최대 3장 · 장당 10MB</small></span></button>
          {!enabled && <p>현재 사진 분석을 사용할 수 없어요. 사진 없이 추천을 이어갈 수 있어요.</p>}
          <div className="scenario-photo-preview">{urls.map((url, index) => <img key={url} src={url} alt={`선택한 여행 사진 ${index + 1}`} />)}</div>
          {photo && <><h3>추천에 더할 분위기</h3><p>사진에서 보이는 분위기 중 직접 선택한 항목만 반영해요.</p><div className="scenario-photo-choices">{photo.batches.flatMap((batch, index) => batch.candidates.filter(candidate => candidate.observation.state === "OBSERVED").map(candidate => <label key={candidate.candidate_id}><input type="checkbox" disabled={busy} checked={chosen.includes(candidate.candidate_id)} onChange={event => setChosen(value => event.target.checked ? [...value, candidate.candidate_id] : value.filter(id => id !== candidate.candidate_id))} />사진 {index + 1} · {labels[candidate.observation.dimension]} {candidate.observation.level}/4</label>))}</div>
            <button className="control" disabled={busy} onClick={() => run(async signal => { await api(`/photos/${escapeId(photo.photo_id)}`, { method: "DELETE", signal }); signal.throwIfAborted(); writeScenarioPhoto(profile.profile_id, null); setPhoto(null); setChosen([]); setUrls([]); })}>사진 분석 결과 삭제</button>
            <p>서버 원본 보관: 없음 · 확정한 사진 분위기는 비교 근거가 있을 때 추천 점수의 20%로 반영해요.</p></>}
        </section>
        {photo && <div className="photo-action-bar"><button className="button button--primary" disabled={busy || !chosen.length} onClick={() => recommend(true)}>선택한 분위기로 추천 보기</button></div>}
      </>}
      {busy && (progress ? <RecommendationProgress {...progress} /> : <p role="status">입력과 근거를 확인하고 있어요…</p>)}{error && <p role="alert">{error}</p>}
    </PhotoWorkspace></main>
  </div></div>;
}
