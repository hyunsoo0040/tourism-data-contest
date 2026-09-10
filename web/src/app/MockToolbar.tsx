"use client";

import { useEffect, useState } from "react";
import styles from "./MockToolbar.module.css";

export function MockToolbar() {
  const [scenario, setScenario] = useState("normal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { void fetch("/v1/mock/scenario").then((r) => r.json()).then((r) => setScenario(r.scenario)).catch(() => setError("목업 서버 연결을 확인해 주세요.")); }, []);
  async function change(next: string, reset = false) {
    setBusy(true); setError("");
    try {
      const response = await fetch(reset ? "/v1/mock/reset" : "/v1/mock/scenario", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario: next }) });
      if (!response.ok) throw new Error();
      setScenario(next);
      if (reset) {
        for (const storage of [localStorage, sessionStorage]) for (const key of Object.keys(storage)) if (key.startsWith("itda")) storage.removeItem(key);
        window.location.assign("/start");
      } else {
        sessionStorage.removeItem("itda:phase5:current-recommendation:v2");
        window.location.reload();
      }
    } catch { setError("설정을 바꾸지 못했어요. 다시 시도해 주세요."); }
    finally { setBusy(false); }
  }
  return <aside className={styles.bar} aria-label="UI 목업 설정">
    <div><strong>UI 목업 · 실제 추천이 아닙니다</strong><span>가상 장소와 고정 점수 · 사진은 건너뛰어 주세요</span></div>
    <label>추천 상태 <select value={scenario} disabled={busy} onChange={(e) => void change(e.target.value)}>
      <option value="normal">정상 · 가상 5곳</option><option value="empty">추천 부족</option><option value="error">서버 오류</option>
    </select></label>
    <button disabled={busy} onClick={() => void change("normal", true)}>목업 초기화</button>
    {error && <p role="alert">{error}</p>}
  </aside>;
}
