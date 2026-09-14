import { useEffect, useState } from "react";
import type { RecommendationStage } from "./scenario";
import styles from "./RecommendationProgress.module.css";

export type RecommendationProgressState = { stage: RecommendationStage; startedAt: number };
const steps: { stage: RecommendationStage; label: string; message: string }[] = [
  { stage: "PREFERENCES", label: "취향·여행 조건 확인", message: "입력한 취향과 여행 조건을 확인하고 있어요." },
  { stage: "MATCHING", label: "관광지 특성과 선호 비교", message: "관광지 특성과 나의 선호를 비교하고 있어요." },
  { stage: "READY", label: "추천 결과 준비", message: "추천이 완료되어 결과 화면으로 이동합니다." },
];

export function RecommendationProgress({ stage, startedAt }: RecommendationProgressState) {
  const [seconds, setSeconds] = useState(() => Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));
  useEffect(() => {
    const tick = () => setSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));
    tick();
    if (stage === "READY") return;
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [startedAt, stage]);
  const current = steps.findIndex(step => step.stage === stage);
  const elapsed = seconds < 60 ? `${seconds}초` : `${Math.floor(seconds / 60)}분 ${seconds % 60}초`;
  return <section className={styles.progress} aria-label="추천 진행 상황">
    <div className={styles.heading}><strong>추천 진행 상황</strong><span className={styles.elapsed} aria-live="off">{elapsed} 경과</span></div>
    <p className={styles.message} role="status" aria-live="polite" aria-atomic="true">{steps[current]!.message}</p>
    <ol className={styles.steps}>
      {steps.map((step, index) => {
        const done = index < current || stage === "READY";
        const active = index === current && !done;
        return <li key={step.stage} className={styles.step} data-state={done ? "done" : active ? "active" : "pending"} aria-current={active ? "step" : undefined}>
          <span className={styles.marker} aria-hidden="true">{done ? <svg viewBox="0 0 20 20" fill="none"><path d="m4 10 4 4 8-8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg> : index + 1}</span>
          <span>{step.label}</span><span className={styles.state}>{done ? "완료" : active ? "진행 중" : "대기"}</span>
        </li>;
      })}
    </ol>
    {seconds >= 15 && stage !== "READY" && <p className={styles.waiting} role="status">아직 응답을 기다리고 있어요. 이 화면을 유지하면 완료되는 대로 결과를 보여드릴게요.</p>}
  </section>;
}
