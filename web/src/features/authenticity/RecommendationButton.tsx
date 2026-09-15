import { useEffect, useState } from "react";
import type { RecommendationProgressState } from "./RecommendationProgress";
import styles from "./RecommendationButton.module.css";

const stages = [
  { key: "PREFERENCES", label: "취향 확인 중" },
  { key: "MATCHING", label: "여행지 찾는 중" },
  { key: "DETAILS", label: "사진·설명 준비 중" },
] as const;

export function RecommendationButton({ label, progress, onClick, disabled = false, variant = "primary" }: {
  label: string; progress: RecommendationProgressState | null; onClick: () => void;
  disabled?: boolean; variant?: "primary" | "secondary";
}) {
  const [waiting, setWaiting] = useState(false);
  const startedAt = progress?.startedAt;
  const ready = progress?.stage === "READY";
  useEffect(() => {
    setWaiting(false);
    if (startedAt === undefined || ready) return;
    const timer = window.setTimeout(() => setWaiting(true), Math.max(0, 15000 - (Date.now() - startedAt)));
    return () => window.clearTimeout(timer);
  }, [startedAt, ready]);
  const completed = ready ? stages.length : Math.max(0, stages.findIndex(stage => stage.key === progress?.stage));
  const currentLabel = ready ? "추천 준비 완료" : stages[completed]!.label;
  const stepText = ready ? "완료" : `${completed + 1}/3`;
  const status = `${currentLabel}${waiting && !ready ? ". 응답을 기다리고 있어요. 완료되면 결과를 보여드릴게요." : ""}`;

  return <>
    <button type="button" className={`button button--${variant} ${styles.button}`} disabled={disabled || !!progress} aria-busy={!!progress} onClick={onClick}>
      <span className={styles.idle} aria-hidden={!!progress}>{label}</span>
      {progress && <>
        <span className={styles.caption}><span>{currentLabel}</span><span className={styles.count}>{stepText}</span></span>
        <span className={styles.track} aria-hidden="true">{stages.map((stage, index) =>
          <span key={stage.key} className={styles.segment} data-state={index < completed ? "done" : index === completed ? "active" : "pending"} />
        )}</span>
      </>}
    </button>
    {progress && <>
      {/* Button descendants are presentational to assistive technology. Keep the semantic progress beside it. */}
      <span className={styles.accessible} role="progressbar" aria-label="추천 진행 상황" aria-valuemin={0} aria-valuemax={3} aria-valuenow={completed} aria-valuetext={`${currentLabel} · ${stepText}${ready ? "" : "단계"}`} />
      <span className={styles.accessible} role="status" aria-live="polite" aria-atomic="true">{status}</span>
    </>}
  </>;
}
