type QuizProgressProps = {
  total: number;
  answered: number[];
};

export function QuizProgress({ total, answered }: QuizProgressProps) {
  const completed = new Set(answered).size;
  const progress = Math.round((completed / total) * 100);

  return (
    <aside className="panel status" aria-label="질문 진행 상황">
      <p className="eyebrow">Your Signal</p>
      <h2>응답 진행도</h2>
      <div
        className="progress-track"
        role="progressbar"
        aria-label="응답 진행도"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={completed}
        aria-valuetext={`${total}개 중 ${completed}개 응답 완료`}
      >
        <i className="progress-bar" style={{ width: `${progress}%` }} />
      </div>
      <div aria-live="polite">{completed} / {total} 응답 완료</div>
    </aside>
  );
}
