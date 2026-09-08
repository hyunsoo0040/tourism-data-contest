"use client";

/**
 * `/quiz` port: upstream 취향테스트.html shell chrome (topbar, intro copy,
 * scoped presentation) wrapping the retained canonical v2 quiz journey. The
 * 12 scenarios, choice texts, keywords, and result copy come exclusively from
 * GET /v1/questionnaires/current through the retained QuizPage; the upstream
 * inline script never loads and never scores. Upstream option-button
 * interaction is intentionally rendered as the retained accessible radio-card
 * form (same served order, same canonical v2 payload on submission) — see the
 * port mapping in 07-02-SUMMARY.
 */
import { QuizPage } from "../../journey-pages/QuizJourneyPage";

export function UpstreamQuizPage() {
  return (
    <div className="up-root">
      <div className="up-quiz" data-upstream-surface="quiz">
        <header className="topbar">
          <a className="brand" href="/"><span>잇</span>IT-DA</a>
          <nav>
            <a href="/#type">유형 보기</a>
            <a href="/profile">취향 결과</a>
            <a href="/start">조건 입력</a>
          </nav>
        </header>
        <main>
          <section className="intro">
            <div>
              <p className="eyebrow">Balance Type Test</p>
              <h1>12개의 장면으로<br />여행의 의미를 찾아요</h1>
              <p>
                정답은 없습니다. 하루 여행처럼 이어지는 상황 속에서 더 자연스러운 선택을 골라보세요.<br />
                마음에 드는 선택지가 여러 개라면, 그중 가장 끌리는 방향을 선택해 주세요.
              </p>
            </div>
          </section>
          <QuizPage />
        </main>
      </div>
    </div>
  );
}
