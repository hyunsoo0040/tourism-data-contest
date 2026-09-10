"use client";

/**
 * `/quiz` port: upstream 취향테스트.html shell chrome (topbar, intro copy,
 * scoped presentation) wrapping the retained canonical v2 quiz journey. The
 * scenario and choice text comes from web/src/content/questionnaire.ko.json.
 * QuizPage checks the backend scoring contract before submission; the upstream
 * inline script never loads and never scores. Upstream option-button
 * interaction is intentionally rendered as the retained accessible radio-card
 * form (same served order, same canonical v2 payload on submission) — see the
 * port mapping in 07-02-SUMMARY.
 */
import { QuizPage } from "../../journey-pages/QuizJourneyPage";
import { JOURNEY_COPY } from "../../content/journey.ko";

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
              <h1>{JOURNEY_COPY.quiz.titleLines[0]}<br />{JOURNEY_COPY.quiz.titleLines[1]}</h1>
              <p>
                {JOURNEY_COPY.quiz.descriptionLines[0]}<br />
                {JOURNEY_COPY.quiz.descriptionLines[1]}
              </p>
            </div>
          </section>
          <QuizPage />
        </main>
      </div>
    </div>
  );
}
