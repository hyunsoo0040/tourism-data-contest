import type { ReactNode } from "react";

export function RecommendationShell({ children }: { children: ReactNode }) {
  return (
    <div className="up-root">
      <div className="up-etc" data-upstream-surface="recommendations">
        <header className="topbar">
          <a className="brand" href="/">
            <span>잇</span>
            <strong>IT-DA</strong>
          </a>
          <nav>
            <a href="/profile">취향 결과</a>
            <a href="#recommendation-list">추천 장소</a>
            <a href="/">홈</a>
          </nav>
          <div className="server-pill ok">경주 PUBLIC 100</div>
        </header>
        <main>{children}</main>
        <nav className="mobile-tabs" aria-label="모바일 추천 이동">
          <a href="#recommendation-list">추천</a>
          <a href="/profile">취향</a>
          <a href="/start">다시 테스트</a>
          <a href="/">홈</a>
        </nav>
      </div>
    </div>
  );
}
