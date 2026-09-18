import type { ReactNode } from "react";

export function RecommendationShell({ children }: { children: ReactNode }) {
  const goBack = () => {
    if (typeof window !== "undefined") window.history.back();
  };

  return (
    <div className="up-root">
      <div className="up-etc" data-upstream-surface="recommendations">
        <header className="topbar">
          <a className="brand main-page-logo" href="/">
            <img className="brand-mark-image" src="/itda-logo-icon.png" alt="" />
            <strong className="brand-wordmark">IT-DA</strong>
          </a>
          <nav>
            <a href="/">홈</a>
            <button type="button" onClick={goBack}>뒤로 가기</button>
          </nav>
        </header>
        <main>{children}</main>
        <nav className="mobile-tabs" aria-label="페이지 이동">
          <a href="/">홈</a>
          <button type="button" onClick={goBack}>뒤로 가기</button>
        </nav>
      </div>
    </div>
  );
}
