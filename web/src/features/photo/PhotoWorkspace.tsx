import type { ReactNode } from "react";

/** Shared presentation from ui-mock 12a3b90; the host owns all photo state and API calls. */
export function PhotoCameraIcon() {
  return <svg viewBox="0 0 40 40" aria-hidden="true" focusable="false">
    <path d="M10 13.5h5l2-3h6l2 3h5a4 4 0 0 1 4 4v11a4 4 0 0 1-4 4H10a4 4 0 0 1-4-4v-11a4 4 0 0 1 4-4Z" />
    <circle cx="20" cy="23" r="6" />
  </svg>;
}

export function PhotoWorkspace({ children, headingLevel = 1, headingId = "photo-page-heading" }: {
  children: ReactNode; headingLevel?: 1 | 2; headingId?: string;
}) {
  const Heading = headingLevel === 1 ? "h1" : "h2";
  return <section className="photo-page" aria-labelledby={headingId}>
    <div className="photo-page-panel">
      <header className="photo-intro">
        <p className="eyebrow">Photo Preference</p>
        <Heading id={headingId}>마음에 남은 장면을<br /><span>이번 여행의 힌트로</span></Heading>
        <p>사진은 경험 유형을 판정하는 기준이 아니라, 원하는 분위기를 더 쉽게 알려주는 보조 입력입니다.</p>
        <ul className="photo-format-list" aria-label="사진 입력 요약">
          <li>선택 입력</li><li>최대 3장</li><li>JPEG · PNG · WEBP</li>
        </ul>
      </header>
      <div className="photo-workspace-layout">
        <section className="workspace" aria-label="사진 입력 단계">{children}</section>
        <aside className="photo-guide" aria-labelledby={`${headingId}-guide`}>
          <div className="photo-guide__visual"><PhotoCameraIcon /></div>
          <p className="photo-guide__kicker">한 장이면 충분해요</p>
          <h2 id={`${headingId}-guide`}>사진은 이렇게 반영돼요</h2>
          <ol className="photo-guide__steps">
            <li><span>1</span><div><strong>장면 고르기</strong><p>좋아했던 여행의 분위기가 잘 보이는 사진을 선택해요.</p></div></li>
            <li><span>2</span><div><strong>분위기 분석</strong><p>사진에 담긴 빛과 색, 풍경의 분위기를 분석해요.</p></div></li>
            <li><span>3</span><div><strong>추천에 더하기</strong><p>사진에서 확인한 분위기를 모두 자동으로 반영해요.</p></div></li>
          </ol>
        </aside>
      </div>
    </div>
  </section>;
}
