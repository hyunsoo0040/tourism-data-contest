export function PhotoMoodIntro({ onOpenPhoto }: { onOpenPhoto: () => void }) {
  return (
    <section id="photo" className="profile-photo-intro photo-feature--intro" aria-labelledby="profile-photo-intro-heading">
      <div className="photo-intro-copy">
        <div className="eyebrow">Photo mood input</div>
        <h2 id="profile-photo-intro-heading">사진으로 더하는<br />나만의 여행 분위기</h2>
        <p>
          말로 표현하기 어려운 취향은 사진으로 알려주세요.
          테스트를 마친 뒤, 마음에 드는 여행 사진을 더하면
          그 안의 색감과 풍경을 추천에 함께 반영해요.
        </p>
      </div>
      <div className="photo-mood-preview" aria-label="사진으로 더할 수 있는 분위기 예시">
        <div className="photo-mood-scenes">
          <figure className="photo-mood-frame photo-mood-frame--warm">
            <div className="photo-mood-scene" aria-hidden="true" />
            <figcaption>따뜻한 빛</figcaption>
          </figure>
          <figure className="photo-mood-frame photo-mood-frame--nature">
            <div className="photo-mood-scene" aria-hidden="true" />
            <figcaption>차분한 자연</figcaption>
          </figure>
          <figure className="photo-mood-frame photo-mood-frame--open">
            <div className="photo-mood-scene" aria-hidden="true" />
            <figcaption>탁 트인 풍경</figcaption>
          </figure>
        </div>
      </div>
      <button type="button" className="button button--primary photo-mood-cta" onClick={onOpenPhoto}>
        사진으로 추천받기
      </button>
    </section>
  );
}
