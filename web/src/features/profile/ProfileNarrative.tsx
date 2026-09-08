export function ProfileNarrative({ description }: { description: string }) {
  return (
    <section className="profile-narrative" aria-labelledby="profile-narrative-title">
      <p className="eyebrow">이번 여행의 한 문장</p>
      <h2 id="profile-narrative-title">당신이 고른 기대</h2>
      <p>{description}</p>
    </section>
  );
}
