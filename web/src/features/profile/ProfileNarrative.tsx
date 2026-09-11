function interpretedDescription(description: string): string {
  const hasHistory = description.includes("역사·전통");
  const hasEmotion = description.includes("감성·이미지");
  const hasRest = description.includes("휴식·몰입");

  if (hasEmotion && hasRest) {
    return "나는 장면 속에 담긴 감정과 오래 머물 수 있는 순간에 끌려요.";
  }
  if (hasHistory && hasEmotion) {
    return "나는 오래된 이야기와 마음속에 그려온 모습에 끌려요.";
  }
  if (hasHistory && hasRest) {
    return "나는 오래된 이야기와 나를 온전히 마주하는 순간에 끌려요.";
  }
  return description;
}

export function ProfileNarrative({ description }: { description: string }) {
  return (
    <section className="profile-narrative" aria-labelledby="profile-narrative-title">
      <p className="eyebrow">이번 여행의 한 문장</p>
      <h2 id="profile-narrative-title">당신의 여행 한 문장</h2>
      <p>{interpretedDescription(description)}</p>
    </section>
  );
}
