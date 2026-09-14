import { useState } from "react";

import type { PreferenceProfile } from "../../api/api";

function shortenedHash(hash: string): string {
  return `${hash.slice(0, 12)}…${hash.slice(-4)}`;
}

function formatUtc(value: string): string {
  return `${new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "long",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value))} UTC`;
}

export function CalculationDetails({ profile }: { profile: PreferenceProfile }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  const copyHash = async () => {
    try {
      await navigator.clipboard.writeText(profile.config_hash);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <details className="profile-details">
      <summary>프로필 계산 정보</summary>
      {profile.scoring_version === "choice-distribution-v3" ? (
        <p>대상•원형형 14개, 의미•이미지형 11개, 자기•몰입형 11개의 선택지 분포를 반영했어요.
          각 축의 순점수를 해당 축의 선택지 수로 나누어 원점수를 계산합니다.
          5번의 두 번째 답변은 휴식 +1, 역사 −1로 반영하며, 음수 결과는 0점으로 처리해요.</p>
      ) : null}
      <p>화면 점수는 세 축의 원점수 비율을 합계 100점인 정수로 환산한 값이에요.
        원점수가 높은 축은 최소 1점 높게 표시하고, 이 조건 안에서 원래 비율에 가장 가깝게 맞춰요.
        대표 유형과 추천에는 환산 전 원점수를 사용합니다.</p>
      <dl>
        <div><dt>결과 형식</dt><dd>{profile.schema_version}</dd></div>
        <div><dt>질문</dt><dd>{profile.questionnaire_version}</dd></div>
        <div><dt>점수 계산</dt><dd>{profile.scoring_version}</dd></div>
        <div><dt>설명 문장</dt><dd>{profile.description_template_version}</dd></div>
        <div>
          <dt>설정 식별자</dt>
          <dd className="config-hash">
            <code>{shortenedHash(profile.config_hash)}</code>
            <button type="button" className="button button--secondary" onClick={() => void copyHash()}>
              전체 설정 식별자 복사
            </button>
          </dd>
        </div>
        <div><dt>만든 시각</dt><dd><time dateTime={profile.created_at}>{formatUtc(profile.created_at)}</time></dd></div>
      </dl>
      <p className="copy-status" role="status" aria-live="polite">
        {copyState === "copied" ? "전체 설정 식별자를 복사했어요." : copyState === "failed" ? "복사하지 못했어요. 다시 시도해 주세요." : ""}
      </p>
    </details>
  );
}
