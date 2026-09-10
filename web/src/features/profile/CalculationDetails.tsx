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
        <p>역사·전통 14개, 감성·이미지 11개, 휴식·몰입 11개의 선택지 분포를 반영했어요.
          각 축의 순점수를 해당 축의 선택지 수로 나누어 100점 기준으로 표시합니다.
          5번의 두 번째 답변은 휴식 +1, 역사 −1로 반영하며, 음수 결과는 0점으로 표시해요.
          가능한 최고점은 역사 86점, 감성 91점, 휴식 100점입니다.</p>
      ) : null}
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
