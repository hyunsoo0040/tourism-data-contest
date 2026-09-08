import { useId } from "react";

/**
 * Explicit, purpose-specific photo consent.
 *
 * Four factual privacy statements are always visible (never collapsed), the
 * checkbox starts unchecked for every new job, and the checkbox plus CTA are
 * bound to the facts through `aria-describedby`. No file control exists here:
 * the picker is mounted only after the explicit continuation.
 */

export const PHOTO_CONSENT_COPY = {
  heading: "사진 사용 내용을 먼저 확인해 주세요",
  facts: [
    "선택한 사진은 이번 여행에서 선호하는 분위기와 경험 후보를 찾는 데만 사용해요.",
    "지원 형식과 크기, 실제 이미지 여부를 확인한 뒤 새 파일명과 안전한 형식으로 다시 만들어요. 원본 파일명과 위치 정보 같은 EXIF 메타데이터는 분석에 사용하지 않아요.",
    "사진 분석 기능이 별도로 승인되어 켜진 경우, 정제된 사진이 승인된 외부 분석 제공자에게 전송될 수 있어요. 공개 취향 기준과 필요한 최소 작업 식별자만 함께 보내며, 여행 답변·내부 점수·비공개 경로는 보내지 않아요.",
    "원본은 검증과 분석에 필요한 동안만 격리해 두고, 성공·거부·오류·시간 초과·삭제 요청으로 처리가 끝나면 즉시 삭제 절차를 시작해요. 원본 잔존이 0인지 확인되고 삭제 기록이 남은 뒤에만 삭제 완료로 표시해요.",
  ],
  factLabels: ["목적", "처리 범위", "외부 전송 가능성", "최소 보유와 삭제 시점"],
  checkbox:
    "위 내용을 읽었고, 이 사진들을 이번 여행 취향 분석에 사용하는 데 동의해요.",
  cta: "동의하고 사진 고르기",
  error:
    "사진 사용 내용을 확인하고 동의해 주세요. 동의하지 않아도 사진 없이 추천을 볼 수 있어요.",
  midJourneyStop:
    "분석 중에도 “사진 사용 중단하고 삭제하기”를 선택할 수 있고, 사진 없이 추천은 기다리지 않고 계속할 수 있어요.",
} as const;

export function PhotoConsentPanel({
  checked,
  error,
  headingLevel = 1,
  onToggle,
  onContinue,
  children,
}: {
  checked: boolean;
  error: boolean;
  headingLevel?: 1 | 2;
  onToggle: (checked: boolean) => void;
  onContinue: () => void;
  children?: React.ReactNode;
}) {
  const baseId = useId();
  const Heading = headingLevel === 1 ? "h1" : "h2";
  const factIds = PHOTO_CONSENT_COPY.facts.map((_, index) => `${baseId}-fact-${index}`);
  const errorId = `${baseId}-consent-error`;
  return (
    <section
      className="profile-state"
      aria-labelledby="photo-consent-heading"
      style={{ padding: "var(--space-lg)" }}
    >
      <Heading id="photo-consent-heading" tabIndex={-1}>
        {PHOTO_CONSENT_COPY.heading}
      </Heading>
      <dl style={{ margin: "var(--space-md) 0 0" }}>
        {PHOTO_CONSENT_COPY.facts.map((fact, index) => (
          <div
            key={factIds[index]}
            id={factIds[index]}
            style={{
              paddingBlock: "var(--space-sm)",
              borderTop: "1px solid var(--line)",
            }}
          >
            <dt
              style={{
                color: "var(--ink-muted)",
                fontSize: "14px",
                fontWeight: 600,
              }}
            >
              {PHOTO_CONSENT_COPY.factLabels[index]}
            </dt>
            <dd style={{ margin: "var(--space-xs) 0 0", minWidth: 0 }}>{fact}</dd>
          </div>
        ))}
      </dl>
      <p className="privacy-note" style={{ marginTop: "var(--space-md)" }}>
        {PHOTO_CONSENT_COPY.midJourneyStop}
      </p>
      <label
        style={{
          display: "flex",
          minHeight: "44px",
          alignItems: "center",
          gap: "var(--space-sm)",
          padding: "var(--space-sm) 0",
          cursor: "pointer",
        }}
      >
        <input
          type="checkbox"
          checked={checked}
          onChange={(event) => onToggle(event.target.checked)}
          aria-describedby={[...factIds, ...(error ? [errorId] : [])].join(" ")}
          style={{ width: "20px", minWidth: "20px", minHeight: "20px", margin: 0 }}
        />
        <span style={{ minWidth: 0 }}>{PHOTO_CONSENT_COPY.checkbox}</span>
      </label>
      {error ? (
        <p id={errorId} className="field-error" role="alert">
          {PHOTO_CONSENT_COPY.error}
        </p>
      ) : null}
      {children}
      <button
        type="button"
        className="button button--primary"
        style={{ width: "100%", marginTop: "var(--space-md)" }}
        onClick={onContinue}
      >
        {PHOTO_CONSENT_COPY.cta}
      </button>
    </section>
  );
}
