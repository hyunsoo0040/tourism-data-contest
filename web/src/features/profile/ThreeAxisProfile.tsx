import type { RefObject } from "react";

import type { PreferenceProfile } from "../../api/api";

type Axis = PreferenceProfile["scores"][number]["axis"];

const AXIS_COPY: Record<Axis, { label: string; subtitle: string; className: string }> = {
  HISTORY_TRADITION: {
    label: "역사·전통",
    subtitle: "이야기와 전통의 흔적",
    className: "axis-score--history",
  },
  EMOTION_IMAGE: {
    label: "감성·이미지",
    subtitle: "빛과 장면의 인상",
    className: "axis-score--emotion",
  },
  REST_IMMERSION: {
    label: "휴식·몰입",
    subtitle: "고요하게 머무는 시간",
    className: "axis-score--rest",
  },
};

const AXIS_ORDER: Axis[] = ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"];

export function ThreeAxisProfile({
  scores,
  headingRef,
}: {
  scores: readonly PreferenceProfile["scores"][number][];
  headingRef?: RefObject<HTMLHeadingElement | null>;
}) {
  const byAxis = new Map(scores.map((score) => [score.axis, score]));

  return (
    <section className="profile-field" aria-labelledby="axis-profile-title" aria-describedby="axis-independence-note">
      <div className="profile-field__heading">
        <p className="eyebrow">세 가지 경험</p>
        <h2 id="axis-profile-title" ref={headingRef} tabIndex={-1}>
          이번 여행에서 기대하는 시간
        </h2>
      </div>
      <p id="axis-independence-note" className="axis-independence-note">
        세 점수는 합계가 아니라, 이번 여행에서 기대하는 경험을 각각 나타냅니다.
      </p>
      <div className="axis-score-list">
        {AXIS_ORDER.map((axis) => {
          const score = byAxis.get(axis);
          if (!score) return null;
          const copy = AXIS_COPY[axis];
          const valueLabel = `${copy.label} ${score.display_score}점 / 100점`;
          return (
            <article className={`axis-score ${copy.className}`} key={axis}>
              <div className="axis-score__copy">
                <div>
                  <h3>{copy.label}</h3>
                  <p>{copy.subtitle}</p>
                </div>
                <strong>{score.display_score}</strong>
              </div>
              <div
                className="axis-meter"
                role="meter"
                aria-label={valueLabel}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={score.display_score}
              >
                <span className="axis-meter__fill" style={{ width: `${score.display_score}%` }}>
                  <span className="axis-meter__marker" />
                </span>
              </div>
              <p className="axis-score__value">{valueLabel}</p>
            </article>
          );
        })}
      </div>
    </section>
  );
}
