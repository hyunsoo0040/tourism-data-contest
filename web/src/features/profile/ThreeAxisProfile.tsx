import { useMemo, type RefObject } from "react";

import type { PreferenceProfile } from "../../api/api";
import { PROFILE_AXIS_ORDER, projectDisplayScores } from "./displayScores";

type Axis = PreferenceProfile["scores"][number]["axis"];

const AXIS_COPY: Record<Axis, { label: string; subtitle: string; className: string }> = {
  HISTORY_TRADITION: {
    label: "대상•원형형",
    subtitle: "이야기와 전통의 흔적",
    className: "axis-score--history",
  },
  EMOTION_IMAGE: {
    label: "의미•이미지형",
    subtitle: "마음속에 그려온 모습",
    className: "axis-score--emotion",
  },
  REST_IMMERSION: {
    label: "자기•몰입형",
    subtitle: "나를 온전히 마주하는 순간",
    className: "axis-score--rest",
  },
};

export function ThreeAxisProfile({
  scores,
  headingRef,
  tieBreak = PROFILE_AXIS_ORDER,
}: {
  scores: readonly PreferenceProfile["scores"][number][];
  headingRef?: RefObject<HTMLHeadingElement | null>;
  tieBreak?: readonly Axis[];
}) {
  const display = useMemo(() => projectDisplayScores(scores, tieBreak), [scores, tieBreak]);

  return (
    <section className="profile-field" aria-labelledby="axis-profile-title">
      
      {display === null ? <p role="status">아직 점수로 표시할 여행 기대가 없어요.</p> : null}
      <div className="axis-score-list">
        {PROFILE_AXIS_ORDER.map((axis) => {
          if (display === null) return null;
          const value = display[axis];
          const copy = AXIS_COPY[axis];
          const valueLabel = `${copy.label} ${value}점 / 100점`;
          return (
            <article className={`axis-score ${copy.className}`} key={axis}>
              <div className="axis-score__copy">
                <div>
                  <h3>{copy.label}</h3>
                  <p>{copy.subtitle}</p>
                </div>
                <strong>{value}</strong>
              </div>
              <div
                className="axis-meter"
                role="meter"
                aria-label={valueLabel}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={value}
              >
                <span className="axis-meter__fill" style={{ width: `${value}%` }}>
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
