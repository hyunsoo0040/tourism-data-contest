import { describe, expect, it } from "vitest";

import { PROFILE_AXIS_ORDER, projectDisplayScores } from "./displayScores";

function scores(values: readonly number[]) {
  return PROFILE_AXIS_ORDER.map((axis, i) => ({ axis, basis_points: values[i]!, display_score: Math.round(values[i]! / 100) }));
}

function values(raw: readonly number[]) {
  const display = projectDisplayScores(scores(raw))!;
  return PROFILE_AXIS_ORDER.map((axis) => display[axis]);
}

describe("result display apportionment", () => {
  it.each([
    [[3600, 3636, 1800], [39, 41, 20]],
    [[5001, 5000, 4999], [35, 33, 32]],
    [[0, 10000, 5000], [0, 67, 33]],
    [[10000, 0, 0], [100, 0, 0]],
    [[10000, 1, 0], [99, 1, 0]],
    [[5000, 5000, 0], [50, 50, 0]],
    [[5000, 5000, 5000], [34, 33, 33]],
  ])("apportions %j as %j", (raw, expected) => {
    expect(values(raw!)).toEqual(expected);
  });

  it("conserves 100, zeros, and every strict ordering across boundaries and near ties", () => {
    for (const h of [0, 1, 4999, 5000, 10000]) {
      for (const e of [0, 1, 4999, 5000, 10000]) {
        for (const r of [0, 1, 4999, 5000, 10000]) {
          const raw = [h, e, r];
          if (raw.every((value) => value === 0)) continue;
          const display = values(raw);
          expect(display.reduce((sum, value) => sum + value, 0)).toBe(100);
          raw.forEach((value, i) => {
            expect(Number.isInteger(display[i])).toBe(true);
            expect(display[i]).toBeGreaterThanOrEqual(0);
            expect(display[i]).toBeLessThanOrEqual(100);
            if (value === 0) expect(display[i]).toBe(0);
            raw.forEach((other, j) => {
              if (value > other) expect(display[i]).toBeGreaterThan(display[j]!);
            });
          });
        }
      }
    }
  });

  it("uses type priority for true ties without mutating or depending on input order", () => {
    const original = Object.freeze(scores([5000, 5000, 5000]).map((score) => Object.freeze(score)));
    const priority = [...PROFILE_AXIS_ORDER].reverse();
    const projected = projectDisplayScores(original, priority);
    expect(projected).toEqual({ HISTORY_TRADITION: 33, EMOTION_IMAGE: 33, REST_IMMERSION: 34 });
    expect(projectDisplayScores([...original].reverse(), priority)).toEqual(projected);
    expect(original.map((score) => score.display_score)).toEqual([50, 50, 50]);
  });

  it("does not invent proportions for an empty profile", () => {
    expect(projectDisplayScores(scores([0, 0, 0]))).toBeNull();
  });
});
