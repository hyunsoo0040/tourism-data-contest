import type { PreferenceProfile } from "../../api/api";

type Axis = PreferenceProfile["scores"][number]["axis"];
export const PROFILE_AXIS_ORDER: readonly Axis[] = ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"];

/** Presentation only: conserve 100 points and preserve every strict raw-score ordering.
 * Among valid integer allocations, minimize squared distance from the exact proportions.
 * Exact allocation ties favor the questionnaire's existing type priority.
 * Server scores, type selection, and recommendation inputs remain untouched.
 */
export function projectDisplayScores(
  scores: readonly PreferenceProfile["scores"][number][],
  tieBreak: readonly Axis[] = PROFILE_AXIS_ORDER,
): Record<Axis, number> | null {
  const order = [...new Set([...tieBreak, ...PROFILE_AXIS_ORDER])];
  const raw = order.map((axis) => scores.find((score) => score.axis === axis)?.basis_points ?? 0);
  const total = raw.reduce((sum, value) => sum + value, 0);
  if (total === 0) return null;

  let best: number[] = [];
  let bestError = Infinity;
  // Descending traversal makes equal-error allocations deterministic by type priority.
  for (let first = 100; first >= 0; first--) {
    for (let second = 100 - first; second >= 0; second--) {
      const candidate = [first, second, 100 - first - second];
      if (raw.some((value, i) =>
        (value === 0 && candidate[i] !== 0) || raw.some((other, j) =>
          value > other && candidate[i]! <= candidate[j]!,
        ),
      )) continue;
      const error = raw.reduce((sum, value, i) => sum + (candidate[i]! * total - 100 * value) ** 2, 0);
      if (error < bestError) {
        best = candidate;
        bestError = error;
      }
    }
  }
  return Object.fromEntries(order.map((axis, i) => [axis, best[i]!])) as Record<Axis, number>;
}
