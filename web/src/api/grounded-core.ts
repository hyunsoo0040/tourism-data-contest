import { z } from "zod";

function pythonFloat(value: number): string {
  if (Object.is(value, -0)) return "-0.0";
  const magnitude = Math.abs(value);
  if (magnitude !== 0 && (magnitude < 0.0001 || magnitude >= 1e16)) {
    return value.toExponential().replace(/e([+-])(\d+)$/, (_match, sign: string, exponent: string) => `e${sign}${exponent.padStart(2, "0")}`);
  }
  return Number.isInteger(value) ? `${value}.0` : String(value);
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    // These fields are strict Python floats; preserve their decimal type when
    // an integral distance (e.g. 0.0) crosses JSON into JavaScript's Number.
    .map(([key, entry]) => `${JSON.stringify(key)}:${typeof entry === "number" && ["distance_meters", "distance_from_place_meters"].includes(key)
      ? pythonFloat(entry) : canonicalJson(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}

export async function canonicalHash(value: unknown): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)));
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function without(value: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
}

export function same(left: unknown, right: unknown): boolean { return canonicalJson(left) === canonicalJson(right); }
export function ordered(values: readonly string[]): boolean { return values.every((v, i) => i === 0 || values[i - 1]! < v); }
export function halfUp(n: number, d: number): number { return Math.floor((2 * n + d) / (2 * d)); }
export function combine(groups: readonly (readonly [number | null, number])[]): number | null {
  const observed = groups.filter((group): group is readonly [number, number] => group[0] !== null && group[1] > 0);
  return observed.length ? halfUp(observed.reduce((sum, [value, weight]) => sum + value * weight, 0),
    observed.reduce((sum, [, weight]) => sum + weight, 0)) : null;
}
export const score = z.number().int().min(0).max(100);
export const nonnegative = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const nullableScore = score.nullable();
export const MOOD_KEYS = ["greenery", "water", "open_composition", "traditional_appearance", "contemporary_design",
  "warm_light", "vivid_color", "night_lighting"] as const;
export const MOOD_LABELS: Record<typeof MOOD_KEYS[number], string> = {
  greenery: "초록 식물이 보이는 풍경", water: "물이 보이는 풍경", open_composition: "시야가 트여 보이는 구도",
  traditional_appearance: "전통적으로 보이는 외관", contemporary_design: "현대적으로 보이는 디자인",
  warm_light: "따뜻한 빛의 색감", vivid_color: "선명한 색감", night_lighting: "밤 조명이 보이는 장면",
};
export const MOOD_POLICY_SHA = "9e9687b4dce79ae4e592d8111c4876969d4f4a6db1af0497a72dbe4faef6e3c2";
