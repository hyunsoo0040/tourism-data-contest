/** Explicit trip needs stay separate from the sealed questionnaire profile. */
export const GROUNDED_TRIP_STORAGE_KEY = "itda:grounded-trip:v1";

export const FACILITY_CHOICES = [
  { id: "wheelchair_rental", label: "휠체어 대여" },
  { id: "stroller_rental", label: "유모차 대여" },
  { id: "accessible_toilet", label: "장애인 화장실" },
  { id: "accessible_parking", label: "장애인 주차 구역" },
  { id: "step_free_entry", label: "단차 없는 출입구" },
] as const;

export type RequiredFacility = typeof FACILITY_CHOICES[number]["id"];
export type GroundedTripInput = {
  region_code?: string | null;
  visit_date: string | null;
  visit_time: string | null;
  required_facilities: RequiredFacility[];
};

export function isIsoDate(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}

export function parseGroundedTripInput(value: unknown): GroundedTripInput | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (Object.keys(row).filter((key) => key !== "region_code").sort().join("|") !== "required_facilities|visit_date|visit_time") return null;
  if (row.region_code != null && (typeof row.region_code !== "string" || !/^\d{2}$/.test(row.region_code))) return null;
  if (row.visit_date !== null && !isIsoDate(row.visit_date)) return null;
  if (row.visit_time !== null && (typeof row.visit_time !== "string" || !/^([01]\d|2[0-3]):[0-5]\d$/.test(row.visit_time))) return null;
  if (!Array.isArray(row.required_facilities) || row.required_facilities.length > FACILITY_CHOICES.length ||
    !row.required_facilities.every((id) => FACILITY_CHOICES.some((choice) => choice.id === id)) ||
    new Set(row.required_facilities).size !== row.required_facilities.length) return null;
  return {
    ...(typeof row.region_code === "string" ? { region_code: row.region_code } : {}),
    visit_date: row.visit_date as string | null,
    visit_time: row.visit_time as string | null,
    required_facilities: [...row.required_facilities].sort() as RequiredFacility[],
  };
}

export function readGroundedTripInput(): GroundedTripInput {
  try {
    const raw = window.sessionStorage.getItem(GROUNDED_TRIP_STORAGE_KEY);
    if (raw && raw.length <= 2_000) {
      const parsed = parseGroundedTripInput(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch {
    // An unavailable or invalid draft never manufactures a facility requirement.
  }
  return { visit_date: null, visit_time: null, required_facilities: [] };
}

export function writeGroundedTripInput(input: GroundedTripInput): boolean {
  const parsed = parseGroundedTripInput(input);
  if (!parsed) return false;
  try {
    window.sessionStorage.setItem(GROUNDED_TRIP_STORAGE_KEY, JSON.stringify(parsed));
    return true;
  } catch {
    return false;
  }
}

export function resetGroundedTripInput(): boolean {
  try {
    window.sessionStorage.removeItem(GROUNDED_TRIP_STORAGE_KEY);
    return true;
  } catch {
    return false;
  }
}

/** A chosen region is a candidate filter, separate from the user's experience profile. */
export function groundedTripForRecommendation(input = readGroundedTripInput()): GroundedTripInput | null {
  const parsed = parseGroundedTripInput(input);
  return parsed && (parsed.region_code != null || parsed.required_facilities.length > 0 || parsed.visit_time !== null) ? parsed : null;
}

export async function groundedTripInputSha256(input: GroundedTripInput | null): Promise<string | null> {
  if (input === null) return null;
  const parsed = parseGroundedTripInput(input);
  if (!parsed) throw new TypeError("Invalid grounded trip input");
  const bytes = new TextEncoder().encode(JSON.stringify({
    ...(parsed.region_code ? { region_code: parsed.region_code } : {}),
    required_facilities: parsed.required_facilities,
    schema_version: "grounded-trip-input.v1",
    visit_date: parsed.visit_date,
    visit_time: parsed.visit_time,
  }));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
