import type { components } from "../../contracts/generated/api";

export type Definition = components["schemas"]["Definition"];
export type Info = components["schemas"]["ServiceInfo"];
export type Intent = components["schemas"]["Intent"];
export type Submission = components["schemas"]["IntentSubmission"];
export type Run = components["schemas"]["RunResult"];
export type Detail = components["schemas"]["Detail"];
export type Photo = components["schemas"]["PhotoReview"];
export type Facet = Definition["questions"][number]["key"];
export type Axis = "H" | "E" | "R";
const tokenKey = "itda.authenticity.session.v1";

export class JourneyError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}
export function currentToken(): string | null {
  try { return sessionStorage.getItem(tokenKey); } catch { return null; }
}
export function clearToken() { try { sessionStorage.removeItem(tokenKey); } catch { /* unavailable */ } }
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  const token = currentToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(`/v1/authenticity${path}`, { ...options, headers, cache: "no-store" });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401) clearToken();
    throw new JourneyError(response.status, typeof body?.detail === "string" ? body.detail : "요청을 완료하지 못했습니다. 다시 시도해 주세요.");
  }
  return body as T;
}
export async function ensureSession(): Promise<void> {
  if (currentToken()) return;
  const session = await api<components["schemas"]["SessionCreated"]>("/sessions", { method: "POST" });
  try { sessionStorage.setItem(tokenKey, session.token); }
  catch { throw new JourneyError(0, "이 브라우저에서 여행 세션을 저장할 수 없습니다. 저장 권한을 확인해 주세요."); }
}
export const json = (value: unknown) => JSON.stringify(value);
export const escapeId = (id: string) => encodeURIComponent(id);
