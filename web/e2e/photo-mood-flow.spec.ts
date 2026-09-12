import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";
import { expect, test } from "@playwright/test";
import { readFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import type { MoodReview, ConfirmedMood, MoodCandidateSet } from "../src/api/visual-mood";

const MOOD_KEYS = ["greenery", "water", "open_composition", "traditional_appearance", "contemporary_design", "warm_light", "vivid_color", "night_lighting"] as const;
const MOOD_POLICY_SHA = "9e9687b4dce79ae4e592d8111c4876969d4f4a6db1af0497a72dbe4faef6e3c2" as const;
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
async function canonicalHash(value: unknown): Promise<string> { return createHash("sha256").update(canonical(value)).digest("hex"); }
function aggregateMoodBatches(batches: MoodCandidateSet[], selected: string[]) {
  return MOOD_KEYS.map((dimension) => {
    const rows = batches.flatMap((batch) => batch.candidates).filter((candidate) => candidate.observation.dimension === dimension && candidate.observation.state === "OBSERVED" && selected.includes(candidate.candidate_id));
    return { dimension, value: rows.length ? Math.floor(rows.reduce((sum, row) => sum + row.observation.level! * 25, 0) / rows.length + 0.5) : null,
      distinct_images: rows.length, candidate_ids: rows.map((row) => row.candidate_id).sort() };
  });
}

// The questionnaire/profile use the configured local API (synthetic in the design gate). Photo model responses and
// recommendation outputs are explicitly synthetic contract fixtures. The real
// photo sanitation/SQL/confirmation lifecycle is covered separately in PG tests.

const grounded = JSON.parse(readFileSync(resolve("fixtures/grounded-synthetic-v5.json"), "utf8"));
const artifactRoot = resolve("../artifacts/reports/photo-mood-browser");
mkdirSync(artifactRoot, { recursive: true });
const image = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");

async function reviewFor(profileId: string, jobId: string): Promise<MoodReview> {
  const candidates = await Promise.all(MOOD_KEYS.map(async (dimension) => {
    const observed = ["greenery", "water", "open_composition"].includes(dimension);
    const observation = { dimension, state: observed ? "OBSERVED" as const : "UNKNOWN" as const,
      level: observed ? 3 : null, certainty: observed ? "HIGH" as const : "LOW" as const };
    return { observation, candidate_id: await canonicalHash({ job_id: jobId, image: "b".repeat(64), observation,
      provider_id: "fixture-glm-mood", policy_sha256: MOOD_POLICY_SHA }) };
  }));
  const fields = { schema_version: "photo-mood-candidates.v1" as const, family: "photo-mood-v1" as const,
    mood_version: "visual-mood-v1" as const, authority_scope: "VISUAL_MOOD_ONLY" as const, job_id: jobId,
    image_index: 1, payload_sha256: "b".repeat(64), policy_sha256: MOOD_POLICY_SHA as typeof MOOD_POLICY_SHA,
    provider_id: "fixture-glm-mood", analysis_kind: "MODEL" as const, model: "glm-5.3-flash" as const, candidates };
  const batch = { ...fields, candidate_set_sha256: await canonicalHash(fields) };
  return { schema_version: "photo-mood-review.v1", family: "photo-mood-v1", job_id: jobId, preference_profile_id: profileId,
    draft_sha256: await canonicalHash({ schema_version: "photo-mood-draft.v1", job_id: jobId,
      preference_profile_id: profileId, policy_sha256: MOOD_POLICY_SHA, candidate_set_sha256: [batch.candidate_set_sha256] }),
    batches: [batch], confirmation: null };
}

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`quiz → image mood → bound recommendation (${viewport.name}, contract fixture)`, async ({ page }, info) => {
    test.setTimeout(120_000);
    await page.setViewportSize(viewport);
    const errors: string[] = [], requests: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const jobId = "a".repeat(64);
    let profile: Record<string, any> | null = null, review: MoodReview | null = null;
    let confirmation: ConfirmedMood | null = null;
    let recommendationBody: Record<string, unknown> | null = null;
    let recommendationPosts = 0, confirmPosts = 0;
    await page.route("**/*", async (route) => {
      const request = route.request(), url = new URL(request.url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) return route.abort();
      if (url.pathname.startsWith("/v1/photo-jobs")) {
        requests.push(`${request.method()} ${url.pathname}`);
        if (!profile) throw new Error("photo started before an actual profile existed");
        let payload: unknown;
        if (url.pathname.endsWith("/moods/confirm")) {
          confirmPosts += 1;
          const input = request.postDataJSON();
          expect(Object.keys(input).sort()).toEqual(["choices", "draft_sha256"]);
          expect(input.choices.every((row: object) => Object.keys(row).sort().join(",") === "candidate_id,included")).toBe(true);
          const fields = { schema_version: "photo-mood-projection.v1" as const, family: "photo-mood-v1" as const,
            job_id: jobId, preference_profile_id: String(profile.profile_id), policy_sha256: MOOD_POLICY_SHA as typeof MOOD_POLICY_SHA,
            draft_sha256: review!.draft_sha256, candidate_set_sha256: review!.batches.map((row) => row.candidate_set_sha256),
            choices: input.choices, moods: aggregateMoodBatches(review!.batches, input.choices.filter((row: { included: boolean }) => row.included).map((row: { candidate_id: string }) => row.candidate_id))! };
          confirmation = { ...fields, receipt_id: await canonicalHash(fields) };
          payload = confirmation;
        } else if (url.pathname.endsWith("/moods")) payload = { ...review, confirmation };
        else if (url.pathname.includes("/traits")) throw new Error("mood flow attempted factual-trait API");
        else if (url.pathname.includes("/images/")) payload = { job_id: jobId, image_index: 1, byte_length: request.postDataBuffer()!.length };
        else if (url.pathname.endsWith("/submit")) payload = { job_id: jobId, state: "succeeded" };
        else if (url.pathname === "/v1/photo-jobs") payload = { job_id: jobId, preference_profile_id: profile.profile_id, state: "queued",
          consent_version: "photo-consent-2026-08-v1", analysis_family: "photo-mood-v1" };
        else payload = { job_id: jobId, preference_profile_id: profile.profile_id, state: "succeeded", terminal_cause: "success", cleanup_pending: false, analysis_family: "photo-mood-v1" };
        return route.fulfill({ status: url.pathname === "/v1/photo-jobs" ? 201 : 200, contentType: "application/json", body: JSON.stringify(payload) });
      }
      if (url.pathname === "/v1/recommendation-runs" && request.method() === "POST") {
        recommendationPosts += 1;
        recommendationBody = request.postDataJSON();
        return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ schema_version: "itda.recommendation-run-created.v1",
          recommendation_run_id: grounded.results.run.run_id, request_id: recommendationBody!.request_id,
          preference_profile_id: profile!.profile_id, preference_input_sha256: await canonicalHash({ questionnaire_version: profile!.questionnaire_version,
            scoring_version: profile!.scoring_version, description_template_version: profile!.description_template_version,
            config_hash: profile!.config_hash, trip_conditions: profile!.trip_conditions, answers: profile!.answers }) }) });
      }
      if (url.pathname.startsWith("/v1/recommendation-runs/")) {
        if (url.pathname.endsWith("/tourism-context") || url.pathname.endsWith("/operating-information")) return route.fulfill({ status: 503, contentType: "application/json", body: "{}" });
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(grounded.results) });
      }
      return route.fallback();
    });
    await page.goto("/start");
    for (const label of ["해질녘", "친구", "도보·대중교통", "1시간 안팎", "상관없어요", "조금 피하고 싶어요"]) {
      await page.getByRole("radio", { name: label, exact: true }).check();
    }
    await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
    const posted = page.waitForResponse((response) => response.url().endsWith("/v1/preference-profiles") && response.request().method() === "POST");
    for (const question of questionnaire.questions) {
      await page.getByRole("radio", { name: question.options[0].text_ko, exact: true }).click();
    }
    const response = await posted;
    expect(response.status()).toBe(201);
    profile = await response.json(); review = await reviewFor(String(profile!.profile_id), jobId);
    await expect(page.getByRole("button", { name: "바로 추천 보기", exact: true })).toBeVisible();
    const before = await page.locator(".axis-score-list").allTextContents();
    await page.getByRole("button", { name: "사진 추천 페이지 열기" }).click();
    await expect(page).toHaveURL(/\/photo$/);
    await expect(page.getByRole("heading", { name: "사진 사용 내용을 먼저 확인해 주세요" })).toBeVisible();
    await page.screenshot({ path: info.outputPath("design-photo.png"), fullPage: true });
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "동의하고 사진 고르기" }).click();
    await page.locator('input[type="file"]').setInputFiles({ name: "fixture.png", mimeType: "image/png", buffer: image });
    await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();
    await expect(page.getByRole("heading", { name: "사진에서 마음에 든 분위기를 골라 주세요" })).toBeVisible();
    await expect(page.getByRole("checkbox")).toHaveCount(3);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.locator(".photo-review").screenshot({ path: resolve(artifactRoot, `mood-review-${viewport.name}.png`) });
    if (viewport.name === "mobile") for (const box of await page.getByRole("checkbox").all()) await box.uncheck();
    await page.getByRole("button", { name: viewport.name === "mobile" ? "사진 분위기 없이 계속" : "선택한 분위기로 계속", exact: true }).click();
    await expect(page.getByRole("button", { name: "사진 취향을 반영해 추천 보기" })).toBeVisible();
    await page.goto("/profile");
    await expect(page.locator(".axis-score-list")).toBeVisible();
    expect(await page.locator(".axis-score-list").allTextContents()).toEqual(before);
    await page.goto(`/photo/jobs/${jobId}`);
    await expect(page.getByRole("heading", { name: "사진 분위기 분석을 완료했어요" })).toBeVisible();
    expect(confirmPosts).toBe(1);
    const reference = await page.evaluate(() => JSON.parse(sessionStorage.getItem("itda.photo-mood-reference.v1")!));
    expect(reference.receipt_id).toBe(confirmation!.receipt_id);
    expect(Object.keys(reference).sort()).toEqual(["family", "photo_job_id", "preference_profile_id", "receipt_id", "schema_version"]);
    await page.reload();
    await page.getByRole("button", { name: "사진 취향을 반영해 추천 보기" }).click();
    await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeVisible();
    expect(recommendationBody!.photo_job_id).toBe(jobId);
    expect(Object.keys(recommendationBody!).some((key) => ["moods", "traits", "scores", "receipt_id"].includes(key))).toBe(false);
    expect(recommendationPosts).toBe(1);
    expect(requests.some((path) => path.includes("/traits"))).toBe(false);
    expect(errors).toEqual([]);
  });
}
