import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";
import { expect, test, type Page, type Response } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";

/** Optional actual browser → local FastAPI → PostgreSQL check. The caller must
 * first start the gated offline bootstrap. This spec never replaces API bodies
 * and must be run with a config that has no automatic webServer startup. */
const enabled = process.env.ITDA_E2E_GROUNDED_PREVIEW === "1";
const expectedCandidate = process.env.ITDA_E2E_GROUNDED_CANDIDATE_SHA256 ?? "";

const outputRoot = resolve(process.env.ITDA_E2E_GROUNDED_PREVIEW_ARTIFACTS ?? "../artifacts/reports/grounded-live-preview");
const tinyPng = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}
type ApiCall = { method: string; path: string; status: number };
function sourceManifest() {
  const paths: string[] = [];
  function walk(directory: string) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) paths.push(path);
    }
  }
  walk(resolve("src"));
  for (const name of ["package.json", "pnpm-lock.yaml", "tsconfig.json", "next.config.ts", "next.config.mjs"]) if (existsSync(name)) paths.push(resolve(name));
  const files = paths.sort().map((path) => ({ path: relative(resolve(".."), path), sha256: hash(readFileSync(path)) }));
  return { files, sha256: hash(canonical(files)) };
}

async function fillTrip(page: Page) {
  for (const label of ["해질녘", "친구", "도보·대중교통", "1시간 안팎", "상관없어요", "조금 피하고 싶어요"]) {
    await page.getByRole("radio", { name: label, exact: true }).check();
  }
}

async function answerQuiz(page: Page) {
  let final: Promise<Response> | null = null;
  for (const [index, question] of questionnaire.questions.entries()) {
    await expect(page.getByText(question.title_ko, { exact: true })).toBeVisible();
    await expect(page.getByText(`${index + 1} / 12`, { exact: true })).toBeVisible();
    if (index === questionnaire.questions.length - 1) final = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/preference-profiles");
    await page.getByRole("radio", { name: question.options[0]!.text_ko, exact: true }).click();
  }
  expect(final).not.toBeNull();
  const response = await final!;
  expect(response.status()).toBe(201);
  return response.json();
}

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`gated active preview real quiz → recommendation → saved replay (${viewport.name})`, async ({ page }, testInfo) => {
    test.skip(!enabled, "Requires an already running gated offline active-pointer preview.");
    test.setTimeout(120_000);
    expect(expectedCandidate).toMatch(/^[0-9a-f]{64}$/);
    mkdirSync(outputRoot, { recursive: true });
    const startedAt = new Date().toISOString();
    const frontend = sourceManifest();
    const apiCalls: ApiCall[] = [], pageErrors: string[] = [], blockedOrigins: string[] = [];
    page.on("response", (response) => {
      const path = new URL(response.url()).pathname;
      if (path.startsWith("/v1/")) apiCalls.push({ method: response.request().method(), path, status: response.status() });
    });
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
        blockedOrigins.push(url.origin);
        return route.abort();
      }
      // The allowed loopback request is passed through without body/header edits.
      return route.continue();
    });
    await page.setViewportSize(viewport);
    await page.goto("/start");
    await fillTrip(page);
    await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
    const profile = await answerQuiz(page);
    expect(Object.keys(profile.answers)).toHaveLength(12);
    await expect(page.getByRole("button", { name: "바로 추천 보기", exact: true })).toBeVisible();
    const createdResponse = page.waitForResponse((response) => response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/v1/recommendation-runs");
    await page.getByRole("button", { name: "바로 추천 보기", exact: true }).click();
    const createdHttp = await createdResponse;
    expect(createdHttp.status()).toBe(201);
    const created = await createdHttp.json();
    const requestBody = createdHttp.request().postDataJSON() as Record<string, unknown>;
    expect(Object.keys(requestBody).some((key) => /candidate|kernel|config|scores/.test(key))).toBe(false);
    expect(created.preference_profile_id).toBe(profile.profile_id);
    await expect(page.locator("[data-grounded-run]")).toHaveAttribute("data-grounded-run", created.recommendation_run_id);
    const runPath = `/v1/recommendation-runs/${encodeURIComponent(created.recommendation_run_id)}`;
    const initialHttp = await page.request.get(runPath);
    expect(initialHttp.status()).toBe(200);
    const initialText = await initialHttp.text(), results = JSON.parse(initialText);
    expect(results.schema_version).toBe("itda.grounded-recommendation-results.v1");
    expect(results.run.authority.candidate_sha256).toBe(expectedCandidate);
    expect(results.run.authority.kernel_version).toBe("recommendation-kernel-v5");
    expect(results.run.preference.profile_id).toBe(profile.profile_id);
    const cards = page.locator("[data-grounded-item]");
    await expect(cards).toHaveCount(5);
    const initialScores = await cards.locator(".recommendation-fit").allTextContents();
    expect(initialScores).toEqual(results.run.items.map((item: { contribution: { experience: { score: number } } }) => `내 취향과 ${item.contribution.experience.score}% 유사`));
    const first = results.run.items[0], second = results.run.items[1];
    const axisLabels: Record<string, string> = { H: "역사·전통", E: "감성·이미지", R: "휴식·몰입" };
    for (const component of first.contribution.experience.components) {
      const axis = cards.first().locator(`[data-supported-axis="${component.key}"]`);
      if (component.fit === null) {
        await expect(axis.getByRole("meter")).toHaveCount(0);
        await expect(axis).toContainText("비교 어려움");
      } else {
        await expect(axis.getByRole("meter", { name: `${axisLabels[component.key]} 취향 유사도 ${component.fit}%` }))
          .toHaveAttribute("aria-valuenow", String(component.fit));
      }
    }
    await expect(page.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toBeEnabled();
    const contextHttp = await page.request.get(`${runPath}/tourism-context`);
    expect(contextHttp.status()).toBe(200);
    const sourceContext = await contextHttp.json();
    expect(sourceContext.source_health).toHaveLength(7);
    expect(sourceContext.source_health.every((source: { state: string; http_attempt_count: number }) =>
      source.state === "UNAVAILABLE" && source.http_attempt_count === 0)).toBe(true);
    await cards.first().getByRole("button", { name: `${first.place_name_ko} 저장`, exact: true }).click();
    await cards.first().getByRole("button", { name: `${first.place_name_ko} 비교에 추가`, exact: true }).click();
    await cards.nth(1).getByRole("button", { name: `${second.place_name_ko} 비교에 추가`, exact: true }).click();
    const comparisonResponse = page.waitForResponse((response) => new URL(response.url()).pathname === `${runPath}/comparison`);
    await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
    const comparisonHttp = await comparisonResponse;
    expect(comparisonHttp.status()).toBe(200);
    const comparison = await comparisonHttp.json();
    expect(comparison.release_sha256).toBe(expectedCandidate);
    expect(comparison.places.map((place: { item: unknown }) => place.item)).toEqual(results.run.items.slice(0, 2));
    const comparisonTable = page.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
    await expect(comparisonTable).toBeVisible();
    await expect(comparisonTable.getByRole("row", { name: /^내 취향과의 유사도/ }).locator("td"))
      .toHaveText([first, second].map((item) => `${item.contribution.experience.score}%`));
    await page.screenshot({ path: resolve(outputRoot, `live-comparison-${viewport.name}.png`), fullPage: true });
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    const detailResponse = page.waitForResponse((response) => new URL(response.url()).pathname === `${runPath}/places/${encodeURIComponent(first.place_id)}`);
    await page.getByRole("link", { name: `${first.place_name_ko} 상세 보기`, exact: true }).click();
    const detailHttp = await detailResponse;
    expect(detailHttp.status()).toBe(200);
    const detail = await detailHttp.json();
    expect(detail.release_sha256).toBe(expectedCandidate);
    expect(detail.item).toEqual(first);
    await expect(page.locator("[data-grounded-detail]")).toHaveAttribute("data-grounded-detail", first.place_id);
    await expect(page.locator("[data-grounded-detail] [data-preference-similarity]"))
      .toHaveText(`내 취향과 ${first.contribution.experience.score}% 유사`);
    await page.screenshot({ path: resolve(outputRoot, `live-detail-${viewport.name}.png`), fullPage: true });
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    await expect(page.getByRole("button", { name: `${first.place_name_ko} 저장됨`, exact: true })).toHaveAttribute("aria-pressed", "true");
    const savedHttp = await page.request.get(`/v1/saved-place-references/${expectedCandidate}/${encodeURIComponent(first.place_id)}`);
    expect(savedHttp.status()).toBe(200);
    const saved = await savedHttp.json();
    expect(saved.saved_release_sha256).toBe(expectedCandidate);
    expect(saved.place_id).toBe(first.place_id);
    await page.reload();
    await expect(cards).toHaveCount(5);
    expect(await cards.locator(".recommendation-fit").allTextContents()).toEqual(initialScores);
    const replayHttp = await page.request.get(runPath);
    const replayText = await replayHttp.text();
    expect(replayHttp.status()).toBe(200);
    expect(replayText).toBe(initialText);
    expect(apiCalls.filter((call) => call.method === "POST" && call.path === "/v1/recommendation-runs")).toHaveLength(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: resolve(outputRoot, `live-results-${viewport.name}.png`), fullPage: true });

    let photoEvidence: Record<string, unknown> | null = null;
    if (viewport.name === "desktop" && process.env.ITDA_E2E_PREVIEW_PROBE_PHOTO === "1") {
      // The bootstrap enforces ITDA_NO_NETWORK=1; exercise real upload and the
      // disabled-provider path without a paid model request or mock provider.
      await page.goto("/profile");
      await page.getByRole("button", { name: "사진 추천 페이지 열기" }).click();
      await page.getByRole("checkbox").check();
      await page.getByRole("button", { name: "동의하고 사진 고르기" }).click();
      await page.locator('input[type="file"]').setInputFiles({ name: "offline-preview.png", mimeType: "image/png", buffer: tinyPng });
      const jobResponse = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/photo-jobs");
      const submitResponse = page.waitForResponse((response) => response.request().method() === "POST" && /\/v1\/photo-jobs\/[^/]+\/submit$/.test(new URL(response.url()).pathname));
      await page.getByRole("button", { name: "사진 1장 분석 시작하기" }).click();
      const jobHttp = await jobResponse, job = await jobHttp.json();
      expect(jobHttp.status()).toBe(201);
      expect(job.analysis_family).toBe("photo-mood-v1");
      const submit = await submitResponse;
      expect(submit.status()).toBe(503);
      await expect(page.getByRole("heading", { name: "사진 분석을 마치지 못했어요." })).toBeVisible();
      await expect(page.getByRole("button", { name: "사진 없이 추천 5곳 보기", exact: true })).toBeVisible();
      await page.screenshot({ path: resolve(outputRoot, "live-photo-disabled-desktop.png"), fullPage: true });
      const stateHttp = await page.request.get(`/v1/photo-jobs/${job.job_id}`);
      const state = await stateHttp.json();
      expect(stateHttp.status()).toBe(200);
      expect(state.analysis_family).toBe("photo-mood-v1");
      expect(state.state).toBe("failed");
      expect(state.cleanup_pending).toBe(false);
      const deletionResponse = page.waitForResponse((response) => response.request().method() === "DELETE" && new URL(response.url()).pathname === `/v1/photo-jobs/${job.job_id}`);
      await page.getByRole("button", { name: "사진 없이 추천 5곳 보기", exact: true }).click();
      const deletionHttp = await deletionResponse, deletion = await deletionHttp.json();
      expect(deletionHttp.status()).toBe(200);
      expect(deletion.state).toBe("deleted");
      expect(deletion.cleanup_pending).toBe(false);
      photoEvidence = { job_id: job.job_id, family: job.analysis_family, submit_status: submit.status(), state: state.state,
        cleanup_pending: state.cleanup_pending, deletion_state: deletion.state, deletion_cleanup_pending: deletion.cleanup_pending };
    }
    expect(pageErrors).toEqual([]);
    expect(sourceManifest().sha256).toBe(frontend.sha256);
    const screenshots = ["comparison", "detail", "results"].map((kind) => {
      const path = resolve(outputRoot, `live-${kind}-${viewport.name}.png`);
      return { path, sha256: hash(readFileSync(path)) };
    });
    const record = {
      schema_version: "grounded-live-preview-browser.v1", mode: "UNMOCKED_BROWSER_LOCAL_API_POSTGRES",
      started_at: startedAt, completed_at: new Date().toISOString(), viewport,
      candidate_sha256: expectedCandidate, run_id: results.run.run_id, run_sha256: results.run.canonical_sha256,
      profile_id: profile.profile_id, request_id: created.request_id, mocked_api_responses: 0,
      source_context_mode: "OFFLINE_BOOTSTRAP_EXPLICITLY_DISABLED", browser_payload_candidate_selectors: 0,
      frontend_sources: frontend, openapi_sha256: hash(readFileSync(resolve("../contracts/openapi.json"))),
      provider_execution: "DISABLED_BY_OFFLINE_BOOTSTRAP", api_calls: apiCalls, blocked_external_origins: [...new Set(blockedOrigins)],
      checks: { actual_quiz_answers: 12, active_candidate_response: true, save_compare_detail: true, replay_response_bytes_identical: true,
        disabled_source_consumers: 7, page_errors: pageErrors, page_horizontal_overflow: false },
      observed_responses: { created, results, comparison, detail, saved_reference: saved, tourism_context: sourceContext },
      response_body_sha256: { results: hash(initialText), replay: hash(replayText), created: hash(await createdHttp.text()),
        comparison: hash(await comparisonHttp.text()), detail: hash(await detailHttp.text()), saved_reference: hash(await savedHttp.text()),
        tourism_context: hash(await contextHttp.text()) },
      photo: photoEvidence, screenshots,
    };
    const output = { ...record, evidence_sha256: hash(canonical(record)) };
    const path = resolve(outputRoot, `live-preview-${viewport.name}.json`);
    writeFileSync(path, JSON.stringify(output, null, 2) + "\n");
    await testInfo.attach(`actual default preview ${viewport.name}`, { path, contentType: "application/json" });
  });
}
