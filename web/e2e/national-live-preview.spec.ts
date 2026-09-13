import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";
import { expect, test, type Page, type Response } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { relative, resolve } from "node:path";
import type { GroundedDetail } from "../src/api/grounded-detail";
import type { GroundedResults, GroundedItem } from "../src/api/grounded-recommendation";
import type { TourismContext } from "../src/api/tourism-context";
import type { TravelRegion } from "../src/api/recommendation-regions";

/** Real browser → application session → normal local API → PostgreSQL.
 * No routes, response replacements, test-support endpoints, token injection,
 * catalogue promotion, uploads or model submissions are performed here. */
const enabled = process.env.ITDA_E2E_NATIONAL_LIVE === "1";
const repoRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
const outputRoot = resolve(process.env.ITDA_NATIONAL_LIVE_ARTIFACTS ?? resolve(repoRoot, "artifacts/national/20260909/verification/browser"));

const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}
type SourceSnapshot = {
  place: { place_id: string; name_ko: string; address: string; region_code: string; region_name: string; provider_content_id: string };
  category: string;
  evidence: Array<GroundedItem["evidence"][number] & { excerpt: string }>;
};
type NationalCandidate = {
  schema_version: string; candidate_sha256: string;
  raw_release: { schema_version: string; published_count: number; profiles: Array<{ place_id: string; profile_sha256: string; recommendation_eligible: boolean }> };
  source_snapshots: SourceSnapshot[];
  assessments: GroundedDetail["assessment"][];
  moods: GroundedDetail["mood"][];
};
type Profile = { profile_id: string; answers: Record<string, number>; scores: unknown; trip_conditions: unknown };
type ApiCall = { method: string; path: string; status: number };
type Body = { body: unknown; sha256: string };
const sightseeingCategories = new Set(["관광지", "문화시설", "레포츠", "축제·공연·행사"]);

function sourceManifest() {
  const paths: string[] = [];
  function walk(directory: string) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) paths.push(path);
    }
  }
  walk(resolve(repoRoot, "web/src"));
  for (const name of ["package.json", "pnpm-lock.yaml", "tsconfig.json", "next.config.ts"]) {
    const path = resolve(repoRoot, "web", name);
    if (existsSync(path)) paths.push(path);
  }
  const files = paths.sort().map((path) => ({ path: relative(repoRoot, path), sha256: hash(readFileSync(path)) }));
  return { files, sha256: hash(canonical(files)) };
}

function usableSources(candidate: NationalCandidate): SourceSnapshot[] {
  const assessments = new Map(candidate.assessments.map((row) => [row.place_id, row]));
  return candidate.source_snapshots.filter((source) => sightseeingCategories.has(source.category) &&
    ["H", "E", "R"].filter((axis) => assessments.get(source.place.place_id)?.dimensions[axis]?.value != null).length >= 2);
}

async function recordResponse(response: Pick<Response, "text">): Promise<Body> {
  const text = await response.text();
  return { body: JSON.parse(text) as unknown, sha256: hash(text) };
}

async function answerQuiz(page: Page): Promise<{ profile: Profile; response: Body }> {
  let final: Promise<Response> | null = null;
  for (const [index, question] of questionnaire.questions.entries()) {
    await expect(page.getByText(question.title_ko, { exact: true })).toBeVisible();
    await expect(page.getByText(`${index + 1} / ${questionnaire.questions.length}`, { exact: true })).toBeVisible();
    if (index === questionnaire.questions.length - 1) final = page.waitForResponse((response) =>
      response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/preference-profiles");
    await page.getByRole("radio", { name: question.options[index % question.options.length]!.text_ko, exact: true }).click();
  }
  expect(final).not.toBeNull();
  const response = await final!;
  expect(response.status()).toBe(201);
  const captured = await recordResponse(response);
  return { profile: captured.body as Profile, response: captured };
}

function assertItemSource(item: GroundedItem, candidate: NationalCandidate, regionCode: string | null) {
  const source = candidate.source_snapshots.find((row) => row.place.place_id === item.place_id)!;
  const profile = candidate.raw_release.profiles.find((row) => row.place_id === item.place_id)!;
  const assessment = candidate.assessments.find((row) => row.place_id === item.place_id)!;
  expect(source).toBeDefined();
  expect(profile).toBeDefined();
  expect(item.place_name_ko).toBe(source.place.name_ko);
  expect(item.region_code).toBe(source.place.region_code);
  expect(item.region_name).toBe(source.place.region_name);
  expect(item.address_ko).toBe(source.place.address);
  expect(source.place.provider_content_id).toBeTruthy();
  if (regionCode !== null) expect(item.region_code?.startsWith(regionCode)).toBe(true);
  expect(item.raw_profile_sha256).toBe(profile.profile_sha256);
  expect(item.assessment_bundle_sha256).toBe(assessment.bundle_sha256);
  expect(item.overall_confidence).toBeNull();
  expect(item.contribution.mood_weight).toBe(0);
  expect(item.evidence.length).toBeGreaterThan(0);
  for (const evidence of item.evidence) {
    const original = source.evidence.find((row) => row.evidence_id === evidence.evidence_id)!;
    expect(original).toBeDefined();
    expect(original.excerpt).toContain(evidence.quote);
    expect(evidence.receipt).toEqual(original.receipt);
    expect(evidence.place_match).toEqual(original.place_match);
  }
}

async function verifyRun(page: Page, profile: Profile, candidate: NationalCandidate, regionCode: string | null,
  viewportName: string, scope: "region" | "nationwide") {
  await expect(page.getByRole("heading", { name: "당신이 기대하는 여행의 시간" })).toBeVisible();
  await expect(page.getByText("취향에 맞는 볼거리·체험을 추천해요.")).toBeVisible();
  await expect(page.getByRole("combobox", { name: "추천 여행 목적" })).toHaveCount(0);
  const createdPromise = page.waitForResponse((response) => response.request().method() === "POST" &&
    new URL(response.url()).pathname === "/v1/recommendation-runs");
  const contextPromise = page.waitForResponse((response) => response.request().method() === "GET" &&
    /^\/v1\/recommendation-runs\/[^/]+\/tourism-context$/.test(new URL(response.url()).pathname));
  await page.getByRole("button", { name: "바로 추천 보기", exact: true }).click();
  const createdHttp = await createdPromise;
  expect(createdHttp.status()).toBe(201);
  const createdResponse = await recordResponse(createdHttp);
  const created = createdResponse.body as { recommendation_run_id: string; preference_profile_id: string; request_id: string };
  const request = createdHttp.request().postDataJSON() as Record<string, unknown>;
  expect(Object.keys(request).some((key) => /candidate|kernel|config|score/.test(key))).toBe(false);
  expect(request.photo_job_id ?? null).toBeNull();
  const grounded = request.grounded_input as { region_code?: string | null } | undefined;
  expect(grounded?.region_code ?? null).toBe(regionCode);
  expect(created.preference_profile_id).toBe(profile.profile_id);
  await expect(page.locator("[data-grounded-run]")).toHaveAttribute("data-grounded-run", created.recommendation_run_id);
  const runPath = `/v1/recommendation-runs/${encodeURIComponent(created.recommendation_run_id)}`;
  const initialHttp = await page.request.get(runPath);
  expect(initialHttp.status()).toBe(200);
  const initialText = await initialHttp.text(), results = JSON.parse(initialText) as GroundedResults;
  expect(results.schema_version).toBe("itda.grounded-recommendation-results.v1");
  expect(results.run.authority.candidate_sha256).toBe(candidate.candidate_sha256);
  expect(results.run.preference.trip_input.region_code ?? null).toBe(regionCode);
  expect(results.run.preference.photo_input_sha256).toBeNull();
  expect(results.run.candidate_bindings.map((row) => row.place_id).sort()).toEqual(candidate.raw_release.profiles.map((row) => row.place_id).sort());
  const expectedEligible = usableSources(candidate).filter((source) => regionCode === null || source.place.region_code.startsWith(regionCode))
    .map((source) => source.place.place_id).sort();
  expect(results.run.eligible_place_ids).toEqual(expectedEligible);
  expect(new Set(results.run.items.map((item) => item.place_id)).size).toBe(5);
  results.run.items.forEach((item) => assertItemSource(item, candidate, regionCode));
  const cards = page.locator("[data-grounded-item]");
  await expect(cards).toHaveCount(5);
  for (const [index, item] of results.run.items.entries()) {
    await expect(cards.nth(index)).toHaveAttribute("data-grounded-item", item.place_id);
    await expect(cards.nth(index).locator("[data-place-region]")).toHaveText(item.region_name!);
    await expect(cards.nth(index).locator("[data-preference-similarity]")).toHaveText(`내 취향과 ${item.contribution.experience.score}% 유사`);
  }
  const contextHttp = await contextPromise;
  expect(contextHttp.status()).toBe(200);
  const contextResponse = await recordResponse(contextHttp), context = contextResponse.body as TourismContext;
  await expect(page.locator("[data-tourism-context-state]")).toHaveAttribute("data-tourism-context-state", "resolved");
  expect(context.recommendation_run_id).toBe(created.recommendation_run_id);
  expect(context.places.map((row) => row.place_id).sort()).toEqual(results.run.items.map((row) => row.place_id).sort());
  expect(context.temporal.ranking_effect).toBe("NONE");
  for (const forecast of context.temporal.forecasts) expect(forecast.region_code)
    .toBe(results.run.items.find((item) => item.place_id === forecast.place_id)!.region_code);

  const first = results.run.items[0]!, second = results.run.items[1]!;
  const saveButton = cards.first().getByRole("button", { name: `${first.place_name_ko} 저장`, exact: true });
  if (await saveButton.count()) await saveButton.click();
  const savedHttp = await page.request.get(`/v1/saved-place-references/${candidate.candidate_sha256}/${encodeURIComponent(first.place_id)}`);
  expect(savedHttp.status()).toBe(200);
  const savedResponse = await recordResponse(savedHttp);
  expect(savedResponse.body).toMatchObject({ place_id: first.place_id, state: "CURRENT", saved_release_sha256: candidate.candidate_sha256,
    resolved_release_sha256: candidate.candidate_sha256, region_code: first.region_code, region_name: first.region_name });
  await expect(page.getByRole("list", { name: "저장한 장소 목록" })).toContainText(first.region_name!);
  const screenshotPaths: string[] = [];
  const screenshot = async (kind: string) => {
    const path = resolve(outputRoot, `${scope}-${kind}-${viewportName}.png`);
    await page.screenshot({ path, fullPage: true });
    screenshotPaths.push(path);
  };
  await screenshot("results");
  for (const index of [0, 1]) await cards.nth(index).getByRole("button", {
    name: `${results.run.items[index]!.place_name_ko} 비교에 추가`, exact: true,
  }).click();
  const comparisonPromise = page.waitForResponse((response) => new URL(response.url()).pathname === `${runPath}/comparison`);
  await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
  const comparisonHttp = await comparisonPromise;
  expect(comparisonHttp.status()).toBe(200);
  const comparisonResponse = await recordResponse(comparisonHttp), comparison = comparisonResponse.body as { release_sha256: string; places: GroundedDetail[] };
  expect(comparison.release_sha256).toBe(candidate.candidate_sha256);
  expect(comparison.places.map((detail) => detail.item)).toEqual([first, second]);
  const table = page.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
  await expect(table).toBeVisible();
  for (const [index, item] of [first, second].entries()) {
    await expect(table.getByRole("columnheader").nth(index + 1)).toContainText(item.place_name_ko);
    await expect(table.getByRole("columnheader").nth(index + 1)).toContainText(item.region_name!);
  }
  await screenshot("comparison");
  await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
  const detailPromise = page.waitForResponse((response) => new URL(response.url()).pathname === `${runPath}/places/${encodeURIComponent(first.place_id)}`);
  await page.locator("[data-grounded-item]").first().getByRole("link", { name: `${first.place_name_ko} 상세 보기`, exact: true }).click();
  const detailHttp = await detailPromise;
  expect(detailHttp.status()).toBe(200);
  const detailResponse = await recordResponse(detailHttp), detail = detailResponse.body as GroundedDetail;
  expect(detail.item).toEqual(first);
  expect(detail.assessment).toEqual(candidate.assessments.find((row) => row.place_id === first.place_id));
  expect(detail.mood).toEqual(candidate.moods.find((row) => row.place_id === first.place_id));
  await expect(page.locator("[data-grounded-detail] > [data-place-region]")).toHaveText(first.address_ko!);
  const evidenceDisclosure = page.locator("[data-grounded-detail] details").filter({ has: page.getByText("추천에 사용한 근거 확인", { exact: true }) });
  await evidenceDisclosure.locator("summary").click();
  await expect(evidenceDisclosure).toContainText(first.evidence[0]!.quote);
  await screenshot("detail-evidence");
  await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
  await page.reload();
  await expect(page.locator("[data-grounded-item]")).toHaveCount(5);
  await expect(page.locator("[data-tourism-context-state]")).toHaveAttribute("data-tourism-context-state", "resolved");
  await expect(page.locator("[data-grounded-item]").first().getByRole("button", { name: `${first.place_name_ko} 저장됨`, exact: true }))
    .toHaveAttribute("aria-pressed", "true");
  const replayHttp = await page.request.get(runPath), replayText = await replayHttp.text();
  expect(replayHttp.status()).toBe(200);
  expect(replayText).toBe(initialText);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  return { scope, region_code: regionCode, created_response: createdResponse, request, results, result_body_sha256: hash(initialText),
    replay_body_sha256: hash(replayText), comparison: comparisonResponse, detail: detailResponse, saved_reference: savedResponse,
    tourism_context: contextResponse, expected_eligible_count: expectedEligible.length,
    screenshots: screenshotPaths.map((path) => ({ path: relative(repoRoot, path), sha256: hash(readFileSync(path)) })) };
}

for (const [viewportIndex, viewport] of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }].entries()) {
  test(`national current catalogue with a real session (${viewport.name})`, async ({ page }, testInfo) => {
    test.skip(!enabled, "Requires the real national candidate, active DB and already running API/frontend.");
    const candidatePath = process.env.ITDA_NATIONAL_CANDIDATE_PATH;
    expect(candidatePath, "ITDA_NATIONAL_CANDIDATE_PATH is required").toBeTruthy();
    const candidateBytes = readFileSync(resolve(repoRoot, candidatePath!));
    const candidate = JSON.parse(candidateBytes.toString("utf8")) as NationalCandidate;
    expect(candidate.schema_version).toBe("grounded-release-candidate.v1");
    expect(candidate.raw_release.schema_version).toBe("grounded-source-release.v1");
    expect(candidate.candidate_sha256).toMatch(/^[0-9a-f]{64}$/);
    if (process.env.ITDA_NATIONAL_CANDIDATE_SHA256) expect(candidate.candidate_sha256).toBe(process.env.ITDA_NATIONAL_CANDIDATE_SHA256);
    expect(candidate.raw_release.published_count).toBeGreaterThanOrEqual(800);
    expect(candidate.raw_release.published_count).toBeLessThanOrEqual(1000);
    const ids = candidate.raw_release.profiles.map((row) => row.place_id).sort();
    expect(new Set(ids).size).toBe(candidate.raw_release.published_count);
    expect(candidate.source_snapshots.map((row) => row.place.place_id).sort()).toEqual(ids);
    expect(candidate.assessments.map((row) => row.place_id).sort()).toEqual(ids);
    expect(candidate.moods.map((row) => row.place_id).sort()).toEqual(ids);
    const frontend = sourceManifest(), startedAt = new Date().toISOString();
    mkdirSync(outputRoot, { recursive: true });
    const apiCalls: ApiCall[] = [], pageErrors: string[] = [], externalOrigins = new Set<string>();
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.pathname.startsWith("/v1/")) apiCalls.push({ method: response.request().method(), path: url.pathname, status: response.status() });
      if (["http:", "https:"].includes(url.protocol) && url.origin !== new URL(page.url()).origin) externalOrigins.add(url.origin);
    });
    await page.setViewportSize(viewport);
    const regionsPromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/v1/recommendation-regions");
    await page.goto("/start");
    const regionsHttp = await regionsPromise;
    expect(regionsHttp.status()).toBe(200);
    const regionsResponse = await recordResponse(regionsHttp), regionEnvelope = regionsResponse.body as { candidate_sha256: string; regions: TravelRegion[] };
    expect(regionEnvelope.candidate_sha256).toBe(candidate.candidate_sha256);
    const expectedRegions = new Map<string, { name: string; count: number }>();
    for (const source of usableSources(candidate)) {
      const code = source.place.region_code.slice(0, 2), name = source.place.region_name.split(/\s+/)[0]!;
      const previous = expectedRegions.get(code);
      if (previous) expect(previous.name).toBe(name);
      expectedRegions.set(code, { name, count: (previous?.count ?? 0) + 1 });
    }
    expect(regionEnvelope.regions).toEqual([...expectedRegions].sort(([a], [b]) => a.localeCompare(b))
      .map(([region_code, row]) => ({ region_code, region_name: row.name, place_count: row.count })));
    const selectable = regionEnvelope.regions.filter((region) => region.place_count >= 5).sort((a, b) => b.place_count - a.place_count || a.region_code.localeCompare(b.region_code));
    expect(selectable.length).toBeGreaterThan(1);
    const selected = selectable[viewportIndex % selectable.length]!;
    const regionSelect = page.getByRole("combobox", { name: "어디로 떠날까요?" });
    await expect(regionSelect.locator("option")).toHaveCount(regionEnvelope.regions.length + 1);
    await regionSelect.selectOption(selected.region_code);
    for (const label of ["해질녘", "친구", "도보·대중교통", "1시간 안팎", "상관없어요", "조금 피하고 싶어요"])
      await page.getByRole("radio", { name: label, exact: true }).check();
    await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
    const profileCreated = await answerQuiz(page);
    expect(Object.keys(profileCreated.profile.answers)).toHaveLength(questionnaire.questions.length);
    expect(profileCreated.profile.scores).toHaveLength(3);
    const cookie = (await page.context().cookies()).find((row) => row.name === "itda_current_profile");
    expect(cookie?.httpOnly).toBe(true);
    const selectedRun = await verifyRun(page, profileCreated.profile, candidate, selected.region_code, viewport.name, "region");

    await page.getByRole("link", { name: "여행 지역·방문 조건 수정", exact: true }).click();
    await page.getByRole("combobox", { name: "어디로 떠날까요?" }).selectOption("");
    const changedPromise = page.waitForResponse((response) => response.request().method() === "POST" && new URL(response.url()).pathname === "/v1/preference-profiles");
    await page.getByRole("button", { name: "수정 내용 반영하기", exact: true }).click();
    const changedHttp = await changedPromise;
    expect(changedHttp.status()).toBe(201);
    const changedResponse = await recordResponse(changedHttp), nationwideProfile = changedResponse.body as Profile;
    expect(nationwideProfile.answers).toEqual(profileCreated.profile.answers);
    expect(nationwideProfile.scores).toEqual(profileCreated.profile.scores);
    expect(nationwideProfile.trip_conditions).toEqual(profileCreated.profile.trip_conditions);
    const nationwideRun = await verifyRun(page, nationwideProfile, candidate, null, viewport.name, "nationwide");
    expect(nationwideRun.results.run.run_id).not.toBe(selectedRun.results.run.run_id);
    expect(nationwideRun.expected_eligible_count).toBeGreaterThan(selectedRun.expected_eligible_count);
    expect(apiCalls.filter((row) => row.method === "POST" && row.path === "/v1/recommendation-runs")).toHaveLength(2);
    expect(apiCalls.filter((row) => /\/photo-jobs(?:\/|$)/.test(row.path))).toEqual([]);
    expect(apiCalls.filter((row) => row.status >= 400)).toEqual([]);
    expect(pageErrors).toEqual([]);
    expect(sourceManifest().sha256).toBe(frontend.sha256);
    expect(hash(readFileSync(resolve(repoRoot, candidatePath!)))).toBe(hash(candidateBytes));
    const record = {
      schema_version: "national-live-browser-verification.v1", mode: "UNMOCKED_BROWSER_NORMAL_API_SESSION_POSTGRES",
      started_at: startedAt, completed_at: new Date().toISOString(), viewport,
      candidate_sha256: candidate.candidate_sha256, candidate_file: relative(repoRoot, resolve(repoRoot, candidatePath!)), candidate_file_sha256: hash(candidateBytes),
      published_count: candidate.raw_release.published_count, region_response: regionsResponse, selected_region: selected,
      frontend_sources: frontend, openapi_sha256: hash(readFileSync(resolve(repoRoot, "contracts/openapi.json"))),
      profile_responses: [profileCreated.response, changedResponse], runs: [selectedRun, nationwideRun], api_calls: apiCalls,
      browser_external_origins: [...externalOrigins].sort(), session_cookie: { name: cookie!.name, http_only: cookie!.httpOnly, same_site: cookie!.sameSite },
      checks: { candidate_complete_membership: true, actual_quiz: true, region_filter: true, nationwide_scope: true,
        candidate_evidence_detail_identity: true, saved_location: true, comparison: true, byte_identical_replay: true,
        api_response_replacements: 0, test_support_calls: 0, photo_endpoint_calls: 0, page_errors: pageErrors, horizontal_overflow: false },
      limitation: "This verifies real delivery and deterministic evidence binding, not human relevance or satisfaction. Backend provider availability is retained as observed.",
    };
    const path = resolve(outputRoot, `national-live-${viewport.name}.json`);
    writeFileSync(path, `${JSON.stringify({ ...record, evidence_sha256: hash(canonical(record)) }, null, 2)}\n`);
    await testInfo.attach(`national live ${viewport.name}`, { path, contentType: "application/json" });
  });
}
