import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";

const resultsFixture = JSON.parse(readFileSync(resolve("fixtures/grounded-synthetic-v5.json"), "utf8"));
const tourismFixture = JSON.parse(readFileSync(resolve("fixtures/tourism-synthetic-v2.json"), "utf8"));
const fixturePath = process.env.ITDA_GROUNDED_E2E_FIXTURE ? resolve(process.env.ITDA_GROUNDED_E2E_FIXTURE) : null;
const fixtureBytes = fixturePath ? readFileSync(fixturePath) : null;
const rawFixture = fixturePath
  ? JSON.parse(fixtureBytes!.toString("utf8"))
  : { ...resultsFixture, context: tourismFixture.grounded_context };
// The facade capture uses singular detail/tourism_context keys. Only the test
// envelope is adapted; sealed payload values and hash fields remain unchanged.
const fixture = { ...rawFixture, context: rawFixture.context ?? rawFixture.tourism_context,
  details: rawFixture.details ?? [...new Map([rawFixture.detail, ...rawFixture.comparison.places]
    .filter(Boolean).map((detail: { item: { place_id: string } }) => [detail.item.place_id, detail])).values()] };
const artifacts = resolve(process.env.ITDA_GROUNDED_E2E_ARTIFACT_DIR ?? (fixturePath
  ? "../artifacts/reports/source-grounded-browser-pg-20260909" : "../artifacts/reports/source-grounded-browser"));
mkdirSync(artifacts, { recursive: true });
const sha256 = (content: string | Buffer) => createHash("sha256").update(content).digest("hex");
const fixtureSha256 = fixtureBytes ? sha256(fixtureBytes) : null;
const specSha256 = sha256(readFileSync(resolve("e2e/source-grounded-recommendation.spec.ts")));
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`).join(",")}}`;
  return JSON.stringify(value);
}
function frontendManifest() {
  const files: string[] = [];
  function walk(directory: string) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) files.push(path);
    }
  }
  walk(resolve("src"));
  for (const name of ["package.json", "pnpm-lock.yaml", "tsconfig.json", "next.config.ts", "next.config.mjs"]) if (existsSync(name)) files.push(resolve(name));
  const rows = files.sort().map((path) => ({ path: relative(resolve(".."), path), sha256: sha256(readFileSync(path)) }));
  return { files: rows, sha256: sha256(canonical(rows)) };
}

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`grounded result/detail/compare/save (${viewport.name}, validated-response replay)`, async ({ page }, testInfo) => {
    test.setTimeout(90_000);
    const startedAt = new Date().toISOString();
    const frontend = frontendManifest();
    const openapiSha256 = sha256(readFileSync(resolve("../contracts/openapi.json")));
    await page.setViewportSize(viewport);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    let posts = 0;
    let contextRequests = 0;
    let capturedSavedLookups = 0;
    const run = fixture.results.run;
    const photoRun = fixture.photo?.results?.run;
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) return route.abort();
      if (!url.pathname.startsWith("/v1/")) return route.fallback();
      if (route.request().method() === "POST") posts += 1;
      let payload: unknown;
      if (url.pathname.endsWith("/tourism-context")) {
        if (photoRun && url.pathname.includes(encodeURIComponent(photoRun.run_id))) {
          // No temporal response for this photo run was captured. Exercise the
          // explicit unavailable path without rewriting another run's context.
          return route.fulfill({ status: 503, contentType: "application/json", body: "{}" });
        }
        contextRequests += 1; payload = fixture.context;
      }
      else if (url.pathname.endsWith("/comparison")) payload = fixture.comparison;
      else if (url.pathname.includes("/places/")) payload = fixture.details.find((detail: { item: { place_id: string } }) => detail.item.place_id === decodeURIComponent(url.pathname.split("/").at(-1)!));
      else if (url.pathname.includes("/saved-place-references/")) {
        const placeId = decodeURIComponent(url.pathname.split("/").at(-1)!);
        const captured = fixture.saved_reference ?? fixture.saved_lookup;
        if (captured) {
          if (captured.place_id === placeId && url.pathname.includes(captured.saved_release_sha256)) {
            payload = captured;
            capturedSavedLookups += 1;
          }
        } else payload = { place_id: placeId, place_name_ko: run.items.find((item: { place_id: string }) => item.place_id === placeId).place_name_ko,
          saved_release_sha256: run.authority.candidate_sha256, resolved_release_sha256: run.authority.candidate_sha256, state: "CURRENT", state_reason: null };
      } else if (url.pathname.startsWith("/v1/recommendation-runs/")) payload = photoRun && url.pathname.endsWith(encodeURIComponent(photoRun.run_id))
        ? fixture.photo.results : fixture.results;
      else return route.fallback();
      return route.fulfill({ status: payload ? 200 : 404, contentType: "application/json", body: JSON.stringify(payload ?? {}) });
    });
    await page.goto(`/recommendations/${encodeURIComponent(run.run_id)}`);
    await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeVisible();
    const cards = page.locator("[data-grounded-item]");
    await expect(cards).toHaveCount(5);
    const first = cards.first();
    const experienceComponents = run.items[0].contribution.experience.components;
    await expect(first.getByRole("meter")).toHaveCount(experienceComponents.filter((component: { fit: number | null }) => component.fit !== null).length);
    const axisLabels: Record<string, string> = { H: "역사·전통", E: "감성·이미지", R: "휴식·몰입" };
    for (const component of experienceComponents) {
      const axis = first.locator(`[data-supported-axis="${component.key}"]`);
      if (component.fit === null) {
        await expect(axis.getByRole("meter")).toHaveCount(0);
        await expect(axis).toContainText("비교 어려움");
      } else {
        await expect(axis.getByRole("meter", { name: `${axisLabels[component.key]} 취향 유사도 ${component.fit}%` }))
          .toHaveAttribute("aria-valuenow", String(component.fit));
      }
    }
    await expect(page.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toBeEnabled();
    expect(contextRequests).toBe(1);
    const fonts = await page.locator("[data-grounded-run] h1, [data-grounded-run] button, [data-grounded-run] summary").evaluateAll((elements) =>
      [...new Set(elements.map((element) => getComputedStyle(element).fontFamily))]);
    expect(fonts).toHaveLength(1);
    const initialScores = await cards.locator(".recommendation-fit").allTextContents();
    expect(initialScores).toEqual(run.items.map((item: { contribution: { experience: { score: number } } }) => `내 취향과 ${item.contribution.experience.score}% 유사`));
    await page.getByRole("button", { name: "방문 참고 정보 다시 확인" }).click();
    await expect(page.getByRole("button", { name: "방문 참고 정보 다시 확인" })).toBeEnabled();
    expect(await cards.locator(".recommendation-fit").allTextContents()).toEqual(initialScores);
    const placeSummary = first.locator("summary").filter({ hasText: "방문 참고 정보" });
    const forecast = fixture.context.temporal.forecasts.find((row: { place_id: string }) => row.place_id === run.items[0].place_id);
    if (forecast?.state === "AVAILABLE" && forecast.value !== null) {
      await placeSummary.click();
      await expect(first.getByRole("heading", { name: "방문 집중 예측" })).toBeVisible();
      await expect(first.getByText(/실시간 인원이나 장소 간 혼잡 비교 수치가 아닙니다/)).toBeVisible();
    } else if (await placeSummary.count() > 0) {
      await placeSummary.click();
      await expect(first.getByRole("heading", { name: "방문 집중 예측" })).toHaveCount(0);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await first.screenshot({ path: resolve(artifacts, `grounded-card-${viewport.name}.png`) });
    if (await placeSummary.count() > 0) await placeSummary.click();
    const visitors = fixture.context.temporal.regional_visitors ?? [fixture.context.temporal.visitors];
    for (const region of visitors) {
      const points = region.state === "UNKNOWN" ? [] : region.points.filter((point: { state: string; value: string | null }) => point.state === "AVAILABLE" && point.value !== null);
      const title = `${region.region_name} 방문자 추이`;
      if (points.length > 0) {
        await page.getByText(title, { exact: true }).click();
        await expect(page.getByRole("region", { name: title, exact: true }).getByRole("table").locator("tbody tr")).toHaveCount(points.length);
        await page.getByText(title, { exact: true }).click();
      } else await expect(page.locator("summary").filter({ hasText: title })).toHaveCount(0);
    }
    await expect(page.getByRole("region", { name: "공식 여행 자료 제공 상태" })).toHaveCount(0);
    const allDemand = fixture.context.temporal.regional_demand ?? fixture.context.temporal.demand;
    for (const code of [...new Set<string>(allDemand.map((row: { region_code: string }) => row.region_code))]) {
      const rows = allDemand.filter((row: { region_code: string }) => row.region_code === code);
      const demand = rows.filter((row: { state: string }) => row.state === "AVAILABLE");
      const title = `${rows[0].region_name} 관광 수요 지수`;
      if (demand.length > 0) {
        await page.locator("summary").filter({ hasText: title }).click();
        const indices = page.getByRole("region", { name: title, exact: true });
        for (const row of demand) await expect(indices.locator("strong").filter({ hasText: row.measures[0].value })).toBeVisible();
        await expect(indices).toContainText(`${rows[0].region_name} 전체`);
        await expect(indices.getByRole("meter")).toHaveCount(0);
        expect(await indices.innerText()).not.toMatch(/%|\/\s*100|\d(?:원|명)/);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
        await indices.screenshot({ path: resolve(artifacts, `grounded-demand-${code}-${viewport.name}.png`) });
        await page.locator("summary").filter({ hasText: title }).click();
      } else await expect(page.locator("summary").filter({ hasText: title })).toHaveCount(0);
    }
    await first.getByRole("button", { name: `${run.items[0].place_name_ko} 저장`, exact: true }).click();
    for (const selected of fixture.comparison.places) {
      await page.locator(`[data-grounded-item="${selected.item.place_id}"]`)
        .getByRole("button", { name: `${selected.item.place_name_ko} 비교에 추가`, exact: true }).click();
    }
    await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
    const comparisonTable = page.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
    await expect(comparisonTable).toBeVisible();
    await expect(comparisonTable.getByRole("row", { name: /^내 취향과의 유사도/ }).locator("td"))
      .toHaveText(fixture.comparison.places.map((detail: { item: { contribution: { experience: { score: number } } } }) => `${detail.item.contribution.experience.score}%`));
    const comparisonRegion = page.getByRole("region", { name: "장소 비교표", exact: true });
    await expect(comparisonRegion).toHaveAttribute("tabindex", "0");
    await comparisonRegion.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
    expect(await comparisonRegion.evaluate((element) => {
      const row = element.querySelector("tbody tr")!;
      const header = row.querySelector("th")!.getBoundingClientRect();
      const range = document.createRange();
      range.selectNodeContents(row.querySelector("td:last-child")!);
      const text = range.getBoundingClientRect();
      return text.left >= header.right && text.right <= element.getBoundingClientRect().right;
    })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: resolve(artifacts, `grounded-comparison-${viewport.name}.png`), fullPage: true });
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    await page.getByRole("link", { name: `${run.items[0].place_name_ko} 상세 보기`, exact: true }).click();
    const densityFit = run.items[0].contribution.traits.components.find((component: { key: string }) => component.key === "M3");
    await expect(page.locator("[data-grounded-trait='M3']")).toContainText(densityFit.fit !== null ? `${densityFit.fit}%`
      : densityFit.expected === null ? "선택하지 않은 항목" : "비교 어려움");
    await expect(page.getByRole("heading", { name: "사진에서 확인한 분위기" })).toBeVisible();
    await expect(page.getByText(/혼잡이나 운영·시설 정보의 근거로 사용하지 않아요/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: resolve(artifacts, `grounded-detail-${viewport.name}.png`), fullPage: true });
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기", exact: true }).click();
    await expect(page.getByRole("button", { name: `${run.items[0].place_name_ko} 저장됨`, exact: true })).toHaveAttribute("aria-pressed", "true");
    await page.reload();
    await expect(page.locator("[data-grounded-item]")).toHaveCount(5);
    expect(await page.locator("[data-grounded-item] .recommendation-fit").allTextContents()).toEqual(initialScores);
    if (fixture.saved_reference ?? fixture.saved_lookup) expect(capturedSavedLookups).toBeGreaterThan(0);
    if (photoRun) {
      expect(photoRun.authority.candidate_sha256).toBe(run.authority.candidate_sha256);
      expect(fixture.photo.confirmation.moods.every((mood: { value: number | null }) => mood.value === null)).toBe(true);
      await page.goto(`/recommendations/${encodeURIComponent(photoRun.run_id)}`);
      await expect(page.locator("[data-grounded-run]")).toHaveAttribute("data-grounded-run", photoRun.run_id);
      await expect(page.locator("[data-grounded-item]")).toHaveCount(5);
      expect(await page.locator("[data-grounded-item] .recommendation-fit").allTextContents()).toEqual(initialScores);
      await expect(page.locator("[data-mood-fit]")).toHaveCount(0);
      await expect(page.getByText("비교할 사진 분위기 근거가 부족해 경험과 여행 조건으로 추천했어요.")).toHaveCount(5);
      await page.reload();
      await expect(page.locator("[data-grounded-run]")).toHaveAttribute("data-grounded-run", photoRun.run_id);
      expect(await page.locator("[data-grounded-item] .recommendation-fit").allTextContents()).toEqual(initialScores);
      await page.screenshot({ path: resolve(artifacts, `grounded-photo-replay-${viewport.name}.png`), fullPage: true });
    }
    expect(posts).toBe(0);
    expect(errors).toEqual([]);
    expect(frontendManifest().sha256).toBe(frontend.sha256);
    if (fixturePath) expect(sha256(readFileSync(fixturePath))).toBe(fixtureSha256);
    expect(sha256(readFileSync(resolve("../contracts/openapi.json")))).toBe(openapiSha256);
    expect(sha256(readFileSync(resolve("e2e/source-grounded-recommendation.spec.ts")))).toBe(specSha256);
    const screenshots = ["card", "comparison", "detail", ...(photoRun ? ["photo-replay"] : [])].map((kind) => {
      const path = resolve(artifacts, `grounded-${kind}-${viewport.name}.png`);
      return { path: relative(resolve(".."), path), sha256: sha256(readFileSync(path)) };
    });
    const evidence = {
      schema_version: "api-ui-browser-evidence.v1",
      mode: "CAPTURED_HTTP_RESPONSE_REPLAY",
      fixture_kind: rawFixture.fixture_kind ?? rawFixture.schema_version ?? rawFixture.provenance,
      source_values: rawFixture.scope === "API_POSTGRES_ONLY" ? "REAL_CANDIDATE_SCRIPTED_USER_PROFILE" : "SYNTHETIC_NOT_FIELD_DATA",
      candidate_member_count: run.candidate_bindings.length,
      source_context_mode: rawFixture.source_context_mode ?? "SYNTHETIC_PROVIDER_TRANSPORT",
      fixture: fixturePath ? { path: relative(resolve(".."), fixturePath), sha256: fixtureSha256 }
        : { path: "web/fixtures/grounded-synthetic-v5.json", sha256: sha256(readFileSync("fixtures/grounded-synthetic-v5.json")) },
      started_at: startedAt, completed_at: new Date().toISOString(), viewport,
      run_id: run.run_id, run_sha256: run.canonical_sha256, candidate_sha256: run.authority.candidate_sha256, config_sha256: run.authority.config_sha256,
      frontend_sources: frontend, openapi_sha256: openapiSha256,
      spec: { path: "web/e2e/source-grounded-recommendation.spec.ts", sha256: specSha256 },
      executed_cases: ["happy_path", "unknown", "replay", ...(photoRun ? ["photo"] : []), viewport.name], failures: [],
      checks: { five_cards: true, nullable_values_preserved: true, source_scope_warnings: true, source_consumers: 7,
        initial_context_requests: 1, refresh_preserved_scores: true, save_compare_detail_return: true,
        reload_preserved_scores: true, browser_recommendation_posts: posts, javascript_errors: errors,
        horizontal_page_overflow: false, comparison_text_unobscured: true, heading_button_summary_font_families: fonts,
        saved_lookup_from_capture: capturedSavedLookups > 0,
        photo_confirmed_unknown_result_replayed: Boolean(photoRun),
        photo_run_id: photoRun?.run_id ?? null, photo_receipt_id: fixture.photo?.confirmation?.receipt_id ?? null },
      limitations: ["PostgreSQL and FastAPI were exercised by the capture producer, not by the browser's routed GET requests.",
        capturedSavedLookups > 0 ? "Saved-place lookup, score/detail/comparison/context payloads are captured API responses."
          : "Saved-place reference lookup is a browser fixture stub; score/detail/comparison/context payloads are captured API responses.",
        "This evidence binds only the candidate hash in the captured run. It does not authorize a different production candidate.",
        photoRun ? "The photo case replays the real API/PG-confirmed all-UNKNOWN result; browser upload/confirmation UI is verified separately."
          : "Photo workflow evidence is collected separately."],
      screenshots,
    };
    const report = { ...evidence, evidence_sha256: sha256(canonical(evidence)) };
    const outputPath = resolve(artifacts, `api-ui-${viewport.name}.json`);
    writeFileSync(outputPath, JSON.stringify(report, null, 2) + "\n");
    await testInfo.attach(`API_UI ${viewport.name}`, { path: outputPath, contentType: "application/json" });
  });
}
