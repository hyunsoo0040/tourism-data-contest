import { FRONTEND_QUESTIONNAIRE as QUESTIONNAIRE } from "../src/content/questionnaire";
import { expect, type Page, test } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)), "../..");
const ARTIFACT_ROOT = resolve(ROOT, "artifacts/research/kto-context-20260909");

type Fixture = {
  provenance: string;
  request: Record<string, unknown>;
  created: { recommendation_run_id: string };
  results: unknown;
  context: { mode: string; places: Array<{ place_id: string }> };
};

/** Invoke the actual app/Postgres test harness. JSON uses stdin, never a shell. */
function generateFixture(input: unknown, destination: string): Promise<Fixture> {
  return new Promise((done, reject) => {
    const child = spawn(resolve(ROOT, "backend/.venv.nosync/bin/python"), [
      resolve(ROOT, "backend/tests/integration/generate_source_grounding_fixture.py"), destination,
    ], {
      cwd: ROOT,
      env: { ...process.env, PYTHONPATH: `${resolve(ROOT, "backend/src")}:${resolve(ROOT, "backend")}` },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stdout.resume();
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(`Actual tracer fixture failed (${code}): ${stderr.slice(-6000)}`));
      else done(JSON.parse(readFileSync(destination, "utf8")) as Fixture);
    });
    child.stdin.end(JSON.stringify(input));
  });
}

async function noHorizontalOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`source facts travel through the browser journey (${viewport.name}, application-response replay)`, async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize(viewport);
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
        await route.abort();
        return;
      }
      await route.fallback();
    });
    let fixture: Fixture | null = null;
    let profile: unknown = null;
    let capturedRequest: Record<string, unknown> | null = null;
    let creates = 0;
    await page.route("**/v1/recommendation-runs", async (route) => {
      if (route.request().method() !== "POST") return route.fallback();
      capturedRequest = route.request().postDataJSON() as Record<string, unknown>;
      creates += 1;
      if (fixture === null) fixture = await generateFixture({ profile, request: capturedRequest },
        resolve(ARTIFACT_ROOT, `tracer-fixture-${viewport.name}.json`));
      await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(fixture.created) });
    });
    await page.route("**/v1/recommendation-runs/*", async (route) => {
      if (fixture === null) return route.fallback();
      const path = new URL(route.request().url()).pathname;
      if (path.endsWith(encodeURIComponent(fixture.created.recommendation_run_id))) {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(fixture.results) });
      } else await route.fallback();
    });
    await page.route("**/v1/recommendation-runs/*/trip-context", async (route) => {
      if (fixture === null) return route.fallback();
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(fixture.context) });
    });
    await page.goto("/start");
    const facilities = page.getByRole("group", { name: "필요한 편의시설 (선택)" });
    await expect(facilities.getByRole("checkbox")).toHaveCount(5);
    await page.getByRole("radio", { name: "아이 동반", exact: true }).check();
    expect(await facilities.getByRole("checkbox").evaluateAll((elements) => elements.every((element) => !(element as HTMLInputElement).checked))).toBe(true);
    await page.getByRole("checkbox", { name: "장애인 화장실", exact: true }).check();
    await page.getByLabel("방문 날짜 (선택)").fill("2026-10-09");
    await page.getByLabel("정확한 방문 시간 (선택)").fill("10:30");
    for (const label of ["해질녘", "도보·대중교통", "1시간 안팎", "상관없어요", "조금 피하고 싶어요"]) {
      await page.getByRole("radio", { name: label, exact: true }).check();
    }
    await noHorizontalOverflow(page);
    await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
    const profileResponse = page.waitForResponse((response) => response.request().method() === "POST" && response.url().endsWith("/v1/preference-profiles"));
    for (const question of QUESTIONNAIRE.questions) {
      await expect(page.getByText(question.title_ko, { exact: true })).toBeVisible();
      await page.getByRole("radio", { name: question.options[0]!.text_ko, exact: true }).click();
    }
    const response = await profileResponse;
    expect(response.status()).toBe(201);
    profile = await response.json();
    await expect(page).toHaveURL(/\/profile$/);
    await page.getByRole("button", { name: "바로 추천 보기" }).click();
    const known = page.locator('[data-trip-fact="accessible_toilet"][data-support-state="SUPPORTED_FACT"]');
    const unknown = page.locator('[data-trip-fact="accessible_toilet"][data-support-state="UNKNOWN"]');
    await expect(known.first()).toBeVisible({ timeout: 70_000 });
    await expect(unknown).toHaveCount(1);
    await expect(unknown.getByText("미확인", { exact: true })).toBeVisible();
    await expect(known.first().getByText("있음", { exact: true })).toBeVisible();
    await expect(known.first().getByText("2026-09-09 기준", { exact: true })).toBeVisible();
    await expect(known.first().getByRole("link", { name: "한국관광공사 무장애 여행 정보" })).toHaveAttribute("href", "https://www.data.go.kr/data/15101897/openapi.do");
    expect(capturedRequest?.grounded_input).toEqual({ visit_date: "2026-10-09", visit_time: "10:30", required_facilities: ["accessible_toilet"] });
    await noHorizontalOverflow(page);
    await page.screenshot({ path: resolve(ARTIFACT_ROOT, `tracer-browser-${viewport.name}.png`), fullPage: true });
    await page.locator("section[data-trip-context-state]").first().screenshot({
      path: resolve(ARTIFACT_ROOT, `tracer-facility-panel-${viewport.name}.png`),
    });
    const pinnedUrl = page.url();
    await page.reload();
    await expect(known.first()).toBeVisible();
    await expect(unknown).toHaveCount(1);
    expect(page.url()).toBe(pinnedUrl);
    expect(creates).toBe(1);
    await noHorizontalOverflow(page);
  });
}
