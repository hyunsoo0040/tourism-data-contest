import { expect, test } from "@playwright/test";

const execution = {
  schema_version: "mvp-daily-refresh-execution.v1",
  run_date: "2026-09-06",
  execution_sequence: 0,
  kind: "SCHEDULED",
  command_id: null,
  status: "COLLECTION_INCOMPLETE",
  changed_count: 0,
  failed_count: 0,
  call_count: 0,
  active_release_sha256: null,
  safe_reason: "TOUR_API_COLLECTION_FAILED",
  started_at: "2026-09-05T23:00:00Z",
  updated_at: "2026-09-05T23:01:00Z",
  finished_at: "2026-09-05T23:01:00Z",
};

async function installOperationsApi(page: import("@playwright/test").Page) {
  await page.route("**/internal/operations/daily-glm/api/**", async (route) => {
    const url = new URL(route.request().url());
    let body: unknown;
    let status = 200;
    if (url.pathname.endsWith("/overview")) {
      body = {
        latest_execution: execution,
        next_run_at: "2026-09-06T23:00:00Z",
        active_release_sha256: "a".repeat(64),
        recollection: { eligible: true, safe_reason: "RECOLLECTION_ALLOWED" },
        pending_command: null,
      };
    } else if (url.pathname.endsWith("/history/2026-09-06")) {
      body = {
        execution,
        collection_failures: [
          {
            place_id: `public:gyeongju:${"1".repeat(64)}`,
            operation: "detailIntro2",
            failure_category: "PROVIDER_TRANSPORT",
            failure_code: "PROVIDER_UNAVAILABLE",
            occurred_at: "2026-09-05T23:01:00Z",
          },
        ],
        attempts: [],
      };
    } else if (url.pathname.endsWith("/history")) {
      body = { executions: [execution] };
    } else {
      status = 404;
      body = { detail: "not found" };
    }
    await route.fulfill({
      body: JSON.stringify(body),
      contentType: "application/json",
      status,
    });
  });
}

test("daily GLM dashboard renders desktop and mobile without overflow", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await installOperationsApi(page);
  await page.goto("/internal/operations/daily-glm");

  await expect(page.getByRole("heading", { name: "Daily GLM 관제" })).toBeVisible();
  await expect(page.getByText("COLLECTION_INCOMPLETE").first()).toBeVisible();
  await expect(page.getByText("PROVIDER_TRANSPORT · PROVIDER_UNAVAILABLE")).toBeVisible();
  await expect(page.getByRole("button", { name: "즉시 재수집" })).toBeEnabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("heading", { name: "최근 30일 실행" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "실행 상세" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(pageErrors).toEqual([]);
});

test("daily GLM dashboard displays safe exclusions and rejection on desktop and mobile", async ({ page }, testInfo) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const observed = {
    ...execution, status: "RELEASE_REJECTED", safe_reason: "INSUFFICIENT_PROFILES",
    available_count: 79, information_unavailable_count: 20, event_ended_count: 1,
    changed_count: 21,
  };
  const excluded = Array.from({ length: 21 }, (_, index) => ({
    place_id: `public:gyeongju:${index.toString(16).padStart(64, "0")}`,
    content_id: String(100 + index),
    state: index === 20 ? "EVENT_ENDED" : "INFORMATION_UNAVAILABLE",
    safe_reason: index === 20 ? "OFFICIAL_EVENT_END_DATE_PASSED" : "COMMON_INFORMATION_UNAVAILABLE",
    event_end_date: index === 20 ? "2026-09-05" : null,
    place_name_ko: index === 20 ? "합성 종료 행사" : `합성 정보 조회 불가 장소 ${index + 1}`,
    raw_body: "synthetic-private-body", source_url: "https://example.invalid/?serviceKey=private",
  }));
  await page.route("**/internal/operations/daily-glm/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/overview") ? {
      latest_execution: observed, next_run_at: "2026-09-06T23:00:00Z", active_release_sha256: "a".repeat(64),
      recollection: { eligible: false, safe_reason: "SNAPSHOT_ALREADY_RECORDED" }, pending_command: null,
    } : path.endsWith("/history/2026-09-06") ? {
      execution: observed, excluded, collection_failures: [], attempts: [],
    } : { executions: [observed] };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/internal/operations/daily-glm");
  const summary = page.getByRole("region", { name: "최신 수집 판정" });
  await expect(summary.getByText("79개")).toBeVisible();
  await expect(summary.getByText("20개")).toBeVisible();
  await expect(summary.getByText("1개")).toBeVisible();
  await expect(summary.getByRole("note")).toContainText("제외 판정 미반영");
  await expect(page.getByText("공식 종료일: 2026-09-05")).toBeVisible();
  await expect(page.getByRole("button", { name: "즉시 재수집" })).toBeDisabled();
  await expect(page.getByText(/synthetic-private-body|serviceKey|example.invalid/)).toHaveCount(0);
  await expect(page.getByText("0 / 200")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("dashboard-exclusions-desktop.png"), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("heading", { name: "수집 제외 판정" })).toBeVisible();
  await expect(page.getByText("합성 종료 행사", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("dashboard-exclusions-mobile.png"), fullPage: true });
  expect(pageErrors).toEqual([]);
});

test("daily GLM dashboard reports HTTP failures and recovers on refresh", async ({ page }, testInfo) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await installOperationsApi(page);
  let failing = true;
  await page.route("**/internal/operations/daily-glm/api/**", async (route) => {
    if (failing) {
      await route.fulfill({ status: 504, contentType: "text/plain", body: "synthetic-private-upstream-error" });
    } else {
      await route.fallback();
    }
  });
  await page.goto("/internal/operations/daily-glm");
  await expect(page.getByText(/HTTP 504/)).toBeVisible();
  await expect(page.getByText("운영 상태를 불러오는 중입니다.")).toHaveCount(0);
  await expect(page.getByText("synthetic-private-upstream-error")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("dashboard-http-error.png"), fullPage: true });

  failing = false;
  await page.getByRole("button", { name: "새로고침" }).click();
  await expect(page.getByText("운영 상태가 최신입니다.")).toBeVisible();
  await expect(page.getByText("PROVIDER_TRANSPORT · PROVIDER_UNAVAILABLE")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("dashboard-recovered.png"), fullPage: true });
  expect(pageErrors).toEqual([]);
});

test("daily GLM dashboard stops waiting after ten seconds and can retry", async ({ page }, testInfo) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await installOperationsApi(page);
  let waiting = true;
  let overviewRequests = 0;
  await page.route("**/internal/operations/daily-glm/api/overview", async (route) => {
    overviewRequests += 1;
    if (!waiting) await route.fallback();
  });
  await page.goto("/internal/operations/daily-glm");
  await expect(page.getByText(/응답 시간이 초과되었습니다\(10초\)/)).toBeVisible({ timeout: 15_000 });
  expect(overviewRequests).toBe(1);
  await expect(page.getByRole("button", { name: "새로고침" })).toBeEnabled();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("dashboard-timeout-mobile.png"), fullPage: true });

  waiting = false;
  await page.getByRole("button", { name: "새로고침" }).click();
  await expect(page.getByText("운영 상태가 최신입니다.")).toBeVisible();
  expect(overviewRequests).toBe(2);
  expect(pageErrors).toEqual([]);
});
