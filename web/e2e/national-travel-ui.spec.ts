import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Presentation-only national examples, derived from the existing synthetic v5
// fixture. This test does not claim to have requested or evaluated real places.
const fixture = JSON.parse(readFileSync(resolve("fixtures/grounded-synthetic-v5.json"), "utf8"));
const artifacts = resolve("../artifacts/reports/national-ui-20260909");
mkdirSync(artifacts, { recursive: true });
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  return JSON.stringify(value);
}
const hash = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const run = fixture.results.run;
const regions = [
  ["11110", "서울특별시 종로구"], ["26110", "부산광역시 중구"], ["51150", "강원특별자치도 강릉시"],
  ["50110", "제주특별자치도 제주시"], ["52111", "전북특별자치도 전주시 완산구"],
];
for (const [index, item] of run.items.entries()) {
  item.region_code = regions[index]![0];
  item.region_name = regions[index]![1];
  item.address_ko = `${item.region_name} 합성 검증 주소`;
  if (index < 2) item.place_name_ko = "동명 관광지";
  item.overall_confidence = null;
  item.mismatch.state = "SUPPRESSED_LOW_CONFIDENCE";
  item.mismatch.message_ko = null;
}
run.input_digest = hash({ preference: run.preference, authority: run.authority });
const { run_id: _runId, created_at: _created, canonical_sha256: _sha, ...body } = run;
run.canonical_sha256 = hash(body);
run.run_id = `recommendation-run:${run.canonical_sha256.slice(0, 32)}`;
for (const detail of fixture.details) {
  detail.recommendation_run_id = run.run_id;
  detail.item = run.items.find((item: { place_id: string }) => item.place_id === detail.item.place_id);
}

for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`national region selection and place identity (${viewport.name}, synthetic)`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (["http:", "https:"].includes(url.protocol) && !["127.0.0.1", "localhost"].includes(url.hostname)) return route.abort();
      if (!url.pathname.startsWith("/v1/")) return route.fallback();
      if (url.pathname === "/v1/recommendation-regions") return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        candidate_sha256: run.authority.candidate_sha256, regions: [
          { region_code: "12", region_name: "전남광주통합특별시", place_count: 42 },
          { region_code: "51", region_name: "강원특별자치도", place_count: 30 },
        ],
      }) });
      if (url.pathname.endsWith("/tourism-context")) return route.fulfill({ status: 503, body: "{}" });
      let payload: unknown = fixture.results;
      if (url.pathname.includes("/places/")) payload = fixture.details.find((detail: { item: { place_id: string } }) =>
        detail.item.place_id === decodeURIComponent(url.pathname.split("/").at(-1)!));
      if (url.pathname.endsWith("/comparison")) payload = { ...fixture.comparison, recommendation_run_id: run.run_id,
        places: url.searchParams.getAll("place_id").map((id) => fixture.details.find((detail: { item: { place_id: string } }) => detail.item.place_id === id)) };
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
    });
    await page.goto("/start");
    await expect(page.getByRole("heading", { name: "이번 여행, 어떤 시간을 보내고 싶나요?" })).toBeVisible();
    const select = page.getByRole("combobox", { name: "어디로 떠날까요?" });
    await expect(select).toHaveValue("");
    await expect(select.locator("option")).toHaveCount(3);
    await select.selectOption("51");
    await page.screenshot({ path: resolve(artifacts, `national-start-${viewport.name}.png`) });
    for (const name of ["아직 미정", "혼자", "도보·대중교통", "30분 이내로 가볍게", "상관없어요", "조금 피하고 싶어요"])
      await page.getByRole("radio", { name, exact: true }).check();
    await page.getByRole("button", { name: "취향 테스트 시작하기" }).click();
    await expect(page).toHaveURL(/\/quiz$/);
    expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem("itda:grounded-trip:v1")!).region_code)).toBe("51");

    await page.goto(`/recommendations/${encodeURIComponent(run.run_id)}`);
    await expect(page.getByRole("heading", { name: "이번 여행에 맞는 5곳" })).toBeVisible();
    const cards = page.locator("[data-grounded-item]");
    await expect(cards).toHaveCount(5);
    await expect(cards.nth(0).locator("[data-place-region]")).toHaveText("서울특별시 종로구");
    await expect(cards.nth(1).locator("[data-place-region]")).toHaveText("부산광역시 중구");
    await expect(cards.nth(0)).toContainText("내 취향과 100% 유사");
    await cards.nth(0).screenshot({ path: resolve(artifacts, `national-card-${viewport.name}.png`) });
    await cards.nth(0).getByRole("link", { name: "동명 관광지 상세 보기" }).click();
    await expect(page.locator("[data-grounded-detail] > [data-place-region]")).toHaveText("서울특별시 종로구 합성 검증 주소");
    await page.screenshot({ path: resolve(artifacts, `national-detail-${viewport.name}.png`) });
    await page.getByRole("link", { name: "추천 5곳으로 돌아가기" }).click();
    for (const index of [0, 1]) await cards.nth(index).getByRole("button", { name: "동명 관광지 비교에 추가", exact: true }).click();
    await page.getByRole("button", { name: "선택한 장소 비교하기" }).click();
    const table = page.getByRole("table", { name: "선택한 장소와 내 취향의 유사도" });
    await expect(table.getByRole("columnheader", { name: "동명 관광지 서울특별시 종로구" })).toBeVisible();
    await expect(table.getByRole("columnheader", { name: "동명 관광지 부산광역시 중구" })).toBeAttached();
    await table.screenshot({ path: resolve(artifacts, `national-comparison-${viewport.name}.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    expect(errors).toEqual([]);
  });
}
