import { test, expect, type Locator } from "@playwright/test";
import path from "node:path";
import examples from "../src/content/public-place-examples.json" with { type: "json" };

const output = process.env.ITDA_UI_CAPTURE_DIR ?? path.resolve(import.meta.dirname, "../../artifacts/ui/place-media-20260914");
async function loadedPhoto(image: Locator) {
  await image.scrollIntoViewIfNeeded();
  await expect.poll(() => image.evaluate(node => (node as HTMLImageElement).complete && (node as HTMLImageElement).naturalWidth > 0)).toBe(true);
}
test.afterEach(async ({ page }) => {
  if (page.url() === "about:blank") return;
  await page.evaluate(async () => {
    const token = sessionStorage.getItem("itda.authenticity.session.v1");
    if (token) await fetch("/v1/authenticity/session", { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
    sessionStorage.clear();
  });
});

for (const [name, width, height] of [["desktop", 1440, 1000], ["mobile", 390, 844]] as const) {
  test(`${name}: current examples, real photo galleries, place information and per-card recovery`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto("/#demo");
    await expect(page.locator("#demo")).toContainText("1,984곳");
    for (const kind of ["history", "image", "rest"] as const) {
      await page.locator(`#demo button[data-type=${kind}]`).click();
      const cards = page.locator("#recommendations article");
      await expect(cards).toHaveCount(1);
      for (const [i, place] of examples.examples[kind].slice(0, 1).entries()) {
        await expect(cards.nth(i).getByRole("heading")).toHaveText(place.name);
        await expect(cards.nth(i)).toContainText(`${place.axis_value}점`);
        await loadedPhoto(cards.nth(i).getByRole("img"));
        await cards.nth(i).locator("summary").click();
        await expect(cards.nth(i)).toContainText(place.address);
      }
    }
    await page.evaluate(() => document.fonts.ready);
    await page.locator("#demo").scrollIntoViewIfNeeded();
    await page.locator("#demo").screenshot({ path: path.join(output, `${name}-examples.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    // Gallery coverage for the separate authenticity routes; home starts at /start.
    await page.goto("/trip");
    for (const axis of ["H", "E", "R"]) {
      for (const letter of ["a", "b", "c", "d"]) {
        const value = axis === "H" && letter !== "c" ? "2" : "0";
        await page.locator("label").filter({ has: page.locator(`input[name="${axis}.${letter}"][value="${value}"]`) }).click();
      }
      await page.getByRole("button", { name: "다음", exact: true }).click();
    }
    if (process.env.ITDA_DESIGN_PHOTO_CHECK === "1") {
      await expect(page.locator("#trip-photo-heading")).toBeVisible();
      await page.screenshot({ path: path.join(output, `${name}-current-photo.png`), fullPage: true });
      await page.route("**/v1/authenticity/photos", route => route.fulfill({ status: 503, json: { detail: "자동 UI 검사: 사진 분석 연결 실패" } }), { times: 1 });
      const picker = page.waitForEvent("filechooser");
      await page.getByRole("button", { name: /사진 고르기/ }).click();
      await (await picker).setFiles(path.resolve(import.meta.dirname, `../public${examples.examples.rest[0].photo.url}`));
      await expect(page.locator("main").getByRole("alert")).toContainText("사진 분석 연결 실패");
      await expect(page.getByRole("button", { name: "사진 없이 추천 보기", exact: true })).toBeEnabled();
    }
    // Transport fault on a single real detail response; ranking and other cards must survive.
    await page.route("**/v1/authenticity/runs/*/places/*", route => route.fulfill({ status: 503, json: { detail: "자동 기술 검사: 일시적인 정보 조회 실패" } }), { times: 1 });
    await page.getByRole("button", { name: "사진 없이 추천 보기", exact: true }).click();
    const cards = page.locator("article[data-details-loaded]");
    await expect(cards).toHaveCount(5);
    await expect(page.locator("article[data-details-loaded=true]")).toHaveCount(4);
    await expect(page.getByText("사진 정보를 확인하지 못했어요")).toBeVisible();
    await expect(page.locator("article[data-details-loaded=false]")).not.toContainText("장소의 연결 근거를 불러오고 있어요");
    await page.getByRole("button", { name: /정보 다시 불러오기$/ }).click();
    await expect(page.locator("article[data-details-loaded=true]")).toHaveCount(5);
    for (const card of await cards.all()) {
      await expect(card.getByRole("region", { name: /장소 정보$/ })).toBeVisible();
      await expect(card.getByRole("link", { name: "지도에서 보기" })).toHaveAttribute("href", /^https:\/\/map.naver.com\/p\/search\//);
      await loadedPhoto(card.getByRole("img"));
    }
    const first = cards.first();
    const initial = await first.getByRole("img").getAttribute("src");
    await first.getByRole("button", { name: /사진 2 보기$/ }).click();
    await loadedPhoto(first.getByRole("img"));
    expect(await first.getByRole("img").getAttribute("src")).not.toBe(initial);
    await page.screenshot({ path: path.join(output, `${name}-results.png`), fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    await first.getByRole("button", { name: "장소 저장", exact: true }).click();
    await expect(first.getByRole("button", { name: "저장 취소" })).toBeVisible();
    await first.getByRole("link", { name: "장소 상세 보기" }).click();
    await expect(page.getByRole("heading", { name: "장소 소개" })).toBeVisible();
    await loadedPhoto(page.getByRole("img"));
    await page.getByRole("button", { name: /사진 2 보기$/ }).click();
    await loadedPhoto(page.getByRole("img"));
    await expect(page.getByRole("heading", { name: "이 점수의 근거" })).toBeVisible();
    await page.screenshot({ path: path.join(output, `${name}-detail.png`), fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    expect(errors).toEqual([]);
  });
}
