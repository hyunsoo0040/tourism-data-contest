import { expect, test, type Page } from "@playwright/test";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { FRONTEND_QUESTIONNAIRE as questionnaire } from "../src/content/questionnaire";

const output = resolve("../.impeccable/review/profile-story");
const axes = ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"];

async function loadProfile(page: Page, winner: number) {
  const created = new Date().toISOString();
  const profile = {
    schema_version: "preference-profile-v2", profile_id: "story-test", request_id: "story-test", created_at: created,
    ...Object.fromEntries(["questionnaire_version", "scoring_version", "config_hash", "description_template_version"].map((key) => [key, questionnaire[key as keyof typeof questionnaire]])),
    trip_conditions: { visit_date: null, visit_time: "SUNSET", companion: "SOLO", transport: "WALK_OR_TRANSIT", walking_tolerance: "WITHIN_30_MINUTES", indoor_outdoor_preference: "NO_PREFERENCE", crowd_avoidance: "MEDIUM" },
    answers: Object.fromEntries(questionnaire.questions.map((q) => [q.question_id, 1])),
    is_current_trip_expectation: true, description_ko: "UI 목업 · 공유 이미지 검증용 합성 결과",
    scores: axes.map((axis, i) => ({ axis, basis_points: i === winner ? 6000 : 3000, display_score: i === winner ? 60 : 30 })),
  };
  await page.route("**/v1/preference-profiles/**", (route) => route.fulfill({ json: profile }));
  await page.addInitScript(({ created, questionnaire }) => {
    localStorage.setItem("itda.phase1.profile.v1", JSON.stringify({
      schema_version: "phase1-profile-reference-v1", profile_schema_version: "preference-profile-v2",
      questionnaire_version: questionnaire.questionnaire_version, scoring_version: questionnaire.scoring_version,
      description_template_version: questionnaire.description_template_version,
      updated_at: created, profile_id: "story-test",
    }));
  }, { created, questionnaire });
  await page.goto("/profile");
  await expect(page.getByRole("button", { name: "스토리 이미지 공유·저장" })).toBeEnabled({ timeout: 25_000 });
}

test("1080 × 1920 PNGs for all three types, with mobile and desktop button checks", async ({ page }) => {
  test.setTimeout(120_000);
  await mkdir(output, { recursive: true });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  for (const [winner, slug] of ["original-seeker", "mood-weaver", "flow-walker"].entries()) {
    await page.setViewportSize({ width: winner === 0 ? 1440 : 390, height: winner === 0 ? 1000 : 844 });
    await loadProfile(page, winner);
    const button = page.getByRole("button", { name: "스토리 이미지 공유·저장" });
    await button.scrollIntoViewIfNeeded();
    const before = await page.getByRole("meter").allTextContents();
    const download = page.waitForEvent("download");
    await button.click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^IT-DA-.+-story\.png$/);
    const destination = resolve(output, `${slug}.png`);
    await file.saveAs(destination);
    const png = await readFile(destination);
    expect(png.subarray(1, 4).toString()).toBe("PNG");
    expect(png.readUInt32BE(16)).toBe(1080);
    expect(png.readUInt32BE(20)).toBe(1920);
    expect(png.byteLength).toBeGreaterThan(100_000);
    expect(await page.getByRole("meter").allTextContents()).toEqual(before);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (winner < 2) {
      await page.screenshot({ path: resolve(output, `${winner === 0 ? "desktop" : "mobile"}-button.png`) });
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: resolve(output, `${winner === 0 ? "desktop" : "mobile"}.png`), fullPage: true });
    }
    await page.unroute("**/v1/preference-profiles/**");
  }
  expect(errors).toEqual([]);
});

test("native sharing receives the PNG within user activation, without downloading", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "canShare", { value: () => true });
    Object.defineProperty(navigator, "share", { value: (data: ShareData) => {
      const file = data.files![0]!;
      document.documentElement.dataset.nativeStory = JSON.stringify({ type: file.type, size: file.size, active: navigator.userActivation.isActive, count: data.files!.length });
      return Promise.resolve();
    } });
  });
  let downloads = 0;
  page.on("download", () => { downloads += 1; });
  await loadProfile(page, 1);
  await page.getByRole("button", { name: "스토리 이미지 공유·저장" }).click();
  const shared = JSON.parse(await page.locator("html").getAttribute("data-native-story") ?? "null");
  expect(shared).toMatchObject({ type: "image/png", active: true, count: 1 });
  expect(shared.size).toBeGreaterThan(100_000);
  expect(downloads).toBe(0);
});
