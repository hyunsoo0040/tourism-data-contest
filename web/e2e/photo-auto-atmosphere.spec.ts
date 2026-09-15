import { expect, test } from "@playwright/test";
import profile from "./fixtures/progress-profile.json" with { type: "json" };
import fixture from "../src/features/authenticity/__fixtures__/prepared-scenario.json" with { type: "json" };
import photos from "../src/features/authenticity/__fixtures__/scenario-photo.json" with { type: "json" };

// Synthetic photo transport only: no model calls or production sessions.
for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`photo recommendation progress with photo (${viewport.name})`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await page.addInitScript(profile => {
      localStorage.setItem("itda.phase1.profile.v1", JSON.stringify({
        schema_version: "phase1-profile-reference-v1", profile_schema_version: profile.schema_version,
        questionnaire_version: profile.questionnaire_version, scoring_version: profile.scoring_version,
        description_template_version: profile.description_template_version, profile_id: profile.profile_id,
        updated_at: new Date().toISOString(),
      }));
    }, profile);
    const candidates = photos.review.batches.flatMap(batch => batch.candidates);
    const confirmed = { ...photos.confirmed,
      selected_candidate_ids: candidates.map(candidate => candidate.candidate_id),
      targets: Object.fromEntries(candidates.map(candidate => [candidate.observation.dimension, candidate.observation.level])),
    };
    const confirmations: unknown[] = [], submissions: unknown[] = [], errors: string[] = [];
    let releaseProfile!: () => void, releaseRun!: () => void, releaseDetails!: () => void;
    const profileGate = new Promise<void>(resolve => { releaseProfile = resolve; });
    const runGate = new Promise<void>(resolve => { releaseRun = resolve; });
    const detailGate = new Promise<void>(resolve => { releaseDetails = resolve; });
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/v1/**", async route => {
      const path = decodeURIComponent(new URL(route.request().url()).pathname);
      if (path.startsWith("/v1/preference-profiles/")) return route.fulfill({ json: profile });
      if (path === "/v1/authenticity/info") return route.fulfill({ json: { photo_enabled: true } });
      if (path === "/v1/authenticity/sessions") return route.fulfill({ json: { token: "synthetic-photo-session" } });
      if (path === "/v1/authenticity/photos") return route.fulfill({ json: photos.review });
      if (path.endsWith("/confirm")) { confirmations.push(route.request().postDataJSON()); return route.fulfill({ json: confirmed }); }
      if (path === "/v1/authenticity/scenario-profiles") {
        submissions.push(route.request().postDataJSON()); await profileGate; return route.fulfill({ json: fixture.profile });
      }
      if (path === "/v1/authenticity/runs" || path === `/v1/authenticity/runs/${fixture.run.run_sha256}`) { await runGate; return route.fulfill({ json: fixture.run }); }
      if (path === "/v1/authenticity/saved") return route.fulfill({ json: [] });
      const detail = fixture.details.find(detail => path.endsWith(`/places/${detail.item.place_id}`));
      if (detail) { await detailGate; return route.fulfill({ json: detail }); }
      return route.fulfill({ status: 503, json: { detail: "Unexpected fixture request" } });
    });
    await page.goto("/photo");
    await page.getByRole("checkbox", { name: "사진을 분위기 분석에 사용하는 데 동의해요." }).check();
    await page.getByLabel("여행 분위기 참고 사진").setInputFiles({ name: "test.png", mimeType: "image/png",
      buffer: Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a4ZkAAAAASUVORK5CYII=", "base64") });
    await expect(page.getByText("사진에서 확인한 분위기를 모두 추천에 자동으로 반영해요.", { exact: true })).toBeVisible();
    await expect(page.getByRole("checkbox")).toHaveCount(1);
    await expect(page.getByText(/greenery|open_composition|녹지 3\/4/)).toHaveCount(0);
    const apply = page.getByRole("button", { name: "사진 분위기로 추천 보기", exact: true });
    await expect(apply).toBeEnabled();
    await apply.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath("automatic-photo.png"), fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    expect(confirmations).toHaveLength(0);
    const before = await apply.boundingBox();
    const beforeHeight = await page.locator(".photo-page-panel").evaluate(node => node.getBoundingClientRect().height);
    await apply.click();
    const progress = page.getByRole("progressbar", { name: "추천 진행 상황" });
    const active = page.locator(".photo-action-bar button[aria-busy=true]");
    await expect(active).toHaveCount(1);
    await expect(active).toBeDisabled();
    await expect(progress).toHaveAttribute("aria-valuenow", "0");
    await expect(page.getByRole("region", { name: "추천 진행 상황" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "사진 없이 추천 보기", exact: true })).toHaveCount(0);
    const during = await active.boundingBox();
    expect(during?.height).toBe(before?.height);
    expect(during?.width).toBe(before?.width);
    expect(await page.locator(".photo-page-panel").evaluate(node => node.getBoundingClientRect().height)).toBe(beforeHeight);
    await expect.poll(() => submissions.length).toBe(1);
    releaseProfile();
    await expect(progress).toHaveAttribute("aria-valuenow", "1");
    await active.screenshot({ path: info.outputPath("photo-progress-button.png") });
    await page.locator(".photo-action-bar").screenshot({ path: info.outputPath("photo-progress-actions.png") });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    releaseRun();
    await expect(progress).toHaveAttribute("aria-valuenow", "2");
    await expect(page).toHaveURL(/\/photo$/);
    releaseDetails();
    await expect(page).toHaveURL(new RegExp(`/recommendations/a-${fixture.run.run_sha256}$`));
    await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
    expect(confirmations).toEqual([{ candidate_ids: confirmed.selected_candidate_ids }]);
    expect(submissions).toHaveLength(1);
    expect(submissions[0]).toMatchObject({ visual_input_kind: "CONFIRMED_PHOTO", visual_targets: confirmed.targets, photo_receipt_sha256: confirmed.receipt_sha256 });
    expect(errors).toEqual([]);
  });
}
