import { expect, test } from "@playwright/test";
import profile from "./fixtures/progress-profile.json" with { type: "json" };
import fixture from "../src/features/authenticity/__fixtures__/prepared-scenario.json" with { type: "json" };

// Controlled transport delays; fixed test answers and published place fixtures.
// No production sessions or model calls.
for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`prepares every result before leaving profile (${viewport.name})`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await page.addInitScript(profile => {
      if (!localStorage.getItem("itda.phase1.profile.v1")) localStorage.setItem("itda.phase1.profile.v1", JSON.stringify({
        schema_version: "phase1-profile-reference-v1", profile_schema_version: profile.schema_version,
        questionnaire_version: profile.questionnaire_version, scoring_version: profile.scoring_version,
        description_template_version: profile.description_template_version, profile_id: profile.profile_id,
        updated_at: new Date().toISOString(),
      }));
    }, profile);
    let releaseDetails!: () => void, releasePhotos!: () => void;
    const detailGate = new Promise<void>(resolve => { releaseDetails = resolve; });
    const photoGate = new Promise<void>(resolve => { releasePhotos = resolve; });
    const requests: { path: string; onProfile: boolean }[] = [], errors: string[] = [];
    let detailRequests = 0, photoRequests = 0;
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/v1/**", async route => {
      const path = decodeURIComponent(new URL(route.request().url()).pathname);
      requests.push({ path, onProfile: page.url().endsWith("/profile") });
      if (path.startsWith("/v1/preference-profiles/")) return route.fulfill({ json: profile });
      if (path === "/v1/authenticity/sessions") return route.fulfill({ json: { token: "synthetic-ready-session" } });
      if (path === "/v1/authenticity/scenario-profiles" || path === `/v1/authenticity/profiles/${fixture.profile.profile_id}`) return route.fulfill({ json: fixture.profile });
      if (path === "/v1/authenticity/runs" || path === `/v1/authenticity/runs/${fixture.run.run_sha256}`) return route.fulfill({ json: fixture.run });
      if (path === "/v1/authenticity/saved") return route.fulfill({ json: [] });
      const detail = fixture.details.find(detail => path.endsWith(`/places/${detail.item.place_id}`));
      if (detail) { detailRequests++; await detailGate; return route.fulfill({ json: detail }); }
      return route.fulfill({ status: 503, json: { detail: "Unexpected fixture request" } });
    });
    await page.route("**/tourism/*.webp", async route => { photoRequests++; await photoGate; await route.continue(); });
    await page.goto("/profile");
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect.poll(() => detailRequests).toBe(5);
    await expect(page).toHaveURL(/\/profile$/);
    const progress = page.getByRole("progressbar", { name: "추천 진행 상황" });
    await expect(progress).toHaveAttribute("aria-valuenow", "2");
    expect(photoRequests).toBe(0);
    releaseDetails();
    await expect.poll(() => photoRequests).toBe(5);
    await expect(page).toHaveURL(/\/profile$/);
    await page.locator("button.button--primary[aria-busy=true]").scrollIntoViewIfNeeded();
    await page.locator("button.button--primary[aria-busy=true]").screenshot({ path: info.outputPath("preparing-details.png") });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    // Observe the very first committed result DOM, before a second request could fill it.
    await page.evaluate(() => {
      const observer = new MutationObserver(() => {
        const cards = document.querySelectorAll("[data-scenario-place]");
        if (!cards.length) return;
        (window as unknown as { firstResult: unknown }).firstResult = {
          cards: cards.length,
          details: document.querySelectorAll("[data-details-loaded=true]").length,
          loading: /장소 정보를 불러오고|사진을 불러오고|최신 분석으로 추천한 장소를 불러오고/.test(document.body.innerText),
          photos: [...cards].map(card => { const image = card.querySelector("figure img") as HTMLImageElement; return Boolean(image?.complete && image.naturalWidth > 0); }),
        };
        observer.disconnect();
      });
      observer.observe(document.body, { subtree: true, childList: true });
    });
    const countBeforeNavigation = requests.length;
    releasePhotos();
    await expect(page).toHaveURL(new RegExp(`/recommendations/a-${fixture.run.run_sha256}$`));
    await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
    const firstResult = await page.evaluate(() => (window as unknown as { firstResult: unknown }).firstResult);
    expect(firstResult).toEqual({ cards: 5, details: 5, loading: false, photos: [true, true, true, true, true] });
    expect(requests).toHaveLength(countBeforeNavigation);
    expect(requests.every(request => request.onProfile)).toBe(true);
    await page.screenshot({ path: info.outputPath("ready-results.png"), fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await info.attach("first-result-and-requests", { body: JSON.stringify({ firstResult, requests }), contentType: "application/json" });
    // A fresh document has no handoff: the canonical URL must still restore via API.
    await page.reload();
    await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
    expect(requests.length).toBeGreaterThan(countBeforeNavigation);
    expect(errors).toEqual([]);
  });
}
