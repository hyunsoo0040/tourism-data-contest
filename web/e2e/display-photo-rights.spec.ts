import { expect, test } from "@playwright/test";
import profile from "./fixtures/progress-profile.json" with { type: "json" };
import fixture from "../src/features/authenticity/__fixtures__/prepared-scenario.json" with { type: "json" };

for (const width of [1440, 390]) {
  test(`display-only photo rights preserve complete images (${width})`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 950 });
    await page.addInitScript(profile => localStorage.setItem("itda.phase1.profile.v1", JSON.stringify({
      schema_version: "phase1-profile-reference-v1", profile_schema_version: profile.schema_version,
      questionnaire_version: profile.questionnaire_version, scoring_version: profile.scoring_version,
      description_template_version: profile.description_template_version, profile_id: profile.profile_id,
      updated_at: new Date().toISOString(),
    })), profile);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/v1/**", async route => {
      const path = decodeURIComponent(new URL(route.request().url()).pathname);
      if (path.startsWith("/v1/preference-profiles/")) return route.fulfill({ json: profile });
      if (path.endsWith("/sessions")) return route.fulfill({ json: { token: "synthetic-display-session" } });
      if (path.endsWith("/scenario-profiles")) return route.fulfill({ json: fixture.profile });
      if (path.endsWith("/runs") || path.endsWith(`/runs/${fixture.run.run_sha256}`)) return route.fulfill({ json: fixture.run });
      const detail = fixture.details.find(d => path.endsWith(`/places/${d.item.place_id}`));
      if (detail) {
        // Local public test images only; simulate all four API rights metadata values.
        const type = fixture.details.indexOf(detail) % 4 + 1;
        return route.fulfill({ json: { ...detail, photos: detail.photos.map(photo => ({
          ...photo, license: `KOGL_TYPE_${type}`, source_url: "https://data.visitkorea.or.kr/page/127841",
        })) } });
      }
      return route.fulfill({ status: 503, json: { detail: "Unexpected test request" } });
    });
    await page.goto("/profile");
    await page.getByRole("button", { name: "추천 장소 보기", exact: true }).click();
    await expect(page.locator("[data-details-loaded=true]")).toHaveCount(5);
    for (const type of [1, 2, 3, 4]) {
      const card = page.locator("[data-scenario-place]").nth(type - 1);
      await expect(card.getByText(new RegExp(`공공누리 제${type}유형`))).toBeVisible();
      const img = card.locator("figure img").first();
      await expect(img).toHaveCSS("object-fit", type >= 3 ? "contain" : "cover");
      expect(await img.evaluate((el: HTMLImageElement) => el.complete && el.naturalWidth > 0)).toBe(true);
      await expect(card.getByRole("link", { name: "출처", exact: true })).toHaveAttribute("href", "https://data.visitkorea.or.kr/page/127841");
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.locator("[data-scenario-place]").nth(2).screenshot({ path: info.outputPath(`type3-${width}.png`) });
    expect(errors).toEqual([]);
  });
}
