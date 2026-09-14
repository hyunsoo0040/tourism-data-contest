import { expect, test } from "@playwright/test";
import profile from "./fixtures/progress-profile.json" with { type: "json" };

// Controlled API delays exercise UI timing only; no model or production requests.
for (const viewport of [{ name: "desktop", width: 1440, height: 1000 }, { name: "mobile", width: 390, height: 844 }]) {
  test(`recommendation stages and profile actions (${viewport.name})`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    await page.addInitScript(profile => {
      localStorage.clear(); sessionStorage.clear();
      localStorage.setItem("itda.phase1.profile.v1", JSON.stringify({
        schema_version: "phase1-profile-reference-v1", profile_schema_version: profile.schema_version,
        questionnaire_version: profile.questionnaire_version, scoring_version: profile.scoring_version,
        description_template_version: profile.description_template_version, profile_id: profile.profile_id,
        updated_at: new Date().toISOString(),
      }));
    }, profile);
    let releaseProfile!: () => void, releaseRun!: () => void;
    let profileRequests = 0, runRequests = 0;
    const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
    await page.route("**/v1/**", async route => {
      const path = new URL(route.request().url()).pathname;
      if (path.startsWith("/v1/preference-profiles/")) return route.fulfill({ json: profile });
      if (path === "/v1/authenticity/sessions") return route.fulfill({ json: { token: "synthetic-progress-session" } });
      if (path === "/v1/authenticity/scenario-profiles") {
        profileRequests++; await new Promise<void>(resolve => { releaseProfile = resolve; });
        return route.fulfill({ json: { profile_id: "a".repeat(64), intent_sha256: "b".repeat(64) } });
      }
      if (path === "/v1/authenticity/runs") {
        runRequests++; await new Promise<void>(resolve => { releaseRun = resolve; });
        return route.fulfill({ status: 503, json: { detail: "기술 검증용 일시적인 연결 실패" } });
      }
      return route.fulfill({ status: 503, json: { detail: "controlled UI fixture" } });
    });
    await page.goto("/profile");
    const button = page.getByRole("button", { name: "바로 추천 보기", exact: true });
    await expect(button).toBeEnabled();
    await expect(page.getByRole("button", { name: "답변 수정하기" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "여행 조건 수정하기" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "사진으로 추천받기" })).toBeVisible();
    await page.clock.install(); await button.click();
    const progress = page.getByRole("region", { name: "추천 진행 상황" });
    await expect(progress).toBeVisible();
    await expect(progress.locator('[aria-current="step"]')).toContainText("취향·여행 조건 확인");
    await expect.poll(() => profileRequests).toBe(1);
    await page.clock.fastForward(16000);
    await expect(progress).toContainText("16초 경과");
    await expect(progress).toContainText("아직 응답을 기다리고 있어요");
    expect(runRequests).toBe(0);
    await expect(progress.locator('[aria-current="step"]')).toContainText("취향·여행 조건 확인");
    releaseProfile();
    await expect(progress.locator('[aria-current="step"]')).toContainText("관광지 특성과 선호 비교");
    await expect.poll(() => runRequests).toBe(1);
    await expect(progress.locator('[data-state="done"]')).toContainText("취향·여행 조건 확인");
    await progress.scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath("progress.png"), fullPage: true });
    await progress.screenshot({ path: info.outputPath("progress-panel.png") });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    releaseRun();
    await expect(page.locator('section[role="alert"]')).toContainText("기술 검증용 일시적인 연결 실패");
    await expect(progress).toHaveCount(0); await expect(button).toBeEnabled();
    await button.click(); await expect(progress).toContainText("0초 경과");
    await expect(progress.locator('[aria-current="step"]')).toContainText("취향·여행 조건 확인");
    await expect.poll(() => profileRequests).toBe(2);
    releaseProfile(); await expect.poll(() => runRequests).toBe(2); releaseRun();
    await expect(progress).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}
