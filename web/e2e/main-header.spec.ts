import { expect, test } from "@playwright/test";

for (const width of [1440, 390]) {
  test(`home header sticks and tracks sections at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/#flow");
    const header = page.locator(".up-main .site-header");
    const menu = header.getByRole("navigation", { name: "주요 메뉴", includeHidden: true });
    await expect(header).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    await expect(menu.locator('a[href="#flow"]')).toHaveAttribute("aria-current", "location");
    await expect.poll(async () => (await header.boundingBox())?.y).toBe(0);
    await page.goto("/");
    await expect(header.locator(".nav-cta")).toHaveAttribute("href", "/start");
    await page.screenshot({ path: info.outputPath("design-main.png") });
    await expect(menu.locator('[aria-current="location"]')).toHaveCount(0);

    for (const id of ["type", "flow", "demo"]) {
      if (width < 920) await header.getByRole("button", { name: "메뉴 열기" }).click();
      await menu.locator(`a[href="#${id}"]`).click();
      await expect(page).toHaveURL(new RegExp(`#${id}$`));
      await expect(menu.locator(`a[href="#${id}"]`)).toHaveAttribute("aria-current", "location");
      await expect(menu.locator("a.active")).toHaveCount(1);
      await expect.poll(async () => (await header.boundingBox())?.y).toBe(0);
      const headerBox = (await header.boundingBox())!;
      const headingBox = (await page.locator(`section#${id} h2, section#${id} h3`).first().boundingBox())!;
      expect(headingBox.y).toBeGreaterThanOrEqual(headerBox.height);
      if (width < 920) {
        await expect(header.getByRole("button", { name: "메뉴 열기" })).toHaveAttribute("aria-expanded", "false");
      }
    }

    // Browser history and manual upward scrolling must also update the highlight.
    await page.goBack();
    await expect(menu.locator('a[href="#flow"]')).toHaveAttribute("aria-current", "location");
    await page.evaluate(() => document.querySelector("section#type")!.scrollIntoView({ behavior: "instant" }));
    await expect(menu.locator('a[href="#type"]')).toHaveAttribute("aria-current", "location");
    await expect.poll(async () => (await header.boundingBox())?.y).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await expect(menu.locator('[aria-current="location"]')).toHaveCount(0);

    await page.goto("/#flow");
    await expect(menu.locator('a[href="#flow"]')).toHaveAttribute("aria-current", "location");
    await expect.poll(async () => (await header.boundingBox())?.y).toBe(0);
    await page.goto("/#photo");
    const photoIntro = page.locator("section#photo");
    await expect(photoIntro.locator(".photo-link")).toHaveCount(0);
    await expect(photoIntro).toHaveClass(/visible/);
    await photoIntro.screenshot({ path: info.outputPath("design-photo-intro.png") });
    if (width < 920) await header.getByRole("button", { name: "메뉴 열기" }).click();
    await menu.getByRole("link", { name: "사진 분위기 입력", exact: true }).click();
    await expect(page).toHaveURL(/\/photo$/);
    await expect(page.locator(".up-photo")).toBeVisible();
  });
}
