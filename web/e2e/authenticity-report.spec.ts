import {test,expect} from "@playwright/test";
import path from "node:path";
import fs from "node:fs";
const output=process.env.ITDA_UI_CAPTURE_DIR??path.resolve(import.meta.dirname,"../../artifacts/authenticity-v1/20260911/report-review");fs.mkdirSync(output,{recursive:true});
for(const [name,width,height] of [["desktop",1440,1000],["mobile",390,844]] as const){
  test(`${name}: public artifact search sources and paired comparison`,async({page})=>{
    page.setDefaultTimeout(15_000);await page.setViewportSize({width,height});const errors:string[]=[];page.on("pageerror",e=>errors.push(e.message));
    await page.goto("/");await expect(page.locator("#count")).toContainText("2,000곳");
    const finalReport=process.env.ITDA_REPORT_EXPECT_FINAL==="1";
    if(finalReport){
      expect(await page.locator("#report-data").evaluate(e=>JSON.parse(e.textContent??"{}").final)).toBe(true);
      await expect(page.locator("#completion")).toContainText("전수 2,000곳의 새 분석과 AI 검토");
      await expect(page.locator("#places .pending")).toHaveCount(0);
      await expect(page.locator("#places")).toContainText("새 분석 있음");
      await expect(page.locator("#case-body h3")).toBeVisible();
      await page.locator("#condition").selectOption("A0");
      await expect(page.locator("#case-body h3")).toBeVisible();
      await page.locator("#condition").selectOption("A1");
      await expect(page.locator("#case-body h3")).toBeVisible();
      await page.locator("#case-body").screenshot({path:path.join(output,`${name}-full-case.png`)});
    }else{
      await expect(page.locator(".pending").first()).toHaveCSS("color","rgb(91, 98, 93)");
    }
    if(width<720)await page.locator("#find .table-wrap").evaluate(e=>{e.scrollLeft=300});
    await page.locator("#find").screenshot({path:path.join(output,`${name}-${finalReport?"complete":"pending"}.png`)});
    await page.locator("#find .table-wrap").evaluate(e=>{e.scrollLeft=0});
    await page.locator("#search").fill("없을법한검증문자열000");await expect(page.locator("#places")).toContainText("조건에 맞는 장소가 없습니다");
    await page.locator("#search").fill("박물관");await expect(page.locator("#places tr")).not.toHaveCount(0);
    await page.locator("#search").fill("");await page.locator("#dataset").selectOption("development");
    await expect(page.locator("#count")).toContainText("120곳");await expect(page.locator("#case-body h3")).toBeVisible();
    await page.locator("#condition").selectOption("A4");await expect(page.locator("#case-body h3")).toBeVisible();
    const firstFacet=page.locator("#case-body > details").filter({has:page.locator("blockquote")}).first();await firstFacet.locator("summary").click();
    await expect(firstFacet.locator("blockquote").first()).toBeVisible();
    await page.evaluate(()=>document.fonts.ready);await page.waitForFunction(()=>Array.from(document.querySelectorAll('#case-body img')).every(i=>(i as HTMLImageElement).complete&&(i as HTMLImageElement).naturalWidth>0));
    await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:path.join(output,`${name}.png`),fullPage:true});
    await page.locator("#case-body").screenshot({path:path.join(output,`${name}-case.png`)});
    await page.locator("#experiment-data").selectOption("new-evaluation");await expect(page.locator("#experiment-body tbody tr")).toHaveCount(2);
    await page.locator("#scenario").selectOption("10");await page.locator("#experiments").screenshot({path:path.join(output,`${name}-experiment.png`)});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);expect(errors).toEqual([]);
    await page.locator("#dataset").selectOption("new-evaluation");await expect(page.locator("#count")).toContainText("60곳");
  });
}
