import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
const output = process.env.ITDA_UI_CAPTURE_DIR ?? path.resolve(import.meta.dirname,"../../artifacts/authenticity-v1/20260911/ui-review");
fs.mkdirSync(output, { recursive: true });
test.afterEach(async ({page})=>{
  if(page.url() === "about:blank")return;
  await page.evaluate(async()=>{const token=sessionStorage.getItem("itda.authenticity.session.v1");if(token)await fetch("/v1/authenticity/session",{method:"DELETE",headers:{Authorization:`Bearer ${token}`}});sessionStorage.clear();});
});
for (const [name, width, height] of [["desktop",1440,1000],["mobile",390,844]] as const) {
  test(`${name}: actual API and data journey`, async ({ page }) => {
    await page.setViewportSize({width,height});
    const errors:string[]=[]; page.on("pageerror",e=>errors.push(e.message));
    await page.goto("/trip");
    await expect(page).toHaveURL(/\/trip$/);
    await expect(page.getByRole("heading",{name:"이번 여행에서 원하는 순간"})).toBeVisible();
    await page.evaluate(()=>document.fonts.ready);
    if(!process.env.ITDA_CAPTURE_RESULTS_ONLY)await page.screenshot({path:path.join(output,`${name}.png`),fullPage:true});
    for (const axis of ["H","E","R"]) {
      for (const letter of ["a","b","c","d"]) {
        const key=`${axis}.${letter}`;
        const value=axis==="H"&&letter!=="c"?"2":"0";
        await page.locator("label").filter({has:page.locator(`input[name="${key}"][value="${value}"]`)}).click();
      }
      await page.getByRole("button",{name:"다음",exact:true}).click();
    }
    if(!process.env.ITDA_CAPTURE_RESULTS_ONLY&&!process.env.ITDA_SKIP_LIVE_PHOTO){
    // Licensed public test material; the live model result is never treated as a human label.
    const pixels=fs.readFileSync(path.resolve(import.meta.dirname,"../../artifacts/national/20260909/official-cache/images/f27b96d96e0cf8bd814c4b5c0c7211fc97488a36ae885b91fd55777fac897fae"));
    await page.locator('input[type="file"]').setInputFiles({name:"official-place.jpg",mimeType:"image/jpeg",buffer:pixels});
    const remove=page.getByRole("button",{name:"사진 분석 결과 삭제"});
    await expect(remove).toBeVisible({timeout:160_000});
    await page.locator('label').filter({hasText:/사진 1 ·/}).getByRole('checkbox').first().check();
    await page.waitForFunction(()=>Array.from(document.querySelectorAll("main img")).every(i=>(i as HTMLImageElement).complete));
    await page.screenshot({path:path.join(output,`${name}-photo.png`),fullPage:true});
    const preview=await page.locator("main img").first().getAttribute("src");
    await page.route("**/v1/authenticity/photos",async route=>{await route.fulfill({status:503,json:{detail:"기술 검증용 업로드 실패입니다. 사진을 다시 선택해 주세요."}});},{times:1});
    await page.locator('input[type="file"]').setInputFiles({name:"replacement.jpg",mimeType:"image/jpeg",buffer:pixels});
    await expect(page.locator("main").getByRole("alert")).toContainText("기술 검증용 업로드 실패");
    expect(await page.locator("main img").first().getAttribute("src")).toBe(preview);
    await expect(page.locator('label').filter({hasText:/사진 1 ·/}).getByRole('checkbox').first()).toBeChecked();
    await page.screenshot({path:path.join(output,`${name}-photo-replacement-error.png`),fullPage:true});
    await remove.click();
    await expect(page.locator("main img")).toHaveCount(0);
    }
    await page.getByRole("button",{name:"사진 없이 추천 보기",exact:true}).click();
    await expect(page.getByRole("heading",{name:"내 기대와 연결되는 장소"})).toBeVisible();
    await expect(page.getByRole("button",{name:"장소 저장",exact:true})).toHaveCount(5);
    await expect(page.locator("article[data-details-loaded=true]")).toHaveCount(5);
    // Place galleries load real images lazily as each card enters the viewport.
    for (const photo of await page.locator("article img").all()) await photo.scrollIntoViewIfNeeded();
    await page.waitForFunction(()=>Array.from(document.querySelectorAll("article img")).every(i=>(i as HTMLImageElement).complete&&(i as HTMLImageElement).naturalWidth>0));
    await expect(page.locator("[data-recommendation-evidence]")).toHaveCount(5);
    await page.screenshot({path:path.join(output,`${name}-results.png`),fullPage:true});
    if(process.env.ITDA_CAPTURE_RESULTS_ONLY)return;
    await page.getByRole("button",{name:"장소 저장",exact:true}).first().click();
    await expect(page.getByRole("button",{name:"장소 저장됨",exact:true})).toHaveCount(1);
    await expect(page.getByRole("button",{name:/비교/})).toHaveCount(0);
    await expect(page.getByRole("link",{name:/비교/})).toHaveCount(0);
    await page.getByRole("link",{name:"장소 상세 보기",exact:true}).first().click();
    await expect(page.getByRole("heading",{name:"이 점수의 근거"})).toBeVisible();
    await page.locator("details summary").first().click();
    await page.screenshot({path:path.join(output,`${name}-detail.png`),fullPage:true});
    await page.getByLabel("기대와 같거나 달랐던 점").fill("자동 브라우저 기술 검증용 기록. 실제 방문 평가가 아닙니다.");
    await page.getByRole("button",{name:"여행 기록 저장"}).click();
    await expect(page.getByRole("button",{name:"기록을 저장했어요"})).toBeDisabled();
    await page.getByRole("link",{name:"저장한 장소"}).click();
    await expect(page.getByRole("heading",{name:"저장한 장소"})).toBeVisible();
    await expect(page.locator("main").getByRole("link")).toHaveCount(2);
    await page.screenshot({path:path.join(output,`${name}-saved.png`),fullPage:true});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
    expect(errors).toEqual([]);
    await page.evaluate(async()=>{const token=sessionStorage.getItem("itda.authenticity.session.v1");await fetch("/v1/authenticity/session",{method:"DELETE",headers:{Authorization:`Bearer ${token}`}});sessionStorage.clear();});
  });
}

test("confirmed photo connects to the actual recommendation", async ({page})=>{
  test.skip(process.env.ITDA_SKIP_LIVE_PHOTO === "1", "Live photo analysis explicitly disabled");
  await page.setViewportSize({width:390,height:844});
  await page.goto("/trip");
  for(const axis of ["H","E","R"]){
    for(const letter of ["a","b","c","d"]){
      const value=axis==="H"&&(letter==="a"||letter==="d")?"2":"0";
      await page.locator("label").filter({has:page.locator(`input[name="${axis}.${letter}"][value="${value}"]`)}).click();
    }
    await page.getByRole("button",{name:"다음",exact:true}).click();
  }
  const pixels=fs.readFileSync(path.resolve(import.meta.dirname,"../../artifacts/national/20260909/official-cache/images/f27b96d96e0cf8bd814c4b5c0c7211fc97488a36ae885b91fd55777fac897fae"));
  const uploaded=page.waitForResponse(r=>r.url().endsWith("/v1/authenticity/photos")&&r.request().method()==="POST");
  await page.locator('input[type="file"]').setInputFiles({name:"official-place.jpg",mimeType:"image/jpeg",buffer:pixels});
  expect((await uploaded).status()).toBe(200);
  await expect(page.getByRole("button",{name:"사진 분석 결과 삭제"})).toBeVisible({timeout:160_000});
  await page.locator("label").filter({hasText:"사진 1 · 녹지"}).getByRole("checkbox").check();
  const sent=page.waitForRequest(r=>r.url().endsWith("/v1/authenticity/profiles")&&r.method()==="POST");
  const received=page.waitForResponse(r=>r.url().endsWith("/v1/authenticity/runs")&&r.request().method()==="POST");
  await page.getByRole("button",{name:"선택한 분위기로 추천 보기"}).click();
  const submission=(await sent).postDataJSON();
  expect(submission.visual_input_kind).toBe("CONFIRMED_PHOTO");
  expect(submission.photo_receipt_sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(Object.keys(submission.visual_targets)).toEqual(["greenery"]);
  expect(submission.answers["H.a"]).toBe(2);
  const response=await received;
  expect(response.status()).toBe(200);
  const run=await response.json();
  expect(run.result_count).toBeGreaterThan(0);
  expect(run.items.some((i:{components:{rule:string;visual_comparison:unknown[]}[]})=>i.components.some(c=>c.rule==="CONFIRMED_VISUAL_FACET_MATCH"&&c.visual_comparison.length>0))).toBe(true);
  await expect(page.getByRole("heading",{name:"내 기대와 연결되는 장소"})).toBeVisible();
});
