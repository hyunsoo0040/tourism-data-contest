import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
const output=process.env.ITDA_UI_CAPTURE_DIR ?? path.resolve(import.meta.dirname,"../../artifacts/authenticity-v1/20260911/ui-preferences");
fs.mkdirSync(output,{recursive:true});
test.afterEach(async({page})=>{
  await page.evaluate(async()=>{const token=sessionStorage.getItem("itda.authenticity.session.v1");if(token)await fetch("/v1/authenticity/session",{method:"DELETE",headers:{Authorization:`Bearer ${token}`}});sessionStorage.clear();});
});
for(const [name,width,height] of [["desktop",1440,1000],["mobile",390,844]] as const){
  test(`${name}: intensity avoidance facilities and private axis record`,async({page})=>{
    page.setDefaultTimeout(Number(process.env.ITDA_E2E_ACTION_TIMEOUT_MS ?? 15_000));
    await page.setViewportSize({width,height});await page.goto("/trip");
    for(const letter of ["a","b","c","d"]){
      await page.locator("label").filter({has:page.locator(`input[name="H.${letter}"][value="2"]`)}).click();
    }
    await page.getByText("원형·유산과의 접촉의 강도·피하기 조정",{exact:false}).click();
    await page.getByLabel("원형·유산과의 접촉 원하는 강도").selectOption("1");
    await page.getByText("전통의 실제 지속의 강도·피하기 조정",{exact:false}).click();
    await page.getByLabel("전통의 실제 지속 피하기",{exact:true}).selectOption("1");
    await expect(page.locator('input[name="H.c"][value="0"]')).toBeChecked();
    await page.locator("label").filter({has:page.locator('input[name="H.c"][value="unknown"]')}).click();
    await expect(page.getByLabel("전통의 실제 지속 피하기",{exact:true})).toHaveValue("0");
    await page.getByLabel("전통의 실제 지속 피하기",{exact:true}).selectOption("1");
    await page.reload();
    await page.getByText("원형·유산과의 접촉의 강도·피하기 조정",{exact:false}).click();
    await page.getByText("전통의 실제 지속의 강도·피하기 조정",{exact:false}).click();
    await expect(page.getByLabel("원형·유산과의 접촉 원하는 강도")).toHaveValue("1");
    await expect(page.getByLabel("전통의 실제 지속 피하기",{exact:true})).toHaveValue("1");
    await page.evaluate(()=>document.fonts.ready);
    await page.screenshot({path:path.join(output,`${name}-preferences.png`),fullPage:true});
    await page.getByRole("button",{name:"다음",exact:true}).click();
    for(const axis of ["E","R"]){
      for(const letter of ["a","b","c","d"]){
        await page.locator("label").filter({has:page.locator(`input[name="${axis}.${letter}"][value="0"]`)}).click();
      }
      await page.getByRole("button",{name:"다음",exact:true}).click();
    }
    await page.getByText("꼭 필요한 시설 (선택)",{exact:true}).click();
    await page.getByLabel("장애인 화장실",{exact:true}).check();
    await page.screenshot({path:path.join(output,`${name}-facilities.png`),fullPage:true});
    const submitted=page.waitForRequest(r=>r.url().endsWith("/v1/authenticity/profiles")&&r.method()==="POST");
    const runResponse=page.waitForResponse(r=>r.url().endsWith("/v1/authenticity/runs")&&r.request().method()==="POST");
    await page.getByRole("button",{name:"사진 없이 추천 보기",exact:true}).click();
    const body=(await submitted).postDataJSON();
    expect(body.desired_levels).toEqual({"H.a":1});expect(body.avoid).toEqual({"H.c":1});
    expect(body.requirements.required_facilities).toEqual(["accessible_toilet"]);
    expect((await runResponse).status()).toBe(200);
    await expect(page.getByRole("heading",{name:"내 기대와 연결되는 장소"})).toBeVisible();
    // Return to the preserved draft and remove the hard facility requirement.
    await page.getByRole("link",{name:"새 여행 기대",exact:true}).click();
    for(let i=0;i<3;i++)await page.getByRole("button",{name:"다음",exact:true}).click();
    await page.getByText("꼭 필요한 시설 (선택)",{exact:true}).click();
    await expect(page.getByLabel("장애인 화장실",{exact:true})).toBeChecked();
    await page.getByLabel("장애인 화장실",{exact:true}).uncheck();
    await page.getByRole("button",{name:"사진 없이 추천 보기",exact:true}).click();
    await page.getByRole("link",{name:"상세 근거",exact:true}).first().click();
    await expect(page.getByRole("heading",{name:"내 여행 기록"})).toBeVisible();
    await page.getByLabel("이 장소를 방문했어요",{exact:true}).check();
    await page.getByLabel("대상•원형형 기대 충족",{exact:true}).selectOption("2");
    await page.getByLabel("의미•이미지형 기대 충족",{exact:true}).selectOption("1");
    await page.getByLabel("기대와 같거나 달랐던 점").fill("자동 브라우저 기술 검증. 실제 방문자 평가가 아닙니다.");
    await page.evaluate(()=>window.scrollTo(0,0));
    await page.screenshot({path:path.join(output,`${name}-personal-record.png`),fullPage:true});
    const feedback=page.waitForRequest(r=>r.url().endsWith("/feedback")&&r.method()==="POST");
    await page.getByRole("button",{name:"여행 기록 저장",exact:true}).click();
    expect((await feedback).postDataJSON().expectations_met).toEqual({H:2,E:1});
    await expect(page.getByRole("button",{name:"기록을 저장했어요"})).toBeDisabled();
    await page.getByLabel("이 장소를 방문했어요",{exact:true}).uncheck();
    const unvisited=page.waitForRequest(r=>r.url().endsWith("/feedback")&&r.method()==="POST");
    await page.getByRole("button",{name:"여행 기록 저장",exact:true}).click();
    expect((await unvisited).postDataJSON().expectations_met).toEqual({});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
  });
}
