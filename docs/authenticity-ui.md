# 진정성 기반 여행 기대 UI 기록

갱신일: 2026-09-12. `/trip`은 기존 IT-DA 인터페이스에 추가한 여행 기대 입력·추천·근거·비교·저장 화면이다. 현재 로컬 런타임은 **DEVELOPMENT 120곳**을 연결한다. [현재 개발 릴리스](../artifacts/authenticity-v1/20260911/development-release-120/release.json)는 `29f0ce39aaa2fd12cfd9b8986be2dc63e496fe13021b999b7200b9887c9f3634`다. 최초 F1–F3 화면 검토와 기존 캡처 14장은 실제 진단 자료 12곳을 연결했던 시점의 기록으로 보존한다. 전국 2,000곳의 새 분석 완료, 클라우드 운영 배포, 사람 평가 또는 전체 개편 계획의 완료를 뜻하지 않는다.

이 문서는 완료된 구현과 보관된 검증 자료를 기술한다. 120곳 전환·사진 확정 경로 확인 당시에는 F1–F3 이후 UI 변경이 없었다. 그 뒤 문항별 강도·회피, 필수 시설, 방문 후 축별 개인 기록을 기존 화면에 추가했고 별도 P1 검토를 마쳤다. 각 단계의 검증 기록은 해당 시점의 근거로 구분한다. 디자인 토큰의 새 원본이나 별도의 시각 체계를 정의하지 않는다. 문서화 단계에서는 UI 코드, `DESIGN.md`, `.impeccable/design.json`, 검증 판정을 변경하지 않았다.

## 구현과 시각 기준

화면은 [Journey.tsx](../web/src/features/authenticity/Journey.tsx), 지역 스타일은 [Journey.module.css](../web/src/features/authenticity/Journey.module.css), API 경계는 [api.ts](../web/src/features/authenticity/api.ts)에 있다. 추가 입력 컴포넌트는 [Preferences.tsx](../web/src/features/authenticity/Preferences.tsx), 초안 복원·설정 전환·사진 충돌 판단은 [preferenceState.ts](../web/src/features/authenticity/preferenceState.ts)에 있다. 기존 Next App Router의 [catch-all 페이지](../web/src/app/trip/[[...path]]/page.tsx)가 `SpaHost`를 사용하고, 실제 페이지 구분은 [routes.tsx](../web/src/app/routes.tsx)의 `/trip` 경로들에 등록되어 있다.

기존 내부 화면의 [internal.css](../web/src/app/styles/internal.css)가 크림색 페이지, 밝은 표면, 짙은 잉크색 본문, 청록색 강조, 오류·포커스·세 축 색상 변수의 원본이다. [globals.css](../web/src/app/globals.css)는 자체 호스팅 Noto Sans KR를 본문과 기본 입력 컨트롤까지 적용한다. 새 화면은 이 변수와 폰트를 사용한다.

| 요소 | 실제 표현과 동작 |
| --- | --- |
| 기본 공간 | 그림자 없는 평평한 배경, 얇은 구분선, 문항과 결과를 세로로 나열한다. 안내·인용·오류는 기존 표면색으로 구분한다. |
| 폭과 반응형 | 본문 최대 폭 1,080px. 650px 이하에서 좌우 여백 16px, 설문 선택지 2열, 결과·상세 정보 1열로 바뀐다. |
| 글자 위계 | 제목은 28–40px의 유동 크기, 본문은 전역 16px, 보조 정보는 13–14px. 한국어 본문 줄높이와 실제 줄바꿈을 유지한다. |
| 조작부 | 기본 선택지와 주요 버튼은 높이 48px 이상, 결과 행의 조작부는 44px 이상이다. 청록색은 선택됨·주요 동작에 사용한다. |
| 지역 변형 | 새 버튼·선택지는 6px 모서리, 입력은 5px, 비교 보관 막대는 8px다. 기존 내부 버튼의 12px 모서리나 1,120px 컨테이너를 전역에서 바꾸지 않는다. |
| 점수 | 대상•원형형 / 의미•이미지형 / 자기•몰입형의 독립 막대와 숫자를 병기한다. 값이 없으면 숫자 대신 `미확인`을 표시한다. |
| 사진 | 결과 목록은 일정 크기로 잘라 표시하고, 상세의 대표 사진은 전체 구도를 보존한다. 사진이 없는 응답은 `사진 미확인`으로 표시한다. |
| 비교 | 표 최소 폭 640px, 표를 감싼 영역 내부에서 가로 스크롤한다. 모바일 캡처는 처음 보이는 열을 보여주며 나머지 열은 가로 이동해서 읽는다. |
| 선택 입력 확장 | 강도·회피와 시설은 기본 disclosure로 접고 펼친다. 명시적 레이블이 있는 강도·회피 및 개인 기록 select는 데스크톱 2열, 650px 이하 1열이다. 시설 체크 항목은 줄바꿈하며 기존 청록색과 평평한 입력 표면을 사용한다. |

키보드 포커스는 기존 전역 포커스 표시와 선택지의 포커스 표시를 사용한다. 설문은 `fieldset`·`legend`·라디오 입력, 단계는 `aria-current`, 오류는 `role="alert"`, 진행 상태는 `role="status"`, 상세 근거는 기본 `details`·`summary`로 구성한다. 단계 전환은 제목으로 포커스를 옮기고 문서 상단으로 스크롤한다. 점수 막대의 220ms 전환은 동작 감소 설정을 요청하지 않은 경우에만 적용한다. 이는 소스에서 확인한 구현 사실이며 접근성 적합성 인증은 아니다.

## 사용자 흐름

| 경로·단계 | 실제 동작 |
| --- | --- |
| `/trip` · 기대 입력 | API가 제공한 12개 문항을 H/E/R 축별 4개씩 제시한다. 라디오로 중요도 또는 `아직 모르겠어요`를 선택하고 선택 입력에서 원하는 강도·피하기를 따로 조정한다. 현재 단계의 문항에 모두 응답해야 다음으로 진행한다. |
| `/trip` · 사진·추천 | 전국 또는 API가 제공한 지역을 고르고 꼭 필요한 시설을 선택할 수 있다. 사진은 선택 사항이며 최대 3장, 장당 10MB, JPG·PNG·WebP 안내가 있다. 사진 없이 추천받는 경로도 제공한다. |
| 사진 분석 후 | API가 `OBSERVED`로 반환한 분위기 후보와 0–4 수준을 표시한다. 사용자가 후보를 직접 선택해야 사진을 반영하는 동작이 활성화된다. 역사적 진위나 실제 혼잡의 판정이 아님을 설명한다. |
| `/trip/results/:runId` | 순위·기대 연결 점수·독립 축·지역·분류·대표 근거를 보여준다. 저장/저장 취소, 최대 3곳 비교, 상세 근거로 이동한다. |
| `/trip/results/:runId/places/:placeId` | 주소, 축 점수, 해석의 한계, 사진 출처·라이선스, 12개 세부 항목의 근거를 보여준다. 방문 여부와 최대 500자의 여행 기록을 저장할 수 있다. 방문했다고 선택하면 H/E/R별 기대 충족을 선택적으로 기록한다. |
| `/trip/results/:runId/compare?places=…` | 선택 장소의 세 축, 주소, 미확인 세부 항목을 표로 비교하고 각 상세 근거로 이동한다. |
| `/trip/saved` | 현재 세션의 저장 응답에서 장소명을 불러와 해당 추천 실행의 상세 화면으로 연결한다. |

입력 단계는 서비스 정보의 범위가 `DEVELOPMENT`일 때 연결된 장소 수를 안내한다. 기존 `ui-review/`의 입력 화면은 `현재 개발 표본 12곳을 연결한 화면입니다.`를 표시하며, 현재 120곳 런타임의 캡처로 재명명하지 않는다. 현재 연결 수는 런타임의 서비스 정보에 따른다. 개발 배너가 결과·상세의 모든 경로에 반복 표시되는 구현은 아니다.

설문 초안과 지역, 별도 강도·회피·필수 시설은 `sessionStorage`에 기록한다. 다시 열 때 설문 해시가 일치하고 현재 정의에 존재하는 응답·지역만 복원한다. 추가 설정은 응답과 양립하는 정수 범위만 복원하며 알 수 없는 시설 키와 중복 시설을 제거한다. 사진 미리보기, 선택한 분위기, 현재 단계와 비교 선택은 이 초안 복원 대상이 아니다. 세션 토큰 역시 `sessionStorage`를 사용하므로 이 UI를 계정이나 다른 기기까지 이어지는 저장 기능으로 설명하지 않는다.

## 강도·회피·시설과 개인 기록

각 문항의 `강도·피하기 조정`은 라디오 응답이 중요도라는 점을 설명한다. 원하는 강도는 별도 지정 없음 또는 0–4의 다섯 단계로 선택하며 중요도가 0·미확인·미응답이면 비활성화한다. 피하기는 조건 없음 또는 1–4의 네 단계다. 피하기를 지정하면 해당 중요도를 `상관없어요`(0)로 바꾸고 별도 강도를 지운다. 이 전환을 화면의 설명에 명시한다.

사용자가 라디오로 새 중요도를 선택하면 해당 항목의 기존 피하기를 항상 지운다. 새 값이 0 또는 `아직 모르겠어요`(`null`)이면 별도 강도도 지운다. 이후 피하기 select에서 다시 명시적으로 선택하는 것은 허용한다. 이 규칙은 P1 수정으로 확정됐으며 중요도·강도·회피를 사용자가 모르게 함께 제출하지 않도록 한다. 추천 제출에는 중요도 `answers`, 원하는 강도 `desired_levels`, 회피 `avoid`를 구분해 넣는다.

필수 시설은 **휠체어 대여, 유모차 대여, 장애인 화장실, 장애인 주차구역, 계단 없는 출입**의 다섯 실제 API 키와 연결된다. 선택은 `requirements.required_facilities`로 제출한다. 화면은 선택 시설이 공식 자료로 확인되는 장소만 추천하고 자료 부족으로 추천 수가 줄 수 있다고 안내한다. 포괄적인 접근성 보증이나 미확인 시설의 이용 가능 확인으로 설명하지 않는다.

선택 사진의 녹지·물·트인 구도는 `R.b` 피하기와, 나머지 지원 분위기는 `E.c` 피하기와 충돌 여부를 확인한다. 충돌하면 사진 확정·프로필 제출 전에 분위기 선택 해제 또는 이전 단계의 피하기 수정을 요청하는 오류를 표시한다. 사진 없이 진행하는 동작은 계속 제공한다. 전통적 외관 사진을 H 축의 진위·유산 선호로 해석해 충돌시키는 규칙은 없다.

개인 여행 기록에서 방문 체크를 하면 대상•원형형, 의미•이미지형, 자기•몰입형의 기대 충족 select가 나타난다. 각 축은 평가하지 않음 또는 0–4의 다섯 단계이며 선택한 값은 `expectations_met`로 제출한다. 방문 체크를 해제하면 축별 값을 지우고 빈 객체를 제출한다. 화면은 개인 경험 기록이 장소의 역사 사실이나 기존 점수를 바꾸지 않고 현재 연구 평가에 집계되지 않는다고 설명한다. [피드백 응답 계약](../backend/src/itda/authenticity/api_contracts.py)의 `research_use`는 `Literal[False]`이며, 화면 요청이 사람 연구 평가를 활성화하는 필드를 보내는 구조는 아니다.

기록 저장 중에는 방문 체크·축별 select·메모·저장 버튼을 비활성화하고 저장 중 문구를 표시한다. 저장 실패 후 입력을 바꾸지 않고 다시 누르면 같은 요청 식별자를 사용한다. 사용자가 입력을 수정하거나 다른 장소로 이동하면 식별자를 초기화한다. 성공 후에는 저장 버튼을 비활성화하며 기록을 수정하면 다시 저장할 수 있다. 실패 후 식별자 유지와 저장 중 조작 제한은 소스 확인 범위다.

## 근거와 불확실성 표현

결과 목록은 장소의 우열과 이번 입력에 대한 연결 정도를 구분하는 설명으로 시작한다. `ResultReason`은 실제 비교에 사용된 항목을 가중치 순으로 살펴보고, 기여 근거에 연결된 해당 항목의 인용을 표시한다. 인용은 최대 160자로 줄이며 잘림 표시를 붙인다. 인용 아래에는 같은 근거 객체의 제공자와 역할을 한국어로 표시한다. 12곳 릴리스의 최종 F2 결과 캡처에서 다섯 행에는 각각 다른 장소 인용과 `한국관광공사 · 공식 설명`이 보인다.

텍스트 인용 대신 사진 기여의 외관 설명을 사용하는 분기에도 제공자·역할을 표시한다. 연결 가능한 요약 근거가 없으면 상세에서 판단과 미확인 사항을 확인하도록 안내한다. 이 사진 설명 분기는 소스에서 확인했으며 최종 F2 결과 캡처가 실행한 분기는 텍스트 인용이다. 후속 사진 확정 추천 테스트도 결과의 사진 설명 분기 자체를 별도로 검증하지는 않는다.

상세에서는 세부 항목별 판단, 텍스트·사진·SNS 채널, 기여 비율, 인용 또는 관찰 내용, 제공자·역할·수집일을 보여준다. URI가 있는 근거에는 출처 링크가 나타난다. 사진은 분위기 관찰로 설명하며 SNS 수치는 관측된 태그 게시물 수로 표시한다. 사진과 SNS를 실제 만족도나 역사적 진위의 확정 근거로 표현하지 않는다.

축이나 세부 항목의 `null`은 `미확인`으로 표현한다. 추천 응답이 `LIMITED`이면 실제 확보한 수를 안내하고, `EMPTY`이면 지역이나 기대 조정을 제안한다. 다섯 곳을 화면에서 임의로 채우는 구현은 없다. 이 제한·빈 추천 분기는 소스 확인 범위이며 보관된 결과 화면은 다섯 곳이 있는 응답이다.

## 사진과 비동기 상태

사진 업로드 성공 응답을 받은 뒤에만 미리보기와 분석 응답을 교체하고 후보 선택·추천 재요청 식별자를 초기화한다. 교체 업로드가 실패하면 이전 미리보기와 선택을 유지하면서 오류를 표시한다. 실패한 교체 사진의 객체 URL은 만들지 않으며 이전 미리보기 URL은 교체 또는 화면 해제 시 해제한다.

사진 분석 결과 삭제는 DELETE 성공 후 미리보기와 선택을 비운다. 화면은 위치 메타데이터 제거, 서버 원본 미보관, 선택한 분위기만 반영하는 계약을 설명한다. 이 문서의 캡처 확인 자체가 서버의 삭제·메타데이터 제거를 별도로 입증하는 것은 아니다.

저장·비교 화면은 로딩, 성공, 실패, 성공했지만 비어 있는 응답을 구분한다. 실패에는 `다시 불러오기`가 있고, 화면을 떠난 후 응답이 도착해도 상태를 갱신하지 않도록 처리한다. 장소별 상세를 불러오는 중에는 결과 목록이 `장소의 연결 근거를 불러오고 있어요.`와 사진 로딩 상태를 사용한다.

API는 같은 출처의 `/v1/authenticity`를 사용하고 생성된 OpenAPI 타입을 가져온다. 세션 토큰을 Authorization 헤더에 넣고 `no-store`로 요청한다. 오류 응답은 한국어 메시지로 표시하며 401에서 로컬 토큰을 지운다. 저장·비교의 재시도 버튼처럼 명시적으로 구현한 동작 외에 공통 클라이언트 자동 재시도는 없다.

## 검증 자료와 판정 범위

[최종 검토](../artifacts/authenticity-v1/20260911/ui-finish-review.md)의 판정은 **F1·F2·F3 모두 resolved, disposition: ship**이다. 이 판정은 12곳 화면으로 확인한 아래 세 수정에만 적용된다. 120곳 전환과 사진 확정 경로의 추가 실행으로 판정 범위를 확대하지 않는다.

| 수정 | 확인된 근거 | 남아 있는 검증 범위 구분 |
| --- | --- | --- |
| F1 · 사진 교체 실패 시 미리보기와 분석 불일치 | 실제 사진 업로드 후 교체 요청에 기술 검증용 HTTP 503을 주입했다. 데스크톱·모바일 테스트는 기존 미리보기 URL과 체크된 후보가 유지됨을 검증했다. | 주입한 503은 실제 서비스 장애 기록이 아니다. |
| F2 · 결과의 일반 분류 대신 장소 근거 표시 | 갱신된 결과 캡처의 다섯 행에서 항목별 인용·제공자·역할이 표시된다. `ResultReason`의 인용·사진 분기를 확인했다. | 사진 설명 분기는 소스 확인이다. 최종 재실행은 결과 화면의 라벨 보정을 대상으로 했다. |
| F3 · 저장·비교 로딩을 빈 내용으로 표시 | 소스는 로딩·오류·빈 성공·재시도를 분리한다. 양쪽 폭의 저장·비교 캡처에는 실제 데이터가 있다. | 일시적인 로딩·오류·빈 성공 상태에는 별도 브라우저 assertion이나 전용 캡처가 없다. |

[브라우저 테스트 소스](../web/e2e/authenticity-journey.spec.ts)와 [설정](../web/playwright.authenticity.config.ts)은 실제 API·연결된 개발 자료를 사용한다. [browser-verdict.log](../artifacts/authenticity-v1/20260911/browser-verdict.log)는 12곳 릴리스에서 데스크톱 1440×1000·모바일 390×844의 두 여정을 14.6초에 통과한 기록이다. 허용된 공개 관광사진 업로드, 후보 선택, 명시적으로 주입한 교체 실패, 사진 삭제, 사진 없는 추천, 근거 로딩, 2곳 비교, 저장, 여행 기록 저장을 거친다. 기록 문구는 자동 브라우저 기술 검증임을 명시하고 실제 방문을 주장하지 않는다. 테스트는 세션 삭제 후 로컬 세션을 비운다.

[browser-verdict-f2.log](../artifacts/authenticity-v1/20260911/browser-verdict-f2.log)는 12곳 릴리스의 결과 라벨 수정 후 두 여정이 4.9초에 통과한 기록이다. `ITDA_CAPTURE_RESULTS_ONLY` 경로는 추가 사진 업로드 없이 결과 화면까지만 진행한다. 당시 사진 확정 후 추천 경로는 이 두 로그의 검증 범위 밖이었으며, 아래 별도 모바일 테스트로 후속 확인했다. 모든 오류·빈 결과, 모든 접근성·브라우저 조합을 검증한 기록은 아니다.

최초 문서화 과정에서는 아래 기존 PNG 14장을 직접 열어 소스의 표현과 대조했다. 모두 12곳 릴리스의 검토 기록이며 그대로 보존한다. 문서화 및 이번 문서 갱신에서는 새 브라우저 실행, 캡처 재생성, 모델 요청 또는 전체 화면의 재승인 검토를 수행하지 않았다.

| 상태 | 데스크톱 | 모바일 |
| --- | --- | --- |
| 첫 설문 | [desktop.png](../artifacts/authenticity-v1/20260911/ui-review/desktop.png) | [mobile.png](../artifacts/authenticity-v1/20260911/ui-review/mobile.png) |
| 사진 분석·선택 | [desktop-photo.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-photo.png) | [mobile-photo.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-photo.png) |
| 교체 실패·이전 선택 유지 | [desktop-photo-replacement-error.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-photo-replacement-error.png) | [mobile-photo-replacement-error.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-photo-replacement-error.png) |
| 추천·출처 라벨 | [desktop-results.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-results.png) | [mobile-results.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-results.png) |
| 상세·첫 근거 펼침 | [desktop-detail.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-detail.png) | [mobile-detail.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-detail.png) |
| 비교 | [desktop-compare.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-compare.png) | [mobile-compare.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-compare.png) |
| 저장 | [desktop-saved.png](../artifacts/authenticity-v1/20260911/ui-review/desktop-saved.png) | [mobile-saved.png](../artifacts/authenticity-v1/20260911/ui-review/mobile-saved.png) |

120곳 활성화 후의 [browser-release-120.log](../artifacts/authenticity-v1/20260911/browser-release-120.log)는 같은 데스크톱·모바일 폭에서 실제 API의 결과 화면까지 진행한 두 테스트가 5.8초에 통과한 기록이다. 다섯 결과, 상세 데이터 로딩, 실제 이미지 로딩, 다섯 근거 요소를 확인했다. 별도 보관된 [120곳 데스크톱 결과](../artifacts/authenticity-v1/20260911/ui-review-120/desktop-results.png)와 [120곳 모바일 결과](../artifacts/authenticity-v1/20260911/ui-review-120/mobile-results.png)는 해당 런타임의 화면이다. 이 두 캡처는 기존 14장을 대체하지 않으며, 120곳에서 비교·저장·기록까지 전부 다시 검증한 자료로 설명하지 않는다.

사진 확정 추천의 [최초 실행](../artifacts/authenticity-v1/20260911/browser-confirmed-photo.log)은 실제 모델 분석 실패 후 `사진 분석 결과 삭제` 버튼을 기다리다가 160초 제한으로 실패했다. 실행 기록에는 오류와 사진 없이 진행하는 상태가 남았으며, F1 검증에서 의도적으로 주입한 교체 실패와는 별개의 실제 제공자 실패다. [재실행](../artifacts/authenticity-v1/20260911/browser-confirmed-photo-retry.log)은 실제 API·모델을 사용하는 모바일 390×844의 한 테스트가 5.2초에 통과한 기록이다. 성공 기록으로 최초 실패를 지우거나 사진 분석의 안정성을 확정하지 않는다.

사진 확정 테스트는 허용된 공개 사진의 녹지 후보를 선택하고 `선택한 분위기로 추천 보기`를 누른다. 제출의 `CONFIRMED_PHOTO`, 64자리 SHA-256 형식의 사진 수신증, 녹지만 포함한 시각 목표, 설문에서 고른 `H.a=2` 유지, 성공한 실제 추천 응답과 결과 화면 진입을 확인한다. 반환 결과 중 하나 이상에 `CONFIRMED_VISUAL_FACET_MATCH` 규칙과 비어 있지 않은 `visual_comparison`이 있음을 검증한다. 이에 따라 사진 확정에서 실제 추천 반영까지의 기존 브라우저 검증 공백은 해당 모바일 시나리오에서 해소됐다. 모든 H 응답의 불변성, 데스크톱의 동일 분기, 모든 분위기·오류 조합 또는 사진 설명 분기의 렌더링까지 이 테스트가 검증한 것은 아니다.

[이전 12곳 구조 검증](../artifacts/authenticity-v1/20260911/development-release/validation.json)과 [현재 120곳 구조 검증](../artifacts/authenticity-v1/20260911/development-release-120/validation.json)은 각각 해당 분석 수의 결합·출처 권한·산술 검사 범위다. 두 기록 모두 의미 정확도는 `NOT_ESTABLISHED`, 사람 평가는 `EXCLUDED_BY_USER`다. UI의 여행 기록은 현재 연구 평가로 집계하지 않는다고 표시한다. 사람 평가·모집, 추가 유료 수집, 전국 전체 전환 승인은 이 UI 검토에서 발생하지 않는다.

## 추가 입력 검토와 실행 근거

[추가 입력 최종 검토](../artifacts/authenticity-v1/20260911/preferences-finish-review.md)는 **P1 resolved, disposition: ship**이다. 최초 `fix` 기록은 남겨 두고, 새 라디오 응답이 기존 회피를 지우도록 한 단일 수정만 최종 승인했다. F1–F3를 다시 검토하거나 전체 앱·접근성·사람 평가의 유효성을 인증한 판정은 아니다.

[추가 입력 브라우저 테스트](../web/e2e/authenticity-preferences.spec.ts)의 [최종 실행 로그](../artifacts/authenticity-v1/20260911/browser-preferences-verdict.log)는 실제 DEVELOPMENT 120 API에 연결한 데스크톱 1440×1000·모바일 390×844의 두 여정이 10.5초에 통과했음을 기록한다. 다음을 직접 확인했다.

| 확인 대상 | 브라우저에서 확인한 범위 |
| --- | --- |
| 강도·회피 | H.a 강도 1, H.c 회피 1을 선택하고 중요도 0 전환을 확인한다. H.c를 `아직 모르겠어요`로 바꾸면 회피가 0이 됨을 확인한 뒤 회피 1을 명시적으로 다시 선택한다. |
| 초안 복원 | 새로고침 후 강도·회피 값이 유지됨을 확인한다. 시설을 넣어 추천받은 뒤 입력으로 돌아오면 장애인 화장실 체크가 유지됨을 확인한다. |
| 실제 제출 | `desired_levels={H.a:1}`, `avoid={H.c:1}`, `required_facilities=[accessible_toilet]` 제출과 추천 HTTP 200을 확인한다. 이후 시설 조건을 해제하고 실제 결과의 상세로 이동한다. |
| 개인 기록 | 방문 상태에서 H=2, E=1을 제출하고 저장 성공을 확인한다. 방문 체크를 해제한 뒤 `expectations_met={}` 제출을 확인한다. 메모에는 자동 기술 검증이며 실제 방문자 평가가 아님을 명시한다. |

[도우미 테스트](../web/src/features/authenticity/Preferences.test.ts)의 두 검사는 형식·응답에 맞는 초안 복원, 알려진 시설만 유지·중복 제거, 새 중요도와 0·null의 회피 제거, 0의 강도 제거, 사진 충돌 예시를 다룬다. 최종 실행 인계와 검토의 verdict에 두 검사 및 TypeScript 통과가 보고됐다. 문서화 단계에서 검사를 다시 실행하지 않았다.

브라우저 테스트는 시설 다섯 종류의 모든 필터 조합이나 시설 데이터의 정확성을 검증하지 않는다. 사진과 회피가 충돌하는 UI 경로, R 축 개인 점수 제출, 피드백 실패 후 재시도·중복 클릭, `research_use:false` 응답 자체에는 이 테스트의 별도 assertion이 없다. 사진 충돌은 도우미·소스, 피드백 응답의 연구 제외는 계약 확인으로 구분한다.

아래 현재 캡처 6장은 최종 리뷰어가 직접 열어 문서 상단부터 해당 상태가 포함된 정상 화면임을 확인했다. 모두 새 컨트롤을 포함한 DEVELOPMENT 120 화면이며 기존 `ui-review/` 14장과 `ui-review-120/` 결과 2장은 이전 시점 기록으로 보존한다. 알 수 없음 선택 직후 회피가 지워지는 P1 전환은 브라우저 assertion으로 확인했고, 캡처는 회피를 명시적으로 다시 설정한 상태다.

| 추가 상태 | 데스크톱 | 모바일 |
| --- | --- | --- |
| 강도·피하기 | [desktop-preferences.png](../artifacts/authenticity-v1/20260911/ui-preferences/desktop-preferences.png) | [mobile-preferences.png](../artifacts/authenticity-v1/20260911/ui-preferences/mobile-preferences.png) |
| 필수 시설 | [desktop-facilities.png](../artifacts/authenticity-v1/20260911/ui-preferences/desktop-facilities.png) | [mobile-facilities.png](../artifacts/authenticity-v1/20260911/ui-preferences/mobile-facilities.png) |
| 방문 후 개인 기록 | [desktop-personal-record.png](../artifacts/authenticity-v1/20260911/ui-preferences/desktop-personal-record.png) | [mobile-personal-record.png](../artifacts/authenticity-v1/20260911/ui-preferences/mobile-personal-record.png) |

## 기존 문맥의 차이와 후속 관리 경계

확인 시점에 저장소 및 `web/` 루트에 `PRODUCT.md`·`DESIGN.md`가 없고, Impeccable context도 해당 문맥과 표면 브리프를 찾지 못했다. 이는 기존 문서 공백으로 기록한다. 이 작업의 기준은 기존 코드와 사용자가 고정한 크림·잉크·청록·Noto Sans KR 체계이며 새로운 디자인 권한 파일은 생성하지 않았다.

프로젝트의 기술 권고에는 React/Vite가 남아 있으나 실제 앱은 이미 Next App Router를 사용한다. 전역 CSS는 기존 내부 화면과 별도로 범위를 제한한 upstream 스타일을 함께 가져온다. 내부 CSS의 Pretendard 우선 선언은 전역 Noto Sans KR 재정의 아래에 있다. 이 차이들은 `/trip` 확장 이전의 구성으로 취급하며 문서화 중 교체하거나 정리하지 않았다.

[전체 구현 기록](authenticity-implementation.md)은 현재 120곳 런타임과 남은 개편 작업을 별도로 관리한다. 현재 `/trip`의 한정된 실제 동작과 검증 근거는 이 문서에 기록하되, 그것으로 개편 전체·2,000곳 재분석·평가 요구사항을 완료 처리하지 않는다.
