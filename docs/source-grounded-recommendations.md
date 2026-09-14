# 출처 기반 추천 운영

> 2026-09-09 현재 [전국 신규 자료 수집](nationwide-data.md)을 진행 중이다. 아래 PUBLIC100의
> 수치·기존 배포 묶음은 경주 기준의 이전 검증 기록이며, 새 전국800~1,000곳의 완료 증거가 아니다.

## 기본 실행 설정 (DEFAULTS)

일반 배포의 기본값은 `ITDA_GROUNDED_RECOMMENDATIONS_ENABLED=1`,
`ITDA_TOURISM_ENABLED=1`, `ITDA_GROUNDED_DAILY_ENABLED=1`,
`ITDA_PHOTO_MOOD_ENABLED=1`이다. 추천은 출처·분석·사진 분위기가 같은 버전으로 묶인 데이터를 사용하고, 공식 관광
맥락과 사진 분위기 채널이 연결된다. 오프라인 미리보기는 명시적으로
`ITDA_NO_NETWORK=1`, `ITDA_TOURISM_ENABLED=0`을 사용한다.

초기 배포도 닫힌 후보와 그 후보의 실제 측정 보고서 세 개를 검증한 초기 시드가 필요하다.
배포 초기화가 이를 활성화해야 첫 추천을 제공할 수 있으며, 기본값 변경은 이 검증을
생략하지 않는다. 이후 일일 배치는 같은 활성화 검증을 거쳐 새 후보로 교체한다.

`itda.cli.deploy_database`는 역할·스키마 구성 후 초기 묶음을 설치한다. 기본 경로는
`artifacts/public/catalog/grounded-bootstrap/`의 `candidate.json`, `gate.json`, `reports/`이며
백엔드 이미지에 읽기 전용으로 포함한다. `ITDA_GROUNDED_INITIAL_CANDIDATE_FILE`,
`ITDA_GROUNDED_INITIAL_GATE_FILE`, `ITDA_GROUNDED_INITIAL_REPORT_DIR`를 모두 지정하면
다른 검증된 묶음을 사용할 수 있다. 이미 호환되는 활성 묶음이 있으면 그대로 유지하며,
동시에 다른 배치가 활성화한 결과도 덮어쓰지 않는다.

신규 추천은 활성 묶음만 사용한다. 묶음이 없거나 새 추천을 비활성화하면 503으로 중지하며
이전 점수 계산으로 되돌아가지 않는다. `ITDA_GROUNDED_CANDIDATE_SHA256`로 검증 전 후보를
직접 서비스하는 방식은 허용하지 않는다. 저장된 과거 결과의 재생은 계속 지원한다.

새 사진 작업은 설정과 관계없이 `photo-mood-v1`이다. 사진 분석을 끄거나 키가 없으면
분석 불가·삭제 처리로 끝나며, 예전 M1–M6 분석으로 전환하지 않는다. 처리 대기 중인
과거 사진 작업의 신규 특성 분석도 차단한다. 기존에 확정된 결과의 조회·재생·삭제는 보존한다.

운영 기본값의 이전 실제 검증 기록은
`artifacts/reports/grounded-production-live-20260909/verification.json`에 있다. 인증 주체만
합성한 API·PostgreSQL 검증에서 실제 관광 API 30회(3개 장소, 7종 서비스)를 호출했고,
GLM-5.3-flash 사진 분석 1회와 취향 확정·삭제 후 추천 재생을 확인했다. 사진 결과는
분위기 5개 확인·3개 미확인이었으며 100개 장소의 핵심 점수·시설·운영 근거는 바뀌지 않았다.
이 기록은 브라우저 검증이나 인간 정확도 평가로 표현하지 않는다. 당시 화면의 실제
브라우저→API→DB 검증은 `artifacts/reports/grounded-defaults-browser-20260909/`에 별도로 보존한다.

## 관광공사 API의 적용 범위

관광지 설명과 사진은 버전이 고정된 장소 분석에 사용한다. 방문 시점의 조건에 필요한
시설 정보는 추천 생성 때 조회하고 그 응답을 저장한다. 결과 화면에서 새로 조회하는
날짜별 예측·지역 통계는 표시용이며, 저장된 추천 점수나 순위를 다시 계산하지 않는다.

| API | 제품에서 사용하는 정보 | 점수 해석의 제한 |
|---|---|---|
| [관광지 집중률](https://www.data.go.kr/data/15128555/openapi.do) | 여행 날짜와 같은 장소의 다른 날짜에 대한 상대적 집중 예측 | 향후30일 예측. 현재 인원·물리적 밀도·장소 간 절대 혼잡도 비교에 사용하지 않음 |
| [지역별 방문자 수](https://www.data.go.kr/data/15101972/openapi.do) | 기준 날짜가 명시된 경주 지역 방문 추이 | 개별 장소 입장객 수나 인기 가산점으로 사용하지 않음 |
| [무장애 여행](https://www.data.go.kr/data/15101897/openapi.do) | 명시적 시설 요구, 대여·화장실·주차·무단차 정보 | 동행 선택으로 신체 조건을 추정하지 않으며 명시적 부재만 제외 사유로 사용 |
| [두루누비](https://www.data.go.kr/data/15101974/openapi.do) | 근처 걷기 코스·거리·소요 시간·난이도 | 시간 필드 `crsTotlRqrmHour`의 공식 단위는 **분**. 코스 전체 값을 관광지 내부 보행량으로 옮기지 않음 |
| [고캠핑](https://www.data.go.kr/data/15101933/openapi.do) | 정확히 대응한 캠핑장의 공식 시설·운영 안내 | 현재 예약 가능 여부를 추정하지 않으며 숫자0을 모든 시설의 부재로 확대하지 않음 |
| [연관 관광지](https://www.data.go.kr/data/15128560/openapi.do) | 내비게이션 이동에 기반한 주변 일정 후보 | 개인 취향 점수나 품질 가산점으로 사용하지 않음 |
| [지역별 관광 수요 강도](https://www.data.go.kr/data/15151868/openapi.do) | 경주시·기준월별 관광 체류·소비 상대 지수 | 원·명·확률 또는 100점 만점으로 변환하지 않으며 개인 취향·장소 혼잡 점수에 반영하지 않음 |

시설 캐시는 기본24시간, 날짜 예측·지역 통계 캐시는6시간, 실패 캐시는15분이다.
통계 기준일은 응답과 화면에 보존한다. 방문자·수요 조회는 기본2개월 전을 요청하며
최신성 보장이 아니다. 연관 관광지는2026-09-09 확인한 공식 문서의 제공 범위 끝인
**2025-04**를 기본 요청한다. 더 최근 자료의 제공을 확인한 뒤
`ITDA_TOURISM_RELATED_MONTH`로 바꿀 수 있다. 각 서비스는 별도 기준 기간 설정을 지원한다.

고캠핑 전국 목록은 페이지당 최대200건으로 수집한다.1000건 응답은 실제로 공통2MB
응답 상한을 넘었기 때문에 상한을 늘리지 않고 페이지를 나눴다. 기본 최대40페이지 내
수집을 완료하지 못하면 부분 수집으로 표시하며 완전한 지역 목록이라고 주장하지 않는다.

2026-09-09 실제 검증에서는 고캠핑 전국3,115건·경주62건을 확인했다. 현재100곳의
카탈로그와 엄격히 대응한 사례는 뷰델카라반펜션1곳이었다. 표기가 다른 캠프ING과
캠프아이엔지, 해변과 해변 내 캠핑장을 자동으로 같은 장소로 합치지 않았다.
연관 관광지와 지역별 수요 강도의 인증 오류는 2026-09-09 15:54(KST) 재확인에서
해결됐다. 같은 설정으로 두 서비스 모두 HTTP200/공급자 코드0000을 반환했다.
연관 관광지2025-04 경주 자료1,918건을 완전 수집했고, 기존 자격·중복 필터를 통과한
나정고운모래해변→한화리조트 경주 연결을 실제 소비 경로에서 확인했다.

수요 API는 문서상 선택값인 지표 코드를 생략하면 정상 코드와 빈 목록을 반환했다.
운영 호출은 전체 체류 `tarSjrnDsIxCd=21`, 전체 소비 `tarExpDsIxCd=22`를 명시한다.
2026-07 경주시의 실제 값은 체류102.99·소비77.92였고,2025-09는91·74.48이었다.
지역 코드47/시군구 코드47130과 기준월·지표 코드·출처가 일치하는 전체 지수만
`AVAILABLE / TOURISM_DEMAND_INDEX`로 제공한다. 확인할 수 없는 과거 원문은
기존 `UNKNOWN / UNVERIFIED_PROVIDER_UNIT` 형태를 유지한다.

[한국관광 DataLab](https://datalab.visitkorea.or.kr/datalab/portal/loc/getTourActivateForm.do)의
설명에 따라 이 값은 지역 상대 지수로 해석한다. 고정0–100 범위나 물리 단위는 가정하지
않으며, 월별 척도 변화가 가능하므로 수치를 실제 방문자·소비액 증가율로 바꾸지 않는다.
서버와 화면 모두 소수를 정확하게 비교하고,100을 넘는 값도 그대로 보존한다.

검증 원문과 정규화 결과는 다음 로컬 산출물에 보존한다.

- `artifacts/research/tourism-source-verification-20260909-runtime/`: 실제7개 서비스 소비 경로,15회 요청. 고캠핑 초기 크기 실패 포함.
- `artifacts/research/tourism-camping-runtime-recovery-20260909/`: 작은 페이지16회로 수집한 전체 목록과 실제 소비기 재생 결과.
- `artifacts/research/kto-context-20260909/`: 초기 범위 조회·공식 매뉴얼·인증 오류 재확인.
- `artifacts/research/tourism-authority-approved-20260909/`: 인증 해결, 실제 연관 장소 및 수요 지표 코드 유무 대조·응답 원문.
- `artifacts/research/tourism-demand-authorized-20260909/`: 공식v4.0 매뉴얼·지역 코드표·지수 단위 해석의 근거.

수정된 수요 호출은 실제 API·PostgreSQL 검증에서 다시 확인했다. 정상 조회 factory와
HTTP 경로를 통해 체류`102.99`·소비`77.92`가 정확한 소수 문자열로 전달됐고,
재조회는 추가 호출 없이 캐시를 사용했으며 저장된 추천 응답은 전후 바이트까지 같았다.
이 검증은 격리된 DB에 미리 저장한 실행을 조회하는 범위다. 신규 추천 생성·활성본 승격·
세션 인증 검증으로 확대하지 않는다. 다른6종은 호출 예산상 미설정이며, 현재 서비스
장애라는 뜻이 아니다. 실제 응답은 `artifacts/reports/grounded-demand-live-20260909/api-fixture.json`에 있다.

이 응답의 데스크톱·모바일 브라우저 재생2개와 기존 오프라인 서버의 호환성·사진 흐름2개가
통과했다. 두 검증의 실행 범위는 구분해 기록했다. 백엔드 관련81개, 프런트엔드61개,
OpenAPI5개 및 번들1개 검사가 통과했다. 최신 API/UI 보고서·게이트·재현 스크립트는
`artifacts/evaluation/grounded-authority-v2-20260909/promotion-authorized-demand/`에 보존한다.
현재 배포 파일 묶음의 게이트는`b76926cfe39ca7e317b2d7e92cc4819724128bb1d8fda5a0f6cab2f06a862309`,
패키지는`b44345538006ff4eaf96efda3bf2b3e71f790ed0a9403124f38d9cc24ce773d4`다.
실행 중인 로컬8000 서버는 이전 오프라인 버전이며, 이번 API/DB 검증은 별도 프로세스에서
수행했다. 이 파일 묶음의 갱신을 서버 재시작이나 배포로 표현하지 않는다.

두 API의 인증 차단은 해결됐다. 2026-09-09 사용자가 원본 평가 자료가 없다고 확인했으므로
원본 DEV24/BLIND12 식별 목록과 provider 교차표의 복원 대기는 종료한다. 현재 PUBLIC100의
실제 장소 ID·공식 출처는 확보되어 있으며, 추천 개선과 API 연결의 구현·자동 검증은 완료했다.
존재하지 않는 과거 평가 자료를 이 구현 작업의 미완료 사유로 두지 않는다.

사람이 판단한 추천 정확도·만족도는 여전히 미측정이다. 이미 분석한 장소를 다시 나누어
블라인드 평가로 부르거나, 이번 정상 수신·구조 검증을 정확도 향상의 실증 결과로 표현하지 않는다.
[새 검수 절차](evaluation-restart.md)에 현재 자료의 검수 목록과 후속 실증 평가 범위를 정리했다.
제품 활성화에 필요한 기존 측정 보고서 검증은 유지한다. 이후 로컬 작업은 GSD 없이 진행한다.

## 점수와 이미지의 근거

지원되는 세부 항목만 동일 가중으로 집계하여 H/E/R을0–100으로 변환한다. 축마다
4개 중 최소2개 근거가 필요하며, 근거가 없으면 `null/UNKNOWN`이다. 과거 독립 축 점수는
비교용으로 보존하고 새 집계 결과로 원본을 덮어쓰지 않는다.

`source-authority-v2`는 인용된 문장에 계절·시간대에 따른 실제 경험이 있는지 M6에
추가 검사를 적용한다. 계절 정보가 없다는 이유로 낮은 숫자를 만들지 않는다. 영업시간,
예약, 점심 대기, 숙박이라는 업종만으로 시간 의존도를 추정하지 않는다. 이 검사는 보수적
출처 허용 규칙이며 인간의 정답 라벨이나 의미 이해 정확도 평가를 대신하지 않는다.

사용자·관광지 사진은 녹지, 물, 구도, 전통적 외관, 현대적 디자인, 빛, 색, 야간 조명 등
별도의 분위기 채널에만 영향을 준다. 핵심 경험 축·혼잡·운영·시설·역사 지정 사실은
픽셀이나 사진 속 글자로 산출하지 않는다. 관광지 사진은 권리, 중복, 촬영 시점과
계절·시간대 대표성을 확인한다. 촬영일을 모르는 사진을 현재 모습이라고 표시하지 않는다.

<!-- GROUNDED_DAILY_OPERATIONS_START -->
## 일일 분석과 후보 보관

`itda.cli.run_daily_glm_refresh` 진입점은 기본적으로 grounded 일일 배치를 실행한다.
`ITDA_GROUNDED_DAILY_ENABLED=0`은 작업을 중지하는 명시적 오류이며, 과거 raw-only
릴리스 활성화·재수집 경로로 전환하지 않는다. 과거 일일 authority 설정도 새 진입점에서
사용하지 않는다. 운영 전환 시 기존 스케줄러 프로세스를 종료하고 새 버전으로 교체한다.

스케줄은 `Asia/Seoul` 매일 08:00이다. 한 프로세스에서 날짜별 작업을 한 번 수행하고,
명시적으로 지정한 게이트/보고서 디렉터리가 바뀌면 검증을 다시 진행한다. 대기 간격은
최대 15초다. 실패한 작업의 재개는 같은 날짜로 일회 실행할 수 있다.

```sh
PYTHONPATH=backend/src \
  backend/.venv.nosync/bin/python -m itda.cli.run_daily_glm_refresh \
  --once --run-date 2026-09-10 --workers 4
```

필요한 설정 이름은 다음과 같다. 값이나 키 내용은 로그에 기록하지 않는다.

| 설정 | 용도 |
|---|---|
| `ITDA_DAILY_GLM_REFRESH_DATABASE_URL` | 승인된 관리자 또는 `itda_daily_glm_refresh_service` 연결 |
| `ITDA_PUBLIC_PLACE_CATALOG_PATH` | 현재 PUBLIC 관광지 목록 |
| `TOUR_API_SERVICE_KEY` / `ITDA_TOUR_API_SERVICE_KEY_FILE` | 공식 관광 자료 요청 |
| `ODII_SERVICE_KEY` / `ITDA_ODII_SERVICE_KEY_FILE` | 선택적 Odii 전용 키. 없으면 공통 키 사용 |
| `ZHIPUAI_API_KEY` / `ITDA_ZHIPUAI_API_KEY_FILE` | GLM-5.3-flash 텍스트·분위기 분석 |
| `ITDA_GROUNDED_DAILY_OUTPUT_ROOT` | 날짜별 불변 입력·출력·진행 기록 |
| `ITDA_GROUNDED_DAILY_CACHE_ROOT` | 날짜 간 공유하는 공식 응답·모델 캐시 |
| `ITDA_GROUNDED_DAILY_WORKERS` | 기본 4, 최대 32. 온라인 사용량을 위한 여유 유지 |
| `ITDA_MODEL_SESSION_LIMIT` / `ITDA_MODEL_SESSION_LOCK_DIR` | 공통 모델 세션 상한(최대 40)과 프로세스 간 잠금 위치 |

여러 프로세스가 같은 키를 공유한다면 공통 모델 잠금 디렉터리도 공유해야 한다. 새 일일
분석은 semantic cache **v2**만 사용한다. 수집 시각만 바뀌고 설명 원문이 같을 때 기존 모델
응답을 재사용하며, 실제 출처·프롬프트·정책이 바뀌면 별도 분석 권한으로 처리한다.
Compose·Swarm·Portainer 템플릿은 같은 호스트의 모델 잠금 볼륨을 공유하고, 별도
`/var/lib/itda/grounded-daily` 볼륨에 날짜별 출력과 날짜 간 캐시를 보존한다.

출력은 `<output-root>/<YYYY-MM-DD>/`에 저장한다.

- `inputs.json`: 원본 릴리스와 실행 계획의 원자적·불변 묶음
- `plan.json`, `raw-release.json`: 동일 입력의 읽기용 사본
- `batch/`: sources, assessments, moods, audits, context, manifest, run 및 candidate
- `events/`: 불변 진행 기록. `state.json`은 마지막 기록을 가리키는 재생성 가능한 포인터

같은 날짜를 재개할 때 활성 릴리스가 바뀌었더라도 원래 입력을 유지한다. 상태 파일만으로
완료를 판정하지 않고 모든 배치 산출물, 후보 해시, DB 저장값을 검증한다. 원문·모델 결과는
캐시에서 재사용하며 원래 릴리스/프로필 바이트를 덮어쓰지 않는다. `--offline`은 캐시 또는
기존 날짜 산출물만 사용한다.

## 검증 후 활성화

기본 결과는 `STAGED / MEASURED_REPORTS_REQUIRED`다. 유효한 실제 보고서가 없으면 기존 활성
완전 묶음을 유지한다. 임의 해시나 `passed=true`만으로 활성화할 수 없다.

측정 도구가 만든 `GroundedPromotionGate` 파일과 세 `GroundedPromotionReport` 파일을 명시한다.
보고서는 각 `report_sha256`을 파일명으로 사용하는 `<reports>/<sha256>.json` 형식이다.

```sh
PYTHONPATH=backend/src \
  backend/.venv.nosync/bin/python -m itda.cli.run_daily_glm_refresh \
  --once --run-date 2026-09-10 \
  --gate /path/to/measured-gate.json --reports /path/to/measured-reports
```

동일 설정은 `ITDA_GROUNDED_DAILY_GATE_FILE`, `ITDA_GROUNDED_DAILY_REPORT_DIR`로 지정할 수 있다.
보고서는 정확한 후보·서버 정책에 연결된 5개 출처 비교, 동일 입력의 독립 축 대 집계 축 비교,
실제 API/UI 실행 결과를 포함해야 한다. 제약 위반·허용되지 않은 주장·재생 오류가 있으면
활성화를 거부한다. 인간 적합도나 NDCG를 가공해서 채우지 않는다.

활성 포인터는 실행 시작 시의 기준 후보와 비교하여 원자적으로 교체한다. 그사이 다른
후보가 활성화되었다면 충돌로 실패하고 새 활성 값을 보존한다. 프로세스가 활성화 직후
중단되어도 같은 게이트의 재시도는 DB 이력에 근거해 같은 완료를 반환한다. 이전 완전 후보와
검증 이력은 보존된다. 과거 후보로 되돌리는 작업도 그 후보의 실제 검증 게이트와 현재 활성
후보를 지정한 `AssessmentReleaseRepository.promote(...)` 비교·교체를 사용해야 한다.

초기 시드와 이후 일일 후보 모두 실제 측정 보고서가 완료된 뒤에만 활성화한다.
<!-- GROUNDED_DAILY_OPERATIONS_END -->
