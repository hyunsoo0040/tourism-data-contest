# 진정성 버전 실행·재현·복구

기준 2026-09-13. 현재는 **로컬 PUBLIC 1,984곳 데모**이며 클라우드 배포는 수행하지 않았다. 명령은 저장소 루트 기준이다. 비밀 값은 Git 제외·권한 0600의 `.secrets/` 파일에서 읽고 출력하지 않는다.

## 현재 실행

| 구성 | 위치 |
| --- | --- |
| 웹 | http://127.0.0.1:3082/trip |
| API | http://127.0.0.1:8086/v1/authenticity/info |
| 최종 보고서 | http://127.0.0.1:8768/ |
| 공개 패키지 | artifacts/authenticity-v1/20260911/public-release |
| 최종 프론트엔드 | web/.next-authenticity-final |
| 기존 PostgreSQL | 로컬 포트 58502의 기존 컨테이너 유지 |

API의 info는 PUBLIC·1,984곳·사진 사용 가능 및 릴리스 해시 `bcd012c94cfd1fb66a2edbc3c3922d2e4dfa5438d7d4a86fc9e2f0049b0c79f7`를 반환한다. 최초 릴리스 로딩 시 info 약 8초를 관측했으며 재시작 후 데모 전에 준비 확인을 수행한다.

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python -m itda.cli.authenticity_runtime serve
PORT=3082 HOSTNAME=127.0.0.1 /Users/penggin/.local/share/mise/installs/node/24.18.0/bin/node web/.next-authenticity-final/standalone/web/server.js
backend/.venv.nosync/bin/python -m http.server 8768 --bind 127.0.0.1 --directory artifacts/authenticity-v1/20260911/final-report
```

각 서버는 별도 터미널에서 실행한다. 이미 실행 중이면 중복 실행하지 않는다. 로컬 DB와 데이터 볼륨을 새로 만들거나 제거할 필요가 없다. 웹은 API8086을 명시해 프로덕션 빌드했고 standalone 폴더에 public 및 같은 빌드의 static 자산을 복사했다.

## 패키지 검증과 활성화

전수 manifest·2,000개 분석·동결 정책·새60 평가·텍스트/픽셀 AI 검토·실제 사용 근거가 완료됐는지 확인한 뒤 공개 선택 v3를 적용한다. 미완료 입력은 패키징 단계에서 거부한다.

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python -m itda.cli.authenticity_runtime package --public --analysis artifacts/authenticity-v1/20260911/full-2000 --publication-selection artifacts/authenticity-v1/20260911/publication-selection.json --release artifacts/authenticity-v1/20260911/public-release
PYTHONPATH=backend/src backend/.venv.nosync/bin/python -m itda.cli.authenticity_runtime setup-local --release artifacts/authenticity-v1/20260911/public-release
```

최종 실행 로그는 `final-public-package.log`·`final-public-install.log`다. 설치는 admin, API는 별도의 제한된 runtime DB 역할을 사용한다. 예상 이전 해시를 대조해 authenticity 활성 포인터를 전환하며 기존 grounded 활성 포인터는 보존한다.

이전 개발120곳으로 롤백할 때는 다음을 사용한다. 최초12곳은 `development-release/`에 따로 있다.

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python -m itda.cli.authenticity_runtime setup-local --release artifacts/authenticity-v1/20260911/development-release-120
```

복원은 공개 패키지의 setup-local 명령으로 수행한다. 실제 DB에서 공개→개발→공개를 실행했고 두 버전의 저장 추천을 모두 재계산해 일치를 확인했다. 검사 자체의 세션·저장 행은 삭제했고 타 세션 읽기·삭제된 토큰은 거부됐다(`final-runtime-audit.json`). 테스트 스크립트 `verify-final-runtime.py`는 실행 중 잠시 활성 버전을 바꾸므로 시연 중에는 실행하지 않는다.

## 분석의 완료와 재개 정책

전수 워크플로는 `workflow.json`의 COMPLETE·마지막 단계 exit 0 및 실제 산출물을 확인해 종료했다. 현재 실행 중인 배치 모델 작업은 없다. 전체 2,000곳의 의미 검토는 2026-09-13 04:27 KST, 픽셀 검토는 같은 날 06:34 KST에 완료됐다.

텍스트 형식 오류 27곳은 저장 원문 23곳·허용된 추가 응답 4곳으로 처리했다. 추가 요청 예약은 실패를 포함한 5건이다. 완전한 JSON의 문자 구간만 복구하고 원 응답·값·인용·형식 경고를 유지했다. 항목별 권한·인용 거부를 없애서 통과시키지 않았다.

사진 오류 13장은 저장 응답 7장·같은 요청 추가 응답 5장을 복구하고 상품 포장 사진 1장을 제외했다. 이전 정상 관찰 2,494개의 해시는 그대로다. 완료 조건은 선택=관찰+사유를 재검증한 제외이며 미해결은 실패로 남긴다. 후속 픽셀 검토의 HTTP500 중단은 같은 요청 캐시를 확인해 재개했고 이전 검토 요약은 해시 버전으로 보존했다.

GLM은 한 호스트에서 공통 잠금을 공유해 동시 5개 이하, 전체 상한40을 지킨다. 429는 Retry-After·지수 대기·공통 대기 후 재시도한다. 다른 호스트는 같은 로컬 잠금으로 조율되지 않으므로 합계 상한을 별도로 맞춰야 한다.

공식 TourAPI/Odii/관광사진 수집은 Odii 한도 이후 중단 상태다. 날짜가 바뀌어도 자동 재수집하지 않는다. 캐시의 읽기는 새 API 요청이 아니며 누락한 자료를 채웠다고 기록하지 않는다. 완료된 워크플로를 반복 실행할 필요는 없다.

## 최종 보고서와 오프라인 확인

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python -m itda.cli.authenticity_report --final --output artifacts/authenticity-v1/20260911/final-report
PYTHONPATH=backend/src backend/.venv.nosync/bin/python artifacts/authenticity-v1/20260911/verify-final-artifacts.py
```

보고서 생성은 완료 입력을 요구한다. 생성 시각 등 표시 데이터가 바뀌면 보고서 해시도 달라질 수 있으므로 전달한 기존 폴더를 먼저 보존한다. 보고서는 HTML·JS·CSS·상세·사진·글꼴·OFL 전체가 하나의 산출물이다. 저장소 루트나 비밀 폴더를 HTTP로 제공하지 않는다.

오프라인 검사는 원본 5개·동결 코드12개·공개 패키지·선택·보고서 상세4,720개·사진2,538개·최종 wheel의 모듈과 자산을 대조한다. API 수집이나 모델 호출은 하지 않는다.

## 비용·개인정보·검사 기록

Apify는 40곳·최대120태그·누적$10에 한정한다. 실제89태그 시범의 3개 실행을 재조회해 장부를 정산한 기록은 **$0.7869**이며 유료 전수 확대는 없다. `apify-charge-audit.json`과 `instagram-pilot/budget.json`을 기준으로 삼고 이전 장부도 보존했다.

공개 배치 응답은 해시로 중복 제거한 10,454건·보고 토큰53,725,191개다(`model-usage.json`). 복사 캐시815건은 중복 집계하지 않았다. 개인 사진 API와 응답 없는 전송 시도는 제외하며 GLM 청구 금액은 제공되지 않아 추정하지 않는다. 개인 사진 브라우저 검사는 이 Apify 예산을 사용하지 않는다.

사용자 사진은 EXIF 제거·재인코딩·분석 후 원본을 저장하지 않는다. 사진 확정·교체 실패·삭제·세션 소유권과 삭제 연쇄를 검사했다. 개인 방문 기록은 연구 집계에 쓰지 않는다.

최종 로그: `final-backend-tests.log`(87개), `final-production-browser.log`(실제 사진 포함5개), `final-report-browser.log`(2개), `final-web-build.log`, `final-wheel-build.log`, `final-ruff-verdict.log`, `final-format-check.log`, `final-mypy.log`, `final-openapi-check.log`, `final-e2e-types-verdict.log`. 경로는 `artifacts/authenticity-v1/20260911/` 기준이다.

재현 가능한 기술 데모의 완료이며 사람 정답률·만족도·척도 타당성의 증거는 아니다. 전체 요구사항은 [완료 감사](authenticity-completion-audit.md)에서 확인한다.
