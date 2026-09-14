# 전국 데이터용 로컬 API 시작 경로

2026-09-10 현재, 별도 로컬 PostgreSQL의 생성과 마이그레이션을 완료했다. 아직 전국 자료의 staging·활성화나 API 실행은 수행하지 않았다. 최종 목표인 새 공식 여행지 800~1,000곳 수집·분석을 소량 진단 결과나 합성 테스트로 대체하지 않는다.

현재 작업 소유의 Compose 프로젝트·DB는 `itda_national_20260910`, 주소는 `127.0.0.1:58502`, 스키마는 `0031_national_grounded_catalog`다. 활성 자료는 0개이며 이전 장소 자료를 넣지 않았다. 비공개 접속 설정은 `.secrets/national-local/database.json`에 보관한다. 공개 실행 결과는 `artifacts/national/20260909/verification/local-database.json`에 기록했다.

## 새 후보 검증과 묶음 생성

최종 선정 파일로 `catalog.json`·`evidence.json`·`relations.json`을 만든 뒤 전체 분석을 실행한다.
실제 새 후보의 API 검사는 `test_national_real_candidate.py`에
`ITDA_NATIONAL_VERIFY_CANDIDATE`와 `ITDA_NATIONAL_VERIFY_CATALOG`를 지정한다.
이 검사는 격리 PostgreSQL과 실제 FastAPI 경로를 사용하지만 사용자 답변은 작성된 입력이고,
사진은 합성 UNKNOWN 공급자를 이용한다. 결과는 인간 평가가 아니다.

검사가 만든 `verification/api/candidate-api-fixture.json`으로
`source-grounded-recommendation.spec.ts`를 실행할 때
`ITDA_GROUNDED_E2E_FIXTURE`에 해당 파일, `ITDA_GROUNDED_E2E_ARTIFACT_DIR`에
`verification/replay/`를 지정한다. Playwright JSON 보고서도 그 폴더에 저장한다.
이 브라우저 단계는 검증된 API 응답의 재생이며 정상 서버의 실제 브라우저 검사와 구분한다.

`evaluation/`의 볼거리 전용 DEV 출처·축 비교, 실제 API·PG 확인, 두 화면의 응답 재생
검사가 모두 통과하면 아래 생성기가 해시·후보·설정·현재 프런트엔드·전체 표본·검사 실행을
대조하고 `release/`에 검토 가능한 묶음을 만든다. 이 명령 자체는 ACTIVE나 current 경로를
변경하지 않는다.

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python \
  artifacts/national/20260909/verification/prepare_promotion.py
```

그 후 아래 순서로 로컬 후보를 활성화하고 `national-live-preview.spec.ts`에서 정상 API·DB와
모바일/데스크톱의 실제 설문→추천→상세·비교·저장·재생을 확인한다.
현재 해당 최종 자료 검증·묶음 생성·활성화는 아직 실행하지 않았다.

## 최소 시작 순서

1. 기존 서버와 분리된, 이 작업 소유의 PostgreSQL 17 Compose 프로젝트와 DB를 생성한다. `infra/compose.yaml`의 `COMPOSE_PROJECT_NAME`, `ITDA_POSTGRES_DB`, `ITDA_POSTGRES_PORT`, 관리 계정·비밀번호를 새로 설정한다. 여러 고정 서비스 역할이 있으므로 같은 PostgreSQL 클러스터에서 다른 실행기의 비밀번호를 재설정하지 않는다.
2. `itda.cli.deploy_database.DeploymentDatabaseSettings`를 만들고 `provision_roles(settings)`와 `upgrade_schema(settings)`만 호출한다. head는 `0031_national_grounded_catalog`이다. 이 두 함수는 데이터·평가 fixture를 넣지 않는다.
3. 실제 새 `GroundedReleaseCandidate`와 그 후보에 결합된 gate·3개 보고서를 검증하고, 관리자 또는 `itda_daily_glm_refresh_service` 연결로 `AssessmentReleaseRepository.stage`, `store_report`, `promote`를 호출한다. `promote`의 `expected_active_sha256`는 현재 읽은 ACTIVE 후보 SHA이며 새 DB라면 `None`이다. 호출 후 `load_active_record()`를 읽어 후보·gate·generation을 대조한다.
4. API 자식 프로세스에는 runtime·session·필요한 photo 연결만 전달한다. 관리자 DSN과 candidate stage용 서비스 비밀번호는 부모 실행기에 둔다. `backend/.venv.nosync/bin/python -m uvicorn itda.api.main:app --host 127.0.0.1 --port 8000`으로 시작한다. 이 정상 `main:app` 진입점에는 데이터 seed가 없다.
5. 프런트엔드는 `ITDA_BACKEND_ORIGIN=http://127.0.0.1:8000`을 시작 시 전달한다. `web/next.config.ts`가 `/v1/*`를 해당 백엔드에 rewrite하므로 브라우저는 `http://127.0.0.1:5173`만 이용한다. 별도 CORS 우회가 필요 없다.

`e2e_runtime.py`는 새 실행기의 필수 진입점이 아니다. 이 파일의 `start_api()`는 옛 Phase 3 평가 권한·manifest 경로와 E2E 지원 플래그를 추가하고, `bootstrap_grounded_preview()`는 항상 외부 통신을 차단한다. 새 전국 로컬 실행기는 위의 일반 DB·API 경로를 쓰면 이 의존성을 가져오지 않는다.

## 비공개 환경값과 역할

`DeploymentDatabaseSettings`의 필수 값은 `admin_dsn`, `database_name`, `runtime_role`, `builder_role`, `approver_role`, `login_passwords`이다. `login_passwords`에는 runtime/builder/approver와 다음 네 서비스의 독립 난수 비밀번호가 필요하다.

- `itda_profile_release_authority_service`
- `itda_photo_service`
- `itda_current_profile_session_service`
- `itda_daily_glm_refresh_service`

`provision_roles`는 이에 대응하는 네 NOLOGIN 소유자 역할도 만든다. runtime·service는 `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, `NOBYPASSRLS`, `NOINHERIT`이며 관리 역할 간 membership은 허용하지 않는다. 옛 라벨·장소 자료를 넣을 필요는 없지만 전체 마이그레이션의 권한 계약을 위해 builder/approver 역할은 존재해야 한다.

API 자식 환경:

| 변수 | 값의 의미 |
|---|---|
| `PYTHONPATH` | 저장소의 `backend/src` 절대 경로 |
| `ITDA_DATABASE_URL` | 새 DB의 제한된 runtime 역할 DSN |
| `ITDA_RUNTIME_ROLE` | 해당 runtime 역할명 |
| `ITDA_PROFILE_SESSION_DATABASE_URL` | 같은 DB의 `itda_current_profile_session_service` DSN |
| `ITDA_PROFILE_SESSION_CURRENT_KID` | 1~24자 `[A-Za-z0-9_-]` 키 ID, 예: `national-local` |
| `ITDA_PROFILE_SESSION_KEYRING` | `kid.base64url(32바이트 난수키)` 형식. 현재 키 1개면 충분하고 최대 2개 지원 |
| `ITDA_CANONICAL_APP_ORIGIN` | `http://127.0.0.1:5173` — 끝 `/` 없이 정확히 일치 |
| `ITDA_E2E_ALLOW_INSECURE_COOKIE` | 로컬 HTTP 실행에서 `1` |
| `ITDA_API_BIND_HOST` | `127.0.0.1` |
| `ITDA_PUBLIC_PLACE_CATALOG_PATH` | 실제 새 전국 catalog JSON의 절대 경로 |
| `ITDA_GROUNDED_RECOMMENDATIONS_ENABLED` | `1` |
| `ITDA_SOURCE_GROUNDING_ENABLED` | `0` 또는 미설정. 현재 v5는 `ProductionTourismRegistry`를 사용 |
| `ITDA_OPERATING_INFORMATION_ENABLED` | 별도 오래된 운영정보 수집기가 필요 없으면 `0`; v5의 공식 조건·관광정보 경로와 별개 |

키를 만들 때는 `base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')`를 사용한다. 환경/DSN/서명키 전체를 로그나 보고서에 쓰지 않는다. 비공개 파일에 보존하는 실행기라면 부모 디렉터리 `0700`, 파일 `0600`을 사용하고 필요한 키만 자식 환경에 복사한다.

사진 흐름까지 연결하려면 추가로 `ITDA_PHOTO_SERVICE_DATABASE_URL`, `ITDA_PHOTO_QUARANTINE_ROOT`(새 비공개 디렉터리), `ITDA_LABEL_BUILDER_ROLE`, `ITDA_PHOTO_MOOD_ENABLED=1`, 승인된 `ITDA_PHOTO_VLM_API_KEY_FILE` 또는 `ITDA_ZHIPUAI_API_KEY_FILE`을 전달한다. 실제 사진 모델은 `glm-5.3-flash`이며 수집 배치와 합쳐 40개 동시 세션 이내여야 한다. 키 미설정 상태도 사진을 건너뛴 설문 추천은 가능하다.

실제 추가 관광 API를 허용할 때만 `ITDA_TOURISM_ENABLED=1`과 승인된 API별 키를 전달하고 `ITDA_NO_NETWORK`를 해제한다. 한도 소진된 KorService2를 다시 호출하도록 전체 env를 무차별 전달하지 않는다. 관광정보 없이 검증할 때는 `ITDA_TOURISM_ENABLED=0`; 미확인 정보는 UI에서 숨겨진다.

쿠키 이름은 `itda_current_profile`, HttpOnly, SameSite=Strict, Path=/, 유효기간 30분이다. HTTP용 Secure 해제는 bind 주소와 실제 peer가 loopback이고 origin이 정확한 `http://127.0.0.1:<port>`인 경우에만 작동한다. 프로필·사진 변경 요청은 `Origin`이 canonical origin과 같아야 하고, `Sec-Fetch-Site`가 있으면 `same-origin`이어야 한다. 정상 브라우저 rewrite 경로를 이용하면 이 조건을 충족한다. E2E 평가 지원·평가 capability 환경은 필요 없다.

## 이전 자료를 다시 가져오는 경로

| 위치 | 전환 시 처리 |
|---|---|
| `app.grounded_release_active` | 실제 새 candidate/gate로 CAS 승격한 뒤 읽기 검증. 일반 신규 추천의 권위 있는 포인터 |
| `artifacts/national/current/{catalog.json,candidate.json,gate.json,reports/,package.json}` | 현재 기본 배포 자료. 파일이 없으면 초기화 실패하며 이전 경주 경로로 돌아가지 않음 |
| `ITDA_GROUNDED_INITIAL_CANDIDATE_FILE`, `ITDA_GROUNDED_INITIAL_GATE_FILE`, `ITDA_GROUNDED_INITIAL_REPORT_DIR` | 초기화 함수를 쓸 때 모두 명시. 미설정이면 위 기본 bootstrap을 읽음 |
| `artifacts/national/current/catalog.json` | 정상 API·운영정보·일일 작업의 기본 catalog. source-only ACTIVE의 catalog/evidence/member hash와 일치해야 함 |
| `artifacts/national/current/relations.json`, `evidence.json` | 새 catalog와 hash가 맞는 관계·공개 근거 파일. 명시 환경 경로도 지원 |
| `artifacts/public/catalog/mvp-scored-releases/active.json` | 옛 MVP 파일 포인터. 정상 API와 전국 일일 작업에서는 resolver 연결을 제거했고, 운영 포인터는 폐기 대상 |
| `dev_eval.daily_scored_release_active` | 옛 daily overlay 포인터. 신규 독립 DB에서는 빈 상태로 유지 가능 |
| `artifacts/national/daily/runs`와 `cache` | CLI의 새 output/cache 기본 경로. 배포에서는 별도 national 하위 volume 경로 사용 |

`ensure_initial_grounded_release()`는 검증된 전국 source-only ACTIVE만 `retained`로 인정한다. 경주 ACTIVE가 남아 있으면 성공 상태를 반환하지 않는다. 기존 DB를 유지하며 교체한다면 `store.promote(new_gate, expected_active_sha256=old_sha)`를 명시적으로 실행해야 한다.

`_recommendation_service_for_dsn()`은 오래된 `RecommendationService`도 고정 영수증 읽기 호환용으로 생성하지만 그 ACTIVE resolver는 항상 None이다. 신규 요청은 현재 전국 catalog와 일치하는 source-only ACTIVE만 사용한다. catalog 파일이 없거나 경주 catalog이면 DB 연결 전에 503, ACTIVE가 없거나 예전 자료이면 신규 추천도 503으로 끝난다. `ITDA_GROUNDED_CANDIDATE_SHA256`는 서비스 시작 시 거부되므로 staged 후보를 임의 활성 후보처럼 쓰는 override로 사용하지 않는다.

일일 grounded 작업은 현재 전국 catalog와 일치하는 source-only ACTIVE만 사용한다. ACTIVE가 없거나 예전 자료이면 raw resolver는 None을 반환하고 배치를 시작하지 않는다. 이전 MVP 파일이나 overlay를 초기 자료로 사용하지 않는다. API 서버 자체가 이 scheduler를 실행하지는 않는다.

현재 `dependencies._source_grounding_service()`의 오래된 opt-in 경로는 CanonicalTourismPlace에 공식 지역 코드를 전달하지 않는다. 전국 v5는 이 경로를 쓰지 않으므로 해당 플래그를 켜지 않는다. 추후 이 오래된 기능을 다시 사용할 계획이라면 별도 지역 전달 수정이 필요하다.

## 크기·DB·정리 범위

실제 새 1,000곳 candidate 파일이 나온 후 크기를 확인한다. `initialize_grounded_release.py`와 `grounded_preview_bootstrap.py`의 읽기 제한은 candidate 64 MiB, 개별 report 32 MiB, gate 1 MiB다. 지금은 이 상한을 변경하지 않았다. 필요 여부는 실제 파일 크기를 근거로 판단한다.

`0030`/`0031`의 SQL staging 함수, `AssessmentReleaseRepository`, `GroundedRunRepository`에서는 `p::text` 길이·`octet_length`·`pg_column_size`에 의한 별도 바이트 상한을 찾지 못했다. SQL은 source-only 프로필 1~1,000개와 전체 멤버·hash·출처 연결을 검증한다. 운영 목표 800~1,000개 여부는 수집·품질 검증에서 별도로 확인해야 한다.

실제 PG 테스트 `backend/tests/integration/test_national_grounded_migration.py`는 격리 DB에서 합성 1,000개 staging/read, 빈 DB 및 기존 DB의 head 업그레이드, runtime 쓰기 거부, 기존 80개 계약 유지, 틀린 전체 멤버 거부를 확인했다(53.52초, 1 passed). 테스트 fixture는 종료 시 DB/Compose를 정리하므로 완료된 테스트 클러스터를 살아 있는 서버로 재사용할 수 없다. 같은 역할·마이그레이션 생성 방식을 새 실행기에 재사용할 수 있으며 합성 candidate 생성 함수를 실제 데이터 초기화에 사용하면 안 된다.

immutable candidate/report/promotion/snapshot에는 일반 UPDATE/DELETE가 막혀 있다. 서비스 또는 runtime 권한을 넓혀 이를 지우는 경로를 만들지 않는다. 완전히 버릴 작업 소유의 로컬 DB라면 부모 관리자 연결에서 **정확한 database_name**에 해당하는 연결만 종료하고 해당 DB만 DROP한다. 역할과 Compose volume 정리는 해당 실행기가 독점 소유한 별도 클러스터에서만 수행한다. 공유 클러스터의 고정 역할을 DROP하거나 비밀번호를 바꾸면 다른 DB의 실행기를 손상시킬 수 있다.
