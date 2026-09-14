# Portainer 이미지 교체 호환성 수정 · 2026-09-14

기존 Portainer 스택에서 이미지만 교체한 뒤 `/v1/authenticity/info`가 503을 반환하고 `migrate`가 `Deployment database setup failed.`로 종료되는 문제를 수정한다. `/definition`은 DB를 사용하지 않으므로 같은 상황에서도 200을 반환할 수 있다.

## 원인과 수정

이전 스택의 backend 명령은 runtime 계정의 `ITDA_DATABASE_URL`만 설정한다. 새 authenticity API는 별도 `ITDA_AUTHENTICITY_DATABASE_URL`을 요구했으므로 기존 연결을 사용하지 못했다. 이제 별도 변수가 없으면 기존 runtime 연결을 사용한다. 별도 변수를 명시하면 그 값이 우선하며, 명시적인 빈 값은 계속 준비 실패로 처리한다.

이전 스택의 migrate에는 authenticity 릴리스 설정도 없었다. 이 경우 초기화 CLI가 기존 grounded 경로를 선택하지만 새 이미지에는 PUBLIC authenticity 패키지만 들어 있다. 따라서 새 API 자료를 활성화하지 못하거나 기존 grounded 패키지 조회에서 실패할 수 있었다.

수정한 backend 이미지에는 포함된 패키지와 일치하는 다음 기본값을 넣는다. 기존 스택의 migrate 명령을 그대로 실행해도 PUBLIC 초기화 경로를 선택한다.

| 환경 변수 | 이미지 기본값 |
|---|---|
| `ITDA_AUTHENTICITY_RELEASE_DIR` | `/app/artifacts/authenticity/current` |
| `ITDA_AUTHENTICITY_RELEASE_SHA256` | `bcd012c94cfd1fb66a2edbc3c3922d2e4dfa5438d7d4a86fc9e2f0049b0c79f7` |
| `ITDA_AUTHENTICITY_EXPECTED_PLACES` | `1984` |
| `ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT` | `0` |
| `ITDA_AUTHENTICITY_PHOTO_ENABLED` | `1` |

기존 스택에서 명시한 환경 값은 이미지 기본값보다 우선한다. 명시적으로 빈 릴리스 경로를 지정하면 기존 초기화 경로가 선택되므로, PUBLIC 이미지에서는 경로를 비우지 않는다. 이후 공개 패키지를 교체할 때 Dockerfile의 해시·개수도 함께 갱신하고 실제 이미지에서 검증해야 한다.

오류 로그에는 이제 `configuration`, `roles`, `schema`, `public_release`, `legacy_release` 단계와 제한된 오류 코드가 표시된다. DB 오류는 가능한 경우 SQLSTATE도 표시한다. 비밀번호·DSN·SQL·관광지 원문·원시 예외 메시지는 출력하지 않는다.

## 기존 스택에 적용

2026-09-14 사용자가 요청한 태그 `latest`를 유지한다. 이번 수정은 backend 이미지에만 해당한다.

1. Portainer에서 `migrate`와 `backend`가 모두 `pengginregistry.pengbot.app/itda/backend:latest`를 사용하도록 확인한다. `latest`는 같은 이름이어도 실행 중인 서비스가 자동 갱신되지 않으므로 새 이미지 받기를 선택하여 서비스를 다시 배포한다. 기존 스택 YAML, DB 볼륨, 비밀번호, 세션 keyring은 유지한다.
2. 먼저 migrate가 새 이미지로 다시 실행되어 정상 종료하는지 확인한다. 정상 로그는 `Authenticity PUBLIC release is ready (activated, 1984 places, ...)`이다. 같은 릴리스를 재실행하면 `retained`가 표시된다. 이후 backend도 새 이미지로 다시 배포한다.
3. `https://it-da.app/v1/authenticity/info`에서 200, `scope=PUBLIC`, `places=1984`, 위 해시를 확인한다. `/trip`에서 설문과 추천 결과를 확인한다.

동일 공개 릴리스는 재설치하지 않고 저장 내용을 검증한다. 다른 authenticity 릴리스가 이미 활성화되어 있으면 예상 이전 해시를 확인하기 전까지 교체를 거부한다. 기존 grounded 활성 포인터와 사용자 데이터는 보존한다. 이번 장애 복구를 위해 DB 초기화나 migration downgrade를 실행할 필요는 없다.

사진 기능은 기존 제공자 키 설정을 사용한다. 이 배포 검증에서는 외부 사진 모델·관광 API·Apify를 호출하지 않는다.

## 검증 기록

회귀 테스트는 기존 DSN 재사용·명시적 설정 우선순위·오류 단계·민감 정보 미출력·SQLSTATE·릴리스 pin 충돌을 검사한다. 별도 PostgreSQL에서 공개 패키지 활성화, 재실행, 잘못된 pin 거부, 기존 데이터 보존과 API 응답을 검사한다. 이미지 및 배포 검증 결과는 `artifacts/deployment/portainer-migration-20260914/`에 보관한다. 이는 자동 기술 검증이며 사람 평가 결과가 아니다.
