# 공개 경험 추천 배포 준비 · 2026-09-13

기존 Swarm·Portainer와 `it-da.app` 구성을 유지한다. 이번 작업은 Linux amd64 이미지, 별도 PostgreSQL을 사용하는 로컬 HTTPS 리허설, 배포·복구 절차까지 준비한다. 운영 서버 변경, 레지스트리 업로드, 공개 DNS·인증서 변경은 실행하지 않았다. 실제 검증 결과와 파일 해시는 `artifacts/deployment/authenticity-20260913/readiness.json`에 기록한다. 이미지의 수정 가능한 취약점을 반영하고 남은 기본 OS 경고는 [별도 보안 기록](authenticity-deployment-security.md)에 보존한다.

## 배포할 내용

| 항목 | 고정값 |
|---|---|
| 공개 관광지 | PUBLIC 1,984곳 |
| 공개 릴리스 SHA-256 | `bcd012c94cfd1fb66a2edbc3c3922d2e4dfa5438d7d4a86fc9e2f0049b0c79f7` |
| 분석 정책 | A1: 공식 문서와 검토된 사진, SNS 미적용 |
| 사진 기여 | E.c·R.b에 최대 25%; H는 공식 문서 근거 |
| 사용자 사진 | 선택한 분위기만 추천에 연결; 원본 기본 미보관 |
| GLM 동시 실행 | 5개; 공유 세션 디렉터리 사용 |
| 자동 수집 | TourAPI·Odii·관광사진 신규 수집 OFF, 일일 수집 서비스 0개 |
| Apify | 배포 환경에서 실행하지 않음; 추가 지출 없음 |
| DB migration | `0032_authenticity_experience` |
| 사용자 시작 경로 | `/` → `/trip` |

기존 2,000곳과 별도 평가 60곳은 분석 자료로 보존한다. 이 둘을 공개 추천 수와 혼동하지 않는다. 사람 평가를 실시하지 않았으며 자동 규칙·AI 검토 결과를 사람의 정답률이나 만족도 검증으로 표현하지 않는다.

## 이번에 연결한 배포 경로

- API 이미지에 약 99 MiB의 검증된 `public-release/`만 포함한다. 수집 캐시·개인 사진·비밀 파일은 이미지 입력에서 제외한다.
- `migrate`가 권한 분리와 migration을 수행한 뒤 공개 패키지의 해시·범위·개수를 검사하여 원자적으로 활성화한다. 이전 `grounded_release_active`는 변경하지 않는다.
- API의 `ITDA_AUTHENTICITY_DATABASE_URL`은 제한된 runtime 계정으로 연결한다. Swarm 사진 분석은 기존 Docker secret 파일에서도 키를 읽는다.
- API healthcheck는 실제 `/v1/authenticity/info`의 PUBLIC·해시·개수·사진 설정을 검사한다. 프로세스 실행만으로 준비 완료로 판정하지 않는다.
- 운영 스크립트는 이미지 digest 고정, 수집 중단, 동시 5개를 검사하고, HTTPS에서 같은 공개 릴리스가 노출되는지 다시 확인한다.

## 로컬 리허설 재현

이번 리허설은 `docker-compose.yml`에서 별도 JSON을 생성했다. 차이는 프로젝트 이름, 로컬 이미지, amd64 지정, Caddy 내부 인증서, 루프백 HTTPS 포트뿐이다. DB·볼륨·네트워크는 기존 개발 환경과 분리했다.

```sh
docker compose \
  --env-file .secrets/itda-authenticity-deploy-check.env \
  -f artifacts/deployment/authenticity-20260913/compose.rehearsal.json up -d

python3 scripts/verify_authenticity_deployment.py \
  --origin https://localhost:3443 \
  --release-sha256 bcd012c94cfd1fb66a2edbc3c3922d2e4dfa5438d7d4a86fc9e2f0049b0c79f7 \
  --places 1984 \
  --ca-file artifacts/deployment/authenticity-20260913/rehearsal-root.crt
```

환경 파일과 합성 테스트 세션·백업은 `.secrets/` 아래 0600으로 보관한다. 운영 자격 증명으로 대체하거나 Git에 추가하지 않는다. 내부 CA는 리허설 전용이며 시스템 신뢰 저장소에 설치하지 않는다.

브라우저 검사는 `web/playwright.authenticity.config.ts`를 사용한다. 리허설 실행 환경은 다음과 같다.

```sh
ITDA_AUTHENTICITY_E2E_URL=https://localhost:3443 \
ITDA_E2E_IGNORE_HTTPS_ERRORS=1 \
ITDA_E2E_EXPECT_TIMEOUT_MS=30000 \
ITDA_E2E_ACTION_TIMEOUT_MS=60000 \
ITDA_E2E_OUTPUT_DIR=../artifacts/deployment/authenticity-20260913/browser-tests-rerun \
ITDA_UI_CAPTURE_DIR=../artifacts/deployment/authenticity-20260913/screenshots-rerun \
pnpm exec playwright test --config playwright.authenticity.config.ts
```

위 명령은 `web/`에서 실행한다. 사진 분석을 포함하므로 기존에 승인된 GLM 키가 필요하다. 사진 선택·실패 시 기존 선택 유지·삭제·분위기 확정·추천·근거·비교·저장·개인 기록·세션 삭제를 검사한다. 기록은 합성 기술 검증용이며 연구 평가에 사용하지 않는다.

Apple Silicon에서 amd64를 에뮬레이션한 최초 검사에서는 기본 5초 대기를 넘겨 4건이 실패했다. 직접 측정한 추천 생성은 약 7.9초였다. 에뮬레이션 전용 대기를 적용한 재검사 결과를 별도로 보존한다. 통상 검사의 5초 기준은 유지하며, 이 결과로 운영 서버의 p95나 동시 사용자 성능을 보장하지 않는다. 준비된 API의 메모리 관측값은 약 600 MiB이므로 512 MiB 제한을 적용하면 안 된다. 서버에서는 API에 최소 1 GiB의 여유를 확보하고 실제 부하·사진 3장 입력에서 최대 사용량을 다시 측정한다.

리허설을 중지할 때는 같은 파일로 `docker compose ... stop`을 사용한다. `down -v`는 데이터·백업을 확인한 뒤에만 사용한다.

## 운영 적용 순서

1. 기존 운영 환경 파일, 현재 backend/web image digest, Swarm revision, DB migration revision, 두 active 릴리스 포인터를 보관한다. 운영 PostgreSQL에서 `pg_dump -Fc`를 비공개 파일로 받고 별도 DB 복원까지 확인한다. 이번 복원 검사는 **로컬 리허설 DB**를 대상으로 했다.
2. 테스트한 로컬 이미지를 전용 태그로 레지스트리에 올린다. `latest`는 사용하지 않는다. 저장소에 대한 쓰기 작업이므로 실제 배포 단계에서 실행한다.

   ```sh
   docker tag itda/backend:authenticity-20260913 pengginregistry.pengbot.app/itda/backend:authenticity-20260913
   docker tag itda/web:authenticity-20260913 pengginregistry.pengbot.app/itda/web:authenticity-20260913
   docker push pengginregistry.pengbot.app/itda/backend:authenticity-20260913
   docker push pengginregistry.pengbot.app/itda/web:authenticity-20260913
   ```

3. 업로드 결과의 registry digest와 준비 기록의 이미지 manifest를 대조한다. 기존 운영 환경 파일에서 아래 비밀이 아닌 설정만 병합하고 `BACKEND_IMAGE`, `WEB_IMAGE`를 `repository@sha256:...` 형식으로 지정한다. 기존 비밀번호·세션 keyring을 새로 생성하지 않는다. `generate_deploy_env.py`는 **빈 환경을 처음 만들 때**만 사용한다.

   ```dotenv
   ITDA_AUTHENTICITY_RELEASE_SHA256=bcd012c94cfd1fb66a2edbc3c3922d2e4dfa5438d7d4a86fc9e2f0049b0c79f7
   ITDA_AUTHENTICITY_EXPECTED_PLACES=1984
   ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256=NONE
   ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT=0
   ITDA_AUTHENTICITY_PHOTO_ENABLED=1
   ITDA_MODEL_SESSION_LIMIT=5
   ITDA_TOURISM_ENABLED=0
   ITDA_OPERATING_INFORMATION_ENABLED=0
   ITDA_GROUNDED_RECOMMENDATIONS_ENABLED=0
   ITDA_GROUNDED_DAILY_ENABLED=0
   ITDA_GROUNDED_DAILY_REPLICAS=0
   ```

   `NONE`은 새 authenticity active 포인터가 아직 없다는 뜻이다. 이미 다른 authenticity 릴리스가 활성 상태라면 그 **실제 해시**를 넣는다. 동일 해시 재배포는 기존 데이터를 검증하고 그대로 유지한다. 예상과 다른 active를 임의로 덮어쓰지 않는다.

4. 기존 Swarm manager에서 `deploy/deploy-swarm-stack.sh /비공개/운영.env`를 실행한다. Python 3, Docker registry 로그인, 기존 Traefik 스택·overlay network·Docker secrets가 필요하다. `itda.data=true` 노드는 정확히 하나여야 하며 서비스는 x86_64 노드에 배치한다. Portainer를 쓸 경우 `deploy/portainer-stack.yaml`과 동일 설정을 사용하고 `ITDA_DATA_NODE_HOSTNAME`을 실제 데이터 노드 hostname으로 지정한 뒤 아래 공개 검증을 직접 실행한다.
5. `python3 scripts/verify_authenticity_deployment.py --origin https://it-da.app --release-sha256 <위 공개 해시> --places 1984`가 통과하는지 확인한다. `/trip` 브라우저 흐름, 사진 실패 시 설문 추천, runtime 권한, daily 0개, 실제 노드 메모리와 응답 시간을 확인한다. 운영 인증서에는 `--ca-file`이나 TLS 검증 우회를 사용하지 않는다.

## 중단과 복구

- PUBLIC 해시·개수·범위가 다르면 healthcheck가 실패한다. mismatch를 우회하거나 DEVELOPMENT 허용을 켜지 않는다. migration 로그와 패키지 pin을 확인한다.
- 사진 제공자 장애 시 `ITDA_AUTHENTICITY_PHOTO_ENABLED=0`으로 설문 추천을 운영할 수 있다. 공개 verifier에도 `--photo-enabled 0`을 전달한다. 다른 사용자의 사진 결과로 대체하지 않는다.
- **이미지만 롤백하면 DB active 포인터는 돌아가지 않는다.** 같은 DB 스키마와 호환되는 이전 PUBLIC 패키지 이미지, 그 패키지 해시·개수, 현재 active 해시를 준비한다. 이전 이미지의 migrate에 `PREVIOUS_RELEASE_SHA256=<현재 해시>`와 `RELEASE_SHA256=<복구할 해시>`를 전달해 활성 포인터를 돌린 후 backend/web도 해당 digest로 되돌린다. 이전 스냅샷과 사용자 run은 보존된다.
- 첫 authenticity 배포에서 이전 공개 스냅샷이 없을 때는 이전 서비스 이미지를 복구하고 수집 중단 설정을 유지한다. 새 스키마는 자동 downgrade하지 않는다. DB 전체 복원이 필요하면 쓰기를 중지하고 검증된 백업을 별도 DB에 복원한 후 연결을 전환한다.
- 수집 중단 플래그와 daily 0개는 롤백 과정에서도 유지한다. 이전 배포 환경 파일에 남아 있는 `1` 값을 그대로 되살리지 않는다.

운영 실행 전 남은 검증은 기본 OS 취약점 경고 검토, 레지스트리 업로드·digest 일치, 실제 운영 DB 백업·현재 active 확인, 대상 노드 용량, 공개 DNS·TLS, 실제 서버 응답 시간이다. 이는 로컬 배포 준비와 구분하여 운영 배포 기록에 남긴다.
