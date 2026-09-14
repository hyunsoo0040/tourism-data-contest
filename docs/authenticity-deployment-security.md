# 배포 이미지 검사 · 2026-09-13

검사 범위는 이번 Linux amd64 backend/web 이미지의 알려진 CRITICAL·HIGH 패키지 취약점이다. 침투 시험이나 모든 취약점의 부재를 증명하는 검사는 아니다. 결과 원문과 최종 집계는 `artifacts/deployment/authenticity-20260913/`에 보관한다.

Docker Scout는 로그인되지 않아 결과를 확보하지 못했다. 대신 [공식 Trivy 0.74.0 릴리스](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0)의 컨테이너를 digest `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`로 고정하여 로컬 image archive를 검사했다. Docker 소켓이나 비밀 환경 파일을 스캐너에 전달하지 않았다.

## 발견 후 적용한 수정

| 위치 | 최초 발견 | 수정 |
|---|---|---|
| 양쪽 OS 이미지 | PCRE2 `10.42-1`, 2개 HIGH | Debian 패치 `10.42-1+deb12u1`을 명시적으로 설치 |
| 웹 standalone | PostCSS `8.4.31`, 2개 HIGH | 기존 개발 의존성과 같은 `8.5.21`로 override·lock 고정 |
| 웹 standalone | Nano ID `3.3.16`, 1개 HIGH | `3.3.18`로 override·lock 고정 |
| 웹 기본 이미지 | npm 내부 도구의 9개 경고 | 실행에 사용하지 않는 npm·npx·Corepack을 최종 이미지에서 제거 |

Node·Python·Next·React 버전, 점수식, 공개 관광지 데이터는 유지한다. 의존성 수정 후 웹 단위 검사와 이미지 빌드, 공개 데이터·사진을 사용하는 HTTPS 브라우저 검사를 다시 수행한다. 최종 이미지 해시와 실제 검사 결과는 `readiness.json`을 기준으로 한다.

최종 재검사에서 수정 버전이 제시된 HIGH·CRITICAL 항목은 양쪽 모두 0건이고, Python·Node 앱 의존성의 HIGH·CRITICAL 항목도 0건이다. 기본 OS에는 backend 60건(고유 CVE 21개: 발생 건수 기준 CRITICAL 5·HIGH 55), web 56건(고유 CVE 18개: CRITICAL 4·HIGH 52)이 남았다. 서로 중복된 CVE가 있으므로 두 이미지의 수를 합쳐 고유 취약점 수로 표현하지 않는다. 이는 전체 심각도 검사를 통과했다는 뜻이 아니다.

## 기본 OS에 남는 경고의 해석

스캐너 원문에서 경고를 삭제하거나 일괄 예외 처리하지 않았다. 같은 소스 패키지의 CVE가 여러 바이너리 패키지에 반복될 수 있으므로 패키지-CVE 발생 건수와 고유 CVE 수를 함께 기록한다. 수정 버전 필드가 빈 항목을 모든 배포판에서 수정 불가능하다는 뜻으로 해석하지 않는다.

- `CVE-2023-45853`은 MiniZip 관련 경고다. Debian은 bookworm의 해당 zlib 소스에서 문제의 MiniZip 바이너리를 만들지 않는다는 이유를 명시한다. 스캐너가 zlib1g에 붙인 경고와 실제 취약 바이너리 포함 여부를 구분한다. [Debian 기록](https://security-tracker.debian.org/tracker/CVE-2023-45853)
- SQLite의 `CVE-2025-7458`은 공격자가 임의 SQL을 실행하는 상황을 전제로 하며 Debian은 bookworm에 별도 보안 공지를 내지 않는 사소한 문제로 분류한다. IT-DA API는 PostgreSQL 연결만 허용한다. 이는 현재 노출 경로를 설명하는 근거이며, 포함된 SQLite 라이브러리 자체가 패치됐다는 뜻은 아니다. [Debian 기록](https://security-tracker.debian.org/tracker/CVE-2025-7458), `backend/src/itda/db/session.py`
- Perl `Archive::Tar`의 `CVE-2026-42496`은 공격자가 조작한 archive를 Perl로 풀 때의 문제다. Debian은 bookworm 대응을 유예하고 있다. 현재 공개 사용자 흐름은 JPEG·PNG·WebP를 Pillow로 처리한다. Perl 기반 archive 입력 경로가 확인되지 않았다는 것과 전체 이미지가 무위험하다는 주장은 다르다. [Debian 기록](https://security-tracker.debian.org/tracker/CVE-2026-42496)
- Perl 정규식의 `CVE-2026-13221`도 bookworm의 경고가 남아 있다. 현재 서비스는 Python·Node로 실행하지만 이를 이유로 자동 예외를 만들지 않는다. [Debian 기록](https://security-tracker.debian.org/tracker/CVE-2026-13221)
- util-linux·mount·systemd·ncurses 등 나머지 경고는 원문에 보존한다. backend/web은 UID 10001로 실행하고 운영 API에 DB 관리자 권한을 주지 않는다. 이러한 제한은 대응 근거 중 일부이며 모든 로컬 권한 상승이나 후속 공격을 배제하지 않는다.

공개 운영 전 남은 OS 경고에 대해 대상 서버의 권한·mount·노출 경로를 확인하고, 지원되는 기본 이미지의 후속 보안 패치를 반영해야 한다. 이번 기록은 남은 경고를 승인한 보안 예외 문서가 아니다. 패키지 수정이 제공된 항목과 서비스 의존성의 재검사 결과를 별도로 확인한다.

## 재검사

```sh
docker save -o /비공개또는로컬경로/backend.tar itda/backend:authenticity-20260913
docker run --rm \
  -v /비공개또는로컬경로:/scan \
  -v itda-authenticity-trivy-cache-20260913:/root/.cache/trivy \
  aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 \
  image --input /scan/backend.tar --scanners vuln --severity CRITICAL,HIGH \
  --format json --output /scan/backend-vulnerabilities.json --exit-code 2
```

web에도 같은 방식으로 실행한다. `--ignore-unfixed`를 사용하지 않으며 exit code 2는 발견 항목이 있다는 뜻이다. 취약점 DB 갱신 시 결과가 달라질 수 있으므로 실행 시각·이미지 digest·검사 결과를 함께 보관한다.
