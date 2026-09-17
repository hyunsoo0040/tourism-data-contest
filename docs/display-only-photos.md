# 공식 장소 사진의 화면 표시 · 2026-09-17

사진 표시와 사진 분석 권한을 분리한다. 사용자는 광고·유료 기능·상업 홍보 없는 공모전·시연용 운영임을 확인했다.

- `public-release/display-photos.json`은 기존 수집 응답에서 추출한 화면 표시 전용 목록이다. 새 수집·이미지 다운로드·모델 호출 없이 생성한다.
- TourAPI content ID와 장소 연결, 응답 원문 SHA-256, 사진별 명시적 공공누리 유형을 확인한다. 대표 이미지(`firstimage`)를 먼저, `detailImage2`의 추가 사진을 뒤에 배치한다. URL 중복은 제거한다. 기존 관광사진갤러리 사진은 후순위로 유지한다.
- 제0~4유형을 지원한다. 권한 불명·다른 장소·공식 이미지 도메인이 아닌 항목은 포함하지 않는다. 현재 데이터에 실제 포함된 유형은 제1·3유형이다.
- `ITDA_DISPLAY_PHOTO_NONCOMMERCIAL=1`이면 제2·4유형도 표시한다. 사용자가 확인한 공모전 환경에 맞춰 Docker 이미지와 Portainer/Compose 기본값을 1로 설정한다. 상업적 운영으로 바꾸면 0으로 설정하며 제0·1·3유형만 표시한다.
- 제3·4유형은 원본 URL을 사용하고 큰 사진·썸네일 모두 `object-fit: contain`으로 표시한다. 잘라내기·필터·변환 파일을 만들지 않으며 워터마크를 유지한다. 출처, 원본 링크와 한국어 이용 조건을 함께 제공한다.
- 이 목록은 `Service.detail()`의 사진 응답에만 합쳐진다. 기존 `auxiliary.json`의 분석용 moods/photos, assessment, H/E/R 점수, 추천식과 릴리스 SHA-256은 수정하지 않는다. 화면 사진 전체를 분석 근거로 취급하지 않는다.
- 릴리스 해시가 다른 과거 추천에는 새 표시 목록을 합치지 않는다. 목록이 없는 기존 패키지는 기존 분석용 사진 표시로 호환된다. 배포 사전검사에서는 목록 해시와 릴리스 소속을 확인한다.

재생성:

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python scripts/export_display_photos.py \
  --release artifacts/authenticity-v1/20260911/public-release
```

별도 DB 마이그레이션이나 분석 재실행은 필요 없다. 배포하려면 표시 목록이 포함된 backend 이미지와 새 사진 표시 컴포넌트가 포함된 web 이미지를 함께 갱신한다.

공식 조건: [제1유형](https://www.kogl.or.kr/info/licenseType1.do), [제2유형](https://www.kogl.or.kr/info/licenseType2.do), [제3유형](https://www.kogl.or.kr/info/licenseType3.do), [제4유형](https://www.kogl.or.kr/info/licenseType4.do).
