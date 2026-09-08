# IT-DA six-place PREVIEW review

Status: PREVIEW / NOT_SCORED

| # | 장소 | 주소 | 좌표 | TourAPI ID | Odii request pair (tid/tlid) | Canonical Odii theme pair (tid/tlid) | 권리 상태 | 해소 상태 |
|---:|---|---|---|---|---|---|---|---|
| 1 | 불국사 | 경상북도 경주시 불국로 385 (진현동) | 129.331725, 35.792302 | 126166 | 2/5 | 2/5 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |
| 2 | 석굴암 | 경상북도 경주시 석굴로 238 (진현동) | 129.350472, 35.795241 | 126216 | 2983/4639 | 2983/4639 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |
| 3 | 첨성대 | 경상북도 경주시 첨성로 140-25 | 129.218535, 35.834330 | 126207 | 2967/4623 | 2967/4623 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |
| 4 | 동궁과 월지 | 경상북도 경주시 원화로 102 | 129.228375, 35.835202 | 128526 | 2961/4617 | 2961/4617 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |
| 5 | 대릉원 일원 | 경상북도 경주시 황남동 | 129.212800, 35.838200 | 1492402 | 2960/4616 | 2960/4616 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |
| 6 | 황리단길 | 경상북도 경주시 포석로 1080 (황남동) | 129.209954, 35.837408 | 2658227 | 1312/2357 | 1312/2357 | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW | RESOLVED |

The provider table below preserves the conservative capture-time state. The reviewed disposition table is authoritative for candidate and asset use.

## Reviewed rights disposition

| 장소 | Selected Odii theme (tid/tlid) | Selected Odii story (stid/stlid) | 선택 story 제목 | TourAPI metadata/text | Odii voice/script/photo | 대표 이미지 | Type1 detail images | 최종 상태 |
|---|---|---|---|---|---|---|---:|---|
| 불국사 | 2/5 | 5499/16497 | 경주 불국사 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type1 USABLE_WITH_ATTRIBUTION | 10 | USABLE_WITH_RESTRICTIONS |
| 석굴암 | 2983/4639 | 5348/16346 | 경주 석굴암 석굴 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type1 USABLE_WITH_ATTRIBUTION | 4 | USABLE_WITH_RESTRICTIONS |
| 첨성대 | 2967/4623 | 5288/16286 | 경주 첨성대 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type1 USABLE_WITH_ATTRIBUTION | 10 | USABLE_WITH_RESTRICTIONS |
| 동궁과 월지 | 2961/4617 | 5278/16276 | 동궁과 월지 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type3 ORIGINAL_DISPLAY_ONLY (no transform/model/normalized asset) | 6 | USABLE_WITH_RESTRICTIONS |
| 대릉원 일원 | 2960/4616 | 5272/16270 | 경주 대릉원 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type1 USABLE_WITH_ATTRIBUTION | 10 | USABLE_WITH_RESTRICTIONS |
| 황리단길 | 1312/2357 | 2933/6824 | 경주 황리단길 | OFFICIAL_DATASET_GRANT | Type0 inherited dataset grant | Type1 USABLE_WITH_ATTRIBUTION | 9 | USABLE_WITH_RESTRICTIONS |

Policy v2 pins each selected Odii story by tid/tlid/stid/stlid/title and its bound response SHA-256. The candidate JSON, external source lock, and provider provenance retain that binding.

Same-theme sibling storyBasedList rows are evidence only and never affect selected-story rights.

searchKeyword2 alternatives are discovery evidence only; their image-right markers are not aggregated into the locked selected candidate.

modifiedtime=UNRESOLVED remains a freshness gap, not a license blocker. Provider, dataset ID, source IDs, retrieved_at, and response SHA-256 are retained.

## Provider response provenance

| 장소 ID | provider | endpoint | source ID | request scope | retrieved UTC | HTTP | response SHA-256 | modifiedtime | rights | asset state |
|---|---|---|---|---|---|---:|---|---|---|---|
| preview:1 | TOUR_API | KorService2/searchKeyword2 | 126166 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"불국사"} | 2026-07-23T17:06:50.723211Z | 200 | 15a38bd27a369dbd2102d33750e11d910f35a85b1327f0e14df02ad1c5b750c9 | 20260619154954 | [{"cpyrhtDivCd":"Type1"},{"cpyrhtDivCd":"Type3"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:1 | ODII | Odii/themeSearchList | 2/5 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"불국사","langCode":"ko"} | 2026-07-23T17:06:51.728902Z | 200 | a3a51fa79ca0820d1d2056787c242b7fd9ce936ec75fc79ddbc82cefe9e813d1 | 20250609183759 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:1 | TOUR_API | KorService2/detailCommon2 | 126166 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126166"} | 2026-07-23T17:06:52.322727Z | 200 | 216e06ddf15d980da69d792cd499afbd3855b19b62e8d5d38cc372076cac56e5 | 20260619154954 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:1 | TOUR_API | KorService2/detailImage2 | 126166 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126166"} | 2026-07-23T17:06:52.753235Z | 200 | b6c34679c0040c46a43fd6be992fb620bffbb162e8a29000c4a820a563e5658e | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:1 | ODII | Odii/storyBasedList | 2/5 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"2","tlid":"5"} | 2026-07-23T17:06:54.971816Z | 200 | ec004af611a76f8f501e73c213cb6a3e8941864ddb0ff372e9e14dd2df7f55d5 | 20250609151804 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:2 | TOUR_API | KorService2/searchKeyword2 | 126216 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"석굴암"} | 2026-07-23T17:06:56.515862Z | 200 | 29d58164a9c0a66dca5c676d4a10d7c9be1f53b1b0cf001db543879d5d6b7ab0 | 20260707100638 | [{"cpyrhtDivCd":"Type1"},{"cpyrhtDivCd":"Type3"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:2 | ODII | Odii/themeSearchList | 2983/4639 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"석굴암","langCode":"ko"} | 2026-07-23T17:06:58.078816Z | 200 | 310ddbb447f2acfe9576596c9c2bda6105c7e291ba55b05b59bfd66f331fe149 | 20250609184548 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:2 | TOUR_API | KorService2/detailCommon2 | 126216 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126216"} | 2026-07-23T17:06:58.182562Z | 200 | 5ba6db40d1f81b5847249605addf4e9f4086fdab8dbc5fb9c551567b6cf659d3 | 20260707100638 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:2 | TOUR_API | KorService2/detailImage2 | 126216 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126216"} | 2026-07-23T17:06:59.206179Z | 200 | 35dfa718d95057a353e03deec4e29be7c95ec59135f644128763b25ce138220e | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:2 | ODII | Odii/storyBasedList | 2983/4639 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"2983","tlid":"4639"} | 2026-07-23T17:06:59.278277Z | 200 | 5d51469196a63d02f698ef9fec7a885bef30e4518cc5eea33d4b15bcb41539e3 | 20250609160446 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:3 | TOUR_API | KorService2/searchKeyword2 | 126207 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"첨성대"} | 2026-07-23T17:07:00.536844Z | 200 | 181b5c8974ad287f754da4b107c98b4dcdc77b82f2d8d17aefbd4a1fdc4bbff4 | 20260519183359 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:3 | ODII | Odii/themeSearchList | 2967/4623 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"첨성대","langCode":"ko"} | 2026-07-23T17:07:01.046435Z | 200 | d06b058808b6eadcacade148d6778a6f27a435d337915269ad4cae5b87e66584 | 20231027111417 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:3 | TOUR_API | KorService2/detailCommon2 | 126207 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126207"} | 2026-07-23T17:07:05.736976Z | 200 | b5c10ccbb9f6a195e59fc18f1465e88e053600de717996d219da15cd5b66fe3f | 20260519183359 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:3 | TOUR_API | KorService2/detailImage2 | 126207 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"126207"} | 2026-07-23T17:07:09.343494Z | 200 | 4c903617d055c3de82cd143886acd9c33fcc4f556d24a49b88cde139dc6203a9 | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:3 | ODII | Odii/storyBasedList | 2967/4623 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"2967","tlid":"4623"} | 2026-07-23T17:07:10.780498Z | 200 | 5cd569e938696ec8914a5afabc74cff09be0a795211e7737670112aa7667c477 | 20230720110647 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:4 | TOUR_API | KorService2/searchKeyword2 | 128526 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"동궁과 월지"} | 2026-07-23T17:07:12.212731Z | 200 | 8edc36c731c8f86f0392a3db16d7b91613febd665f28927a9e155235612218ec | 20251202172402 | [{"cpyrhtDivCd":"Type3"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:4 | ODII | Odii/themeSearchList | 2961/4617 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"동궁과 월지","langCode":"ko"} | 2026-07-23T17:07:13.745407Z | 200 | 75177af2f7583bbdc11dada2cf8845025f1f9bef8e47d0e87ce3d4b43f4f5684 | 20250609184818 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:4 | TOUR_API | KorService2/detailCommon2 | 128526 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"128526"} | 2026-07-23T17:07:13.831202Z | 200 | 5f1fa72d414f46aaa004207fc15dfaec6cc63027d34d37a75e27657cb0900a1b | 20251202172402 | [{"cpyrhtDivCd":"Type3"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:4 | TOUR_API | KorService2/detailImage2 | 128526 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"128526"} | 2026-07-23T17:07:13.895196Z | 200 | 2b65dd89a23b3ab467da041d8727598dc3eb0aa28bdbed4b9c512d6a35ab6455 | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:4 | ODII | Odii/storyBasedList | 2961/4617 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"2961","tlid":"4617"} | 2026-07-23T17:07:16.101336Z | 200 | bbf5f58b394b2aff9f82d5a3df0190362c1accc50ec48c1d70124ee0bb912351 | 20250609161845 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:5 | TOUR_API | KorService2/searchKeyword2 | 1492402 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"대릉원 일원"} | 2026-07-23T17:07:16.361873Z | 200 | ac247169ce0f01b42844bc18a258ceda7501a2a4d9ec2bc7f3ce8f2f81c88ada | 20260619154706 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:5 | ODII | Odii/themeSearchList | 2960/4616 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"대릉원","langCode":"ko"} | 2026-07-23T17:07:16.438178Z | 200 | 8c0c68f4ee83b13a2724ec73fa8b545d080874a539623b378a25e58616a53697 | 20250609184440 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:5 | TOUR_API | KorService2/detailCommon2 | 1492402 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"1492402"} | 2026-07-23T17:07:19.179838Z | 200 | e358fc8473ce643893d3fbffc5f3671148c50d6d297635a1dee12b12ab4386ef | 20260619154706 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:5 | TOUR_API | KorService2/detailImage2 | 1492402 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"1492402"} | 2026-07-23T17:07:20.196349Z | 200 | 200acdbbb1021426d7960e5d3c96812fe4f97f2a6b87700fb971e0d960845d34 | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:5 | ODII | Odii/storyBasedList | 2960/4616 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"2960","tlid":"4616"} | 2026-07-23T17:07:21.222639Z | 200 | 13f7c306f3cedf318b02df7dca18e0c624b342da3cbbf92a0a3ee077ea604605 | 20251028134916 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:6 | TOUR_API | KorService2/searchKeyword2 | 2658227 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"황리단길"} | 2026-07-23T17:07:22.246648Z | 200 | 0baeb784d83550fac68b4a806429f68728b5eb26ecb4fa1699c413f3a75ffb73 | 20260304100426 | [{"cpyrhtDivCd":"Type1"},{"cpyrhtDivCd":"Type3"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:6 | ODII | Odii/themeSearchList | 1312/2357 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","keyword":"황리단길","langCode":"ko"} | 2026-07-23T17:07:22.651669Z | 200 | 4c990ca1d4f46ed4d724d7455089e3aef84481f4ec93c24798765c2fcd6ea2d9 | 20250609191557 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:6 | TOUR_API | KorService2/detailCommon2 | 2658227 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"2658227"} | 2026-07-23T17:07:23.164198Z | 200 | de1b82fd761f7c5aa3e6a8c03d6004d36540e099147fcd48a83ce87cc3473d68 | 20260304100426 | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:6 | TOUR_API | KorService2/detailImage2 | 2658227 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","contentId":"2658227"} | 2026-07-23T17:07:24.147593Z | 200 | dba1c0fdf7357b1b448d8e97ac5b55b1ef6af807547419557f09a6b2b302253d | UNRESOLVED | [{"cpyrhtDivCd":"Type1"}] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
| preview:6 | ODII | Odii/storyBasedList | 1312/2357 | {"MobileApp":"IT-DA","MobileOS":"ETC","_type":"json","langCode":"ko","tid":"1312","tlid":"2357"} | 2026-07-23T17:07:25.324940Z | 200 | 6b7652c224aebe8878e2f24ceb011a824f763caa340bcce2f05f98ae185f9b73 | 20250922181134 | [] | BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW |
