# 이론·문항·권한·검사 버전 연결

이 문서는 코드의 현재 계약을 옮긴 연결표다. 심리 척도 타당성이나 사람 정답률 검증을 의미하지 않는다.

| 항목 | 정의 | 사용자 기대 문항 | 허용된 텍스트 주장 |
| --- | --- | --- | --- |
| H.a 원형·유산과의 접촉 | 확인된 실제 원형·유산을 방문자가 경험할 수 있는가? | 원래 남아 있는 유적이나 실물을 직접 만나는 경험을 원해요. | HERITAGE_FACT |
| H.b 역사·출처의 구체성 | 그 장소의 실제 역사와 출처를 이해할 수 있는가? | 이 장소에 얽힌 실제 역사와 사람들의 이야기를 알고 싶어요. | HISTORICAL_NARRATIVE |
| H.c 전통의 실제 지속 | 지역 주체의 전승·생활문화와 실제로 연결되는가? | 지금도 이어지는 지역의 전통과 생활문화를 접하고 싶어요. | LIVING_TRADITION |
| H.d 원형 맥락의 탐구 | 원형·유산·전통에 연결된 해설과 학습이 가능한가? | 유산이나 전통의 의미를 해설·전시를 통해 깊이 이해하고 싶어요. | HERITAGE_INTERPRETATION |
| E.a 공유되는 상징·의미 | 그 장소에 어떤 이미지와 상징적 의미가 부여되는가? | 낭만·레트로처럼 이 장소를 떠올리게 하는 이미지를 느껴보고 싶어요. | REPRESENTED_MEANING |
| E.b 매체를 통한 이미지 유통 | 장소의 이미지가 어떤 매체를 통해 재현·확산되는가? | 작품·사진·SNS에서 접한 장소를 직접 찾아가고 싶어요. | MEDIA_REPRESENTATION |
| E.c 이미지의 시각적 표현 | 외관·경관·연출이 장소의 이미지를 어떻게 표현하는가? | 내 취향의 색감·경관·공간 분위기를 경험하고 싶어요. | VISUAL_EXPRESSION, VISUAL_APPEARANCE |
| E.d 이미지의 체험·재현 | 대표 장면·구도·이야기를 현장에서 경험하고 재현할 수 있는가? | 알고 있던 장면이나 대표 구도를 현장에서 재현해보고 싶어요. | IMAGE_ENACTMENT |
| R.a 일상에서 벗어날 여지 | 자율적 탐색·여유·자기 선택을 지원하는 경험이 있는가? | 일정에 쫓기지 않고 내 방식으로 선택하고 둘러보고 싶어요. | AUTONOMOUS_ACTIVITY |
| R.b 회복을 지원하는 환경 | 자연·시각적 저자극·머무를 환경의 근거가 있는가? | 자연이나 시각적으로 편안한 환경 속에 머물고 싶어요. | ENVIRONMENT, VISUAL_APPEARANCE |
| R.c 참여·도전·몰입 | 만들기·신체 활동·탐방 등 집중할 활동의 기회가 있는가? | 만들기·걷기·신체 활동처럼 한 활동에 집중해보고 싶어요. | PARTICIPATORY_ACTIVITY |
| R.d 관계·자기표현 | 교류·공동 활동·자기표현의 기회를 제공하는가? | 함께하는 활동이나 나를 표현할 기회를 원해요. | RELATIONAL_ACTIVITY |

사진은 E.c의 시각적 성격과 R.b의 자연 환경을 보완한다. 기본 A1에서 H는 텍스트에만 근거한다. 조건부 H 사진은 실험 A2, SNS 수치와 의미는 개발 A3/A4이며 새 기본 정책에 자동 편입하지 않는다.

사용자 중요도·원하는 강도·회피는 서로 다른 필드다. 확정 사진의 색·구도 취향은 E.c/R.b의 비교를 대체해 추가 가산을 막는다. 출처 개수·사진 장수·SNS 건수는 신뢰도 보너스가 아니다.

검사 연결: 항목별 인용/권한/대상/UNKNOWN·0 구분 → 허용된 관찰만 융합 → 핵심 의미와 최소2항목의 축 자격 → 중요한 미확인 기대의 추천 제외 → 개별 기여·불일치·출처를 표시한다. 사람 라벨이 필요한 MAE/NDCG·만족도/척도 지표는 측정하지 않았다.

| 버전 | 값 |
| --- | --- |
| construct | `authenticity-construct-v1` |
| rubric_sha256 | `0ddd0da72d7e0167ebb9a1fe8975a1f994edd02a9a79610215d8ce618690cecc` |
| questionnaire_sha256 | `5fd1a9ca18babea6b70ffad1e25e09ab7a822e74e9c14ba86227562d03897ff7` |
| authority | `authenticity-authority-v1` |
| default_policy_sha256 | `a3a6035f61ccbb5c9a1a318c8f3077c03338b2f059d3037634e66f3eb25d7709` |
| ranking | `authenticity-fulfillment-v1` |
| model | `glm-5.3-flash` |
| text_prompt_sha256 | `1ff389f456713ee790d7c6d849d48af38957572c1d3112804fa09414bc1f1806` |
| appearance_prompt_sha256 | `6dc46d4251935f66c9cc17cabf88e6e0483c341c125b976c4e11b66775b21023` |

모든 수준 앵커와 반례는 `backend/src/itda/authenticity/rubric.py`와 실행별 `rubric.json`에 있다. 개발 동결 정책 및 모델 코드 해시는 `development/evaluation/recipe.json`, 데이터 구성은 각 `manifest.json`, 실제 응답과 AI 검토는 실행별 캐시/감사 기록에 보존한다.
