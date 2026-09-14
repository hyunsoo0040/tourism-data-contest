"""Searchable public evidence report; incomplete full-corpus data remains explicit."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from PIL import Image

from itda.authenticity.batch import COHORT_PATHS
from itda.authenticity.contracts import Assessment
from itda.authenticity.evaluation import CONDITIONS
from itda.authenticity.publication_scope import PublicationSelection
from itda.authenticity.rubric import AXES, AXIS_THEORY, FACETS
from itda.authenticity.scoring import verify_assessment
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def checked(path: Path, key: str = "report_sha256") -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    if data[key] != canonical_sha256({k: v for k, v in data.items() if k != key}):
        raise ValueError("REPORT_INPUT_DIGEST_MISMATCH")
    return data


def photos(directory: Path, output: Path) -> dict[str, list[dict[str, Any]]]:
    summary = checked(directory / "photo-review/summary.json")
    result: dict[str, list[dict[str, Any]]] = {}
    for review in summary["rows"]:
        path = (
            directory / "appearance/materializations" / (review["materialization_sha256"] + ".json")
        )
        packet = json.loads(path.read_text())
        if canonical_sha256(packet) != review["materialization_sha256"]:
            raise ValueError("REPORT_PHOTO_MATERIALIZATION_CHANGED")
        original = Path(packet["local_path"])
        if hashlib.sha256(original.read_bytes()).hexdigest() != review["image_sha256"]:
            raise ValueError("REPORT_ORIGINAL_IMAGE_CHANGED")
        with Image.open(original) as opened:
            suffix = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp", "GIF": "gif"}.get(
                opened.format or ""
            )
        relative = None
        if suffix:
            relative = "photos/" + review["image_sha256"] + "." + suffix
            target = output / relative
            target.parent.mkdir(exist_ok=True)
            if not target.exists():
                shutil.copy2(original, target)
        result.setdefault(review["place_id"], []).append(
            {
                "url": packet["image_url"],
                "image_file": relative,
                "attribution": packet["attribution_ko"],
                "reviews": review["reviews"],
                "observations": packet["observations"]["observations"],
                "image_sha256": review["image_sha256"],
            }
        )
    return result


def detail(a: Assessment, images: list[dict[str, Any]]) -> dict[str, Any]:
    source = {e.evidence_id: e for e in a.source.evidence}
    judgments = {j.key: j for j in a.judgments}
    facets = []
    for facet in a.facets:
        contributions = []
        for contribution in facet.contributions:
            evidence = []
            for eid in contribution.evidence_ids:
                e = source[eid]
                quotes = [
                    c.quote.original for c in judgments[facet.key].citations if c.evidence_id == eid
                ]
                limit = 180 if e.receipt.provider == "APIFY_INSTAGRAM" else 1200
                joined = " / ".join(quotes)
                evidence.append(
                    {
                        "quote": joined[:limit] + ("…" if len(joined) > limit else ""),
                        "observation": e.appearance.reason if e.appearance else None,
                        "count": e.reported_count,
                        "provider": e.receipt.provider,
                        "role": e.source_role,
                        "at": e.receipt.retrieved_at.isoformat(),
                        "uri": e.receipt.source_uri,
                        "image_sha256": e.image_sha256,
                    }
                )
            contributions.append(
                {
                    "channel": contribution.channel,
                    "weight_bp": contribution.weight_bp,
                    "evidence": evidence,
                }
            )
        facets.append(
            {
                "key": facet.key,
                "value": facet.value,
                "reason": (
                    "텍스트 판단은 미확인이며, 사진에서 보이는 분위기로 이 항목을 보완했습니다. "
                    + facet.reason
                    if any(c.channel == "PHOTO" for c in facet.contributions)
                    and not any(c.channel == "TEXT" for c in facet.contributions)
                    else facet.reason
                ),
                "missing": list(facet.missing_channels),
                "contributions": contributions,
            }
        )
    return {
        "name": a.source.place.name_ko,
        "address": a.source.place.address,
        "axes": {x.axis: x.value for x in a.axes},
        "facets": facets,
        "photos": images,
        "hash": a.assessment_sha256,
        "source_hash": a.source.bundle_sha256,
        "policy_hash": a.policy.policy_sha256,
    }


def experiment(directory: Path, *, development: bool) -> dict[str, Any]:
    result = checked(directory / "evaluation/results.json")
    plan = checked(directory / "evaluation/plan.json", "plan_sha256")
    raw = json.loads((directory / "evaluation/raw-runs.json").read_text())
    for scenario in raw.values():
        for run in scenario.values():
            if run["run_sha256"] != canonical_sha256(
                {k: v for k, v in run.items() if k != "run_sha256"}
            ):
                raise ValueError("REPORT_RECOMMENDATION_RUN_CHANGED")
    rows = []
    for s in plan["scenarios"]:
        comparisons = []
        if development:
            comparisons = [
                {
                    "first": c["first"],
                    "second": c["second"],
                    "common_eligible": c["common_eligible_places"],
                    "common": c["common_pool"],
                }
                for c in result["comparisons"]
                if c["scenario"] == s["id"]
            ]
        else:
            c = next(r for r in result["scenarios"] if r["scenario"] == s["id"])
            comparisons = [
                {
                    "first": "A0",
                    "second": "A1",
                    "common": c["common_pool"],
                    "common_eligible": raw[s["id"]]["common_A0"]["eligible_count"],
                }
            ]
        answers = s["answers"]
        labels = {f.key: f.title for f in FACETS}
        label = " · ".join(f"{labels[k]} {v}" for k, v in answers.items())
        rows.append(
            {
                "label": label,
                "description": "작성된 중요도 입력(0–4): " + label,
                "runs": {
                    k: {
                        "run_sha256": v["run_sha256"],
                        "eligible_count": v["eligible_count"],
                        "items": [
                            {"place_id": i["place_id"], "score": i["score"]} for i in v["items"]
                        ],
                    }
                    for k, v in raw[s["id"]].items()
                    if k in CONDITIONS
                },
                "comparisons": comparisons,
            }
        )
    return {
        "places": 120 if development else 60,
        "scenarios": rows,
        "report_sha256": result["report_sha256"],
    }


def build(repository: Path, root: Path, output: Path, *, final: bool = False) -> dict[str, Any]:
    legacy = checked(root / "legacy-replay.json")
    legacy_by_id = {r["place_id"]: r["axes"] for r in legacy["rows"]}
    full = root / "full-2000"
    terminal = full / "workflow-photo-review.json"
    complete = False
    if terminal.exists():
        state = json.loads(terminal.read_text())
        complete = state.get("status") == "COMPLETE" and state.get("exit_code") == 0
    if final and not complete:
        raise ValueError("FULL_CORPUS_NOT_READY_FOR_FINAL_REPORT")
    output.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "version": "authenticity-evidence-report-v1",
        "final": complete,
        "datasets": {},
        "representatives": [
            m["place_id"]
            for m in checked(root / "diagnostic/manifest.json", "manifest_sha256")["members"]
        ],
        "facets": {f.key: f.title for f in FACETS},
        "theory": [
            {
                "axis": axis,
                "theory": AXIS_THEORY[axis],
                "facets": [
                    {
                        "key": f.key,
                        "title": f.title,
                        "question": f.question,
                        "anchors": f.anchors,
                        "counterexample": f.counterexample,
                    }
                    for f in FACETS
                    if f.key[0] == axis
                ],
            }
            for axis in AXES
        ],
    }
    catalogs = {
        p["place_id"]: p
        for base, _ in COHORT_PATHS.values()
        for p in json.loads((repository / base / "catalog.json").read_text())["places"]
    }
    for name, folder, conditions in (
        ("full", "full-2000", {"A0": "text", "A1": "photo-er"}),
        ("development", "development", CONDITIONS),
        ("new-evaluation", "new-evaluation", {"A0": "text", "A1": "photo-er"}),
    ):
        directory = root / folder
        manifest = checked(directory / "manifest.json", "manifest_sha256")
        images = photos(directory, output) if name != "full" or complete else {}
        rows = []
        for member in manifest["members"]:
            pid = member["place_id"]
            stem = pid.split(":")[-1]
            if name == "full" and not complete:
                p = catalogs[pid]
                rows.append(
                    {
                        "id": pid,
                        "name": p["name_ko"],
                        "region": p["administrative_area"],
                        "category": p["category"],
                        "axes": None,
                        "conditions": None,
                        "legacy": legacy_by_id.get(pid),
                    }
                )
                continue
            record: dict[str, Any] = {"id": pid, "conditions": {}, "legacy": legacy_by_id.get(pid)}
            for condition, path in conditions.items():
                a = Assessment.model_validate_json(
                    (directory / "final-assessments" / path / (stem + ".json")).read_bytes()
                )
                verify_assessment(a)
                if a.source.place.place_id != pid:
                    raise ValueError("REPORT_PLACE_BINDING_MISMATCH")
                data = detail(a, images.get(pid, []))
                presentation_hash = canonical_sha256(data)
                relative = "data/" + presentation_hash + ".js"
                js = (
                    "window.itdaDetails["
                    + json.dumps(presentation_hash)
                    + "]="
                    + json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
                    + ";\n"
                )
                target = output / relative
                target.parent.mkdir(exist_ok=True)
                if target.exists() and target.read_text() != js:
                    raise ValueError("REPORT_DETAIL_SNAPSHOT_CHANGED")
                if not target.exists():
                    target.write_text(js)
                record["conditions"][condition] = {"file": relative, "hash": presentation_hash}
                if condition == "A1":
                    record.update(
                        name=data["name"],
                        region=a.source.place.region_name,
                        category=a.source.place.category,
                        axes=data["axes"],
                    )
            rows.append(record)
        payload["datasets"][name] = {"rows": rows, "manifest_sha256": manifest["manifest_sha256"]}
    payload["experiments"] = {
        "development": experiment(root / "development", development=True),
        "new-evaluation": experiment(root / "new-evaluation", development=False),
    }
    budget = json.loads((root / "instagram-pilot/budget.json").read_text())
    spent = sum(float(r.get("actual_usd", 0)) for r in budget["runs"].values())
    dev_photos = checked(root / "development/photo-review/summary.json")
    new_photos = checked(root / "new-evaluation/photo-review/summary.json")
    social = checked(root / "instagram-pilot/association-report.json")
    quality = checked(root / "instagram-pilot/quality.json")
    conflicts = quality["count_states"].get("CONFLICT", 0)
    sensitivity = checked(root / "development/evaluation/sensitivity.json")
    changes = sensitivity["all_photo_removal_facet_changes"]
    payload["limitations"] = [
        "개발120곳은 기존 자료이며, 새60곳은 이전 상세 조회ID 16,249개와 "
        "같은 명칭·좌표를 제외해 수집했습니다. "
        "개발 자료를 블라인드로 재명명하지 않았습니다.",
        f"개발 사진{dev_photos['images']}장과 새 평가 사진{new_photos['images']}장을 "
        "별도 픽셀 AI 검토했습니다. "
        "새 사진 목표60장에는 못 미쳤으며 Odii 한도 이후 공식 추가 수집은 중단했습니다.",
        f"Instagram은{quality['total_places']}곳·{quality['analytics_tags']}태그 탐색입니다. "
        f"대표 수치 {conflicts}곳의 충돌을 격리했습니다. "
        f"캡션 연결은 {social['places_with_caption_evidence']}곳이며, "
        f"사용 가능한 수치와 캡션이 함께 있는 곳은 {social['places_with_usable_count']}곳입니다.",
        f"Apify 사용 기록 ${spent:.4f} / 승인 상한 $10. "
        "전체 장소의 별도 유료 SNS 확대는 하지 않았습니다.",
        f"사진 {sensitivity['duplicate_observations_checked']}개 관찰을 중복한 검사에서 "
        f"점수 변화는 {sensitivity['duplicate_value_violations']}건입니다. "
        f"사진 제거로 {changes['became_unknown']}개 항목은 미확인이 되고 "
        f"{changes['decreased']}개는 내려갔으며 {changes['increased']}개는 올라갔습니다. "
        "결측이 평균을 올릴 수 있다는 한계를 숨기지 않습니다.",
        "이전 진단12곳의 텍스트가 캐시 복사 누락으로 중복 요청됐습니다. "
        "두 응답을 보존하고 복사를 수정했습니다. "
        "진단→개발 수치 차이는 사진 효과가 아닙니다. "
        "A0–A4는 같은 개발 텍스트를 비교합니다.",
        "사람 정답률, NDCG, 만족도, 척도 타당성과 추천 품질 우월성은 측정하지 않았습니다. "
        "구조·권한·산술 통과가 모델 해석의 참을 보장하지 않습니다.",
    ]
    recipe = checked(root / "development/evaluation/recipe.json", "recipe_sha256")
    payload["lineage"] = {
        "생성 시각": datetime.now(UTC).isoformat(),
        "선택 정책": recipe["policy"],
        "정책 동결": recipe["recipe_sha256"],
        "원래2000곳 재생": legacy["report_sha256"],
        "개발 비교": payload["experiments"]["development"]["report_sha256"],
        "새 장소 비교": payload["experiments"]["new-evaluation"]["report_sha256"],
    }
    full_photo_path = root / "full-2000/appearance/summary.json"
    if full_photo_path.exists():
        full_photos = checked(full_photo_path)
        excluded = full_photos.get("excluded_images", 0)
        unresolved = full_photos["selected_images"] - full_photos["observed_images"] - excluded
        payload["limitations"].append(
            f"전수 사진 1차 처리: 선택 {full_photos['selected_images']}장 중 "
            f"관찰 결과 {full_photos['observed_images']}장, 사유를 기록한 제외 {excluded}장, "
            f"미해결 {unresolved}장입니다. 제외 사진은 점수 근거에 포함하지 않습니다. "
            "형식 복구와 1차 처리 수는 사진 의미의 정확도·최종 AI 검토 통과율이 아닙니다."
        )
        payload["lineage"]["전수 사진 1차 처리"] = full_photos["report_sha256"]
    selection_path = root / "publication-selection.json"
    if selection_path.exists():
        selection = PublicationSelection.model_validate_json(selection_path.read_bytes())
        full_manifest = checked(full / "manifest.json", "manifest_sha256")
        if selection.parent_manifest_sha256 != full_manifest["manifest_sha256"]:
            raise ValueError("REPORT_PUBLICATION_SELECTION_PARENT_CHANGED")
        excluded = [d for d in selection.decisions if d.decision != "INCLUDE_ACTIVITY"]
        payload["limitations"].append(
            f"분석 {len(selection.analyzed_place_ids):,}곳은 모두 보존합니다. "
            f"숙박·음식·판매 관련 검토 대상 {len(selection.decisions)}곳의 공식 원문을 AI가 확인해 "
            f"독립 관람·체험이 확인되지 않은 {len(excluded)}곳을 공개 추천 대상에서 제외했습니다. "
            f"공개 후보 {len(selection.eligible_ids):,}곳의 활성화 여부는 "
            "서비스 릴리스로 확인합니다. "
            "전 장소의 업종을 독립 검증한 결과는 아닙니다."
        )
        payload["lineage"]["공개 추천 범위"] = {
            "selection_sha256": selection.selection_sha256,
            "분석 수": len(selection.analyzed_place_ids),
            "공개 후보 수": len(selection.eligible_ids),
            "제외 근거": [
                {"장소": catalogs[d.place_id]["name_ko"], "원문": d.quote, "이유": d.reason_ko}
                for d in excluded
            ],
        }
    usage_path = root / "model-usage.json"
    if usage_path.exists():
        usage = checked(usage_path)
        payload["lineage"]["기록된 GLM 사용량"] = {
            "기준 시각": usage["observed_at"],
            "중복 캐시 제외 응답 수": usage["unique_recorded_exchanges"],
            "보고된 토큰 합계": usage["reported_total_tokens"],
            "범위": "보존된 공개 배치 응답만 집계. 개인 사진 API 및 응답 없는 전송 재시도 제외.",
            "금액": "제공되지 않아 추정하지 않음",
        }
    comparison_path = root / "development/evaluation/ranking-comparison/results.json"
    if comparison_path.exists():
        comparison = checked(comparison_path)
        importance = comparison["groups"]["IMPORTANCE_ONLY"]
        explicit = comparison["groups"]["EXPLICIT_INTENSITY"]
        payload["limitations"].append(
            "사후 개발 점검에서 중요도를 목표 강도로 간주하는 거리 비교식은 "
            f"{importance['scenarios']}개 중 {importance['changed_top5_order']}개 시나리오의 "
            "상위5 순서를 바꿨습니다. "
            f"목표 강도를 명시한 {explicit['scenarios']}개에서는 "
            f"{explicit['changed_top5_order']}개가 달랐습니다. "
            "옛 서비스 전체 비교나 품질 우월성 검증이 아니며, "
            "이 점검을 정책 동결 당시의 근거로 소급하지 않습니다."
        )
        payload["lineage"]["사후 추천식 비교"] = {
            "보고서 해시": comparison["report_sha256"],
            "범위": comparison["scope"],
            "결과": comparison["groups"],
            "동결 정책 변경": comparison["frozen_recipe_changed"],
        }
    payload["report_sha256"] = canonical_sha256(payload)
    assets = Path(__file__).parent / "report_assets"
    for file in ("report.css", "report.js"):
        shutil.copy2(assets / file, output / file)
    (output / "report-assets").mkdir(exist_ok=True)
    shutil.copy2(
        repository / "web/public/fonts/NotoSansKR-wght.ttf",
        output / "report-assets/NotoSansKR-wght.ttf",
    )
    shutil.copy2(
        repository / "web/public/fonts/NotoSansKR-OFL.txt",
        output / "report-assets/NotoSansKR-OFL.txt",
    )
    html = (
        (assets / "index.html")
        .read_text()
        .replace("__REPORT_DATA__", json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c"))
    )
    (output / "index.html").write_text(html)
    atomic_json(output / "report-data.json", payload)
    return {
        "report_sha256": payload["report_sha256"],
        "final": complete,
        "datasets": {k: len(v["rows"]) for k, v in payload["datasets"].items()},
    }
