"""DEV audit experiments: real source-lane inference, no fabricated human judgments."""

from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from itda.application.grounded_context import (
    _merge_facilities,
    _source_conditions,
    build_candidates,
    build_grounded_preference,
)
from itda.contracts.grounded_promotion import (
    SOURCE_LANES,
    AxisComparisonResults,
    AxisComparisonRow,
    GroundedPromotionReport,
    MeasuredViolations,
    SourceAblationResults,
    SourceAblationRow,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import (
    GROUNDED_POLICY,
    GroundedPreference,
    GroundedRecommendationRun,
)
from itda.contracts.preference import PreferenceProfile, QuestionnaireSubmission
from itda.contracts.recommendation import RecommendationPurpose, RecommendationRequest
from itda.contracts.source_assessment import AssessmentBundle, SourceService, SupportState
from itda.contracts.visual_mood import MoodChoice, PhotoMoodCandidateSet
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_recommendation import (
    GroundedCandidate,
    GroundedRecommendationError,
    _can_complete,
    _compatible,
    _excluded,
    rank_grounded,
)
from itda.domain.grounded_scoring import (
    combine_groups,
    fit_trace,
    half_up,
    observed_value,
    pair_distance,
)
from itda.domain.preference import calculate_preference
from itda.domain.visual_mood import build_candidate_set, confirm_moods, mood_draft_sha256
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot, atomic_json
from itda.pipeline.grounded_assessment import AGGREGATION_POLICY_SHA256, build_assessment
from itda.pipeline.grounded_place_scoring import (
    ACTIVE_TEXT_PROMPT_SHA256 as TEXT_PROMPT_SHA256,
)
from itda.pipeline.grounded_place_scoring import (
    TEXT_PROMPT_V2,
    GroundedTextProvider,
    build_text_request,
    structured_facts,
)
from itda.pipeline.source_authority import SOURCE_AUTHORITY_VERSION, supports_dimension

EVALUATION_VERSION = "grounded-dev-ablation-v1"
Lane = Literal["baseline", "detail", "odii", "images", "combined"]
FIXED_TIME = datetime(2026, 9, 9, tzinfo=UTC)
PURPOSES = {
    "SIGHTSEEING": {"관광지", "문화시설", "레포츠", "축제·공연·행사"},
    "FOOD": {"음식점"},
    "LODGING": {"숙박"},
}


def _immutable(path: Path, payload: Any) -> None:
    if path.is_file():
        if json.loads(path.read_text()) != payload:
            raise ValueError("preregistered evaluation artifact changed")
    else:
        atomic_json(path, payload)


def _hash_record(fields: dict[str, Any], key: str) -> dict[str, Any]:
    return fields | {key: canonical_sha256(fields)}


def source_lane(source: DestinationEvidenceSnapshot, lane: str) -> DestinationEvidenceSnapshot:
    if lane not in SOURCE_LANES:
        raise ValueError("unknown source lane")
    allowed = {"detailCommon2", "detailIntro2"}
    if lane in {"detail", "combined"}:
        allowed.add("detailInfo2")
    evidence = tuple(
        e
        for e in source.evidence
        if (
            e.receipt.service == SourceService.TOUR
            and e.receipt.operation in allowed
            or lane in {"odii", "combined"}
            and e.receipt.service == SourceService.ODII
        )
    )
    payload = source.model_dump(mode="json", exclude={"snapshot_sha256"})
    payload["evidence"] = [e.model_dump(mode="json") for e in evidence]
    payload["text_lineage"] = [
        r for r in payload["text_lineage"] if r["evidence_id"] in {e.evidence_id for e in evidence}
    ]
    payload["coverage"] = {
        **payload["coverage"],
        "evaluation_lane": lane,
        "scope": "DEV_SOURCE_INPUT_VIEW",
        "note": (
            "Original official response bytes are retained; "
            "only declared evidence is transmitted to the model."
        ),
    }
    return DestinationEvidenceSnapshot.model_validate(_hash_record(payload, "snapshot_sha256"))


def _scenario(purpose: str, index: int, reference: PhotoMoodCandidateSet) -> dict[str, Any]:
    submission = QuestionnaireSubmission.model_validate(
        {
            "request_id": f"dev-eval:{purpose.lower()}:{index}",
            "trip_conditions": {
                "visit_date": None,
                "visit_time": "UNDECIDED",
                "companion": ["SOLO", "FRIEND_OR_PARTNER", "FAMILY_WITH_CHILDREN"][index],
                "transport": "MIXED",
                "walking_tolerance": ["WITHIN_30_MINUTES", "ABOUT_1_HOUR", "EXTENDED_WALKING_OK"][
                    index
                ],
                "indoor_outdoor_preference": "NO_PREFERENCE",
                "crowd_avoidance": ["LOW", "MEDIUM", "HIGH"][index],
            },
            "answers": {f"q{q}": index + 1 for q in range(1, 13)},
        }
    )
    profile = calculate_preference(submission, created_at=FIXED_TIME)
    confirmed = None
    if index:
        job = canonical_sha256(
            {"scenario": submission.request_id, "reference_image": reference.payload_sha256}
        )
        batch = build_candidate_set(
            job_id=job,
            image_index=1,
            image_sha256=reference.payload_sha256,
            observations=tuple(c.observation for c in reference.candidates),
            provider_id=reference.provider_id,
            analysis_kind="MODEL",
            model="glm-5.3-flash",
        )
        choices = tuple(
            MoodChoice(candidate_id=c.candidate_id, included=True)
            for c in batch.candidates
            if c.observation.state == "OBSERVED"
            and (
                index == 1
                or c.observation.dimension.value in {"greenery", "open_composition", "vivid_color"}
            )
        )
        confirmed = confirm_moods(
            job_id=job,
            profile_id=profile.profile_id,
            batches=(batch,),
            choices=choices,
            draft_sha256=mood_draft_sha256(
                job_id=job, profile_id=profile.profile_id, batches=(batch,)
            ),
        )
    request = RecommendationRequest(
        request_id=submission.request_id,
        preference_profile_id=profile.profile_id,
        purpose=RecommendationPurpose(purpose),
        photo_job_id=confirmed.job_id if confirmed else None,
    )
    preference = build_grounded_preference(profile, request, confirmed)
    return {
        "scenario_id": submission.request_id,
        "purpose": purpose,
        "participant_status": "AUTHORED_COUNTERFACTUAL_NOT_A_PARTICIPANT",
        "submission": submission.model_dump(mode="json"),
        "profile": profile.model_dump(mode="json"),
        "preference": preference.model_dump(mode="json"),
        "confirmed_reference_mood": confirmed.model_dump(mode="json") if confirmed else None,
    }


def preregister(
    candidate: GroundedReleaseCandidate,
    reference: PhotoMoodCandidateSet,
    output: Path,
    *,
    cache_version: Literal["v1", "v2"] = "v1",
    workers: int = 4,
    scope: Literal["all", "sightseeing"] = "all",
) -> dict[str, Any]:
    if cache_version not in {"v1", "v2"} or type(workers) is not int or not 1 <= workers <= 40:
        raise ValueError("unsupported evaluation cache version or model session count")
    prompt_sha = (
        hashlib.sha256(TEXT_PROMPT_V2.encode()).hexdigest()
        if cache_version == "v2"
        else TEXT_PROMPT_SHA256
    )
    if scope not in {"all", "sightseeing"}:
        raise ValueError("unsupported evaluation scope")
    purposes = tuple(PURPOSES) if scope == "all" else ("SIGHTSEEING",)
    members_per_purpose = 8 if scope == "all" else 24
    scenarios = [_scenario(p, i, reference) for p in purposes for i in range(3)]
    sources = {
        s.place.place_id: s
        for s in map(DestinationEvidenceSnapshot.model_validate, candidate.source_snapshots)
    }
    moods = {m.place_id: m for m in candidate.moods}
    members: list[dict[str, Any]] = []
    selection = []
    for purpose in purposes:
        example = next(s for s in scenarios if s["purpose"] == purpose)
        preference = GroundedPreference.model_validate(example["preference"])
        profile = PreferenceProfile.model_validate(example["profile"])
        pool = tuple(
            c
            for c in build_candidates(candidate, (), preference, profile)
            if _excluded(c, preference) is None
        )
        selected = []
        for reason, predicate in [
            ("ODII_AVAILABLE", lambda c: sources[c.place_id].coverage.get("odii_scripts", 0) > 0),
            ("LICENSED_MOOD_AVAILABLE", lambda c: bool(moods[c.place_id].images)),
        ]:
            anchor = next(
                (
                    c
                    for c in sorted(pool, key=lambda c: c.place_id)
                    if predicate(c) and c not in selected
                ),
                None,
            )
            if anchor:
                selected.append(anchor)
                selection.append({"place_id": anchor.place_id, "reason": reason})
        for c in sorted(pool, key=lambda c: c.place_id):
            if len(selected) == members_per_purpose:
                break
            if c not in selected:
                selected.append(c)
                selection.append({"place_id": c.place_id, "reason": "CANONICAL_ID_FILL"})
        if len(selected) != members_per_purpose:
            raise ValueError(
                "insufficient currently eligible places for preregistered "
                f"{members_per_purpose} per purpose"
            )
        members.extend(
            {
                "place_id": c.place_id,
                "name": sources[c.place_id].place.name_ko,
                "purpose": purpose,
                "source_snapshot_sha256": canonical_sha256(
                    sources[c.place_id].model_dump(mode="json")
                ),
            }
            for c in selected
        )
    manifest = _hash_record(
        {
            "schema_version": "grounded-dev-manifest.v1",
            "scope": "DEV",
            "origin_pool": "PUBLIC_UNLABELLED",
            "candidate_sha256": candidate.candidate_sha256,
            "selection_rule": (
                "One eligible Odii anchor and one licensed-mood anchor if available, "
                "then lexicographic place ID fill to8 perpurpose."
                if scope == "all"
                else "One eligible Odii anchor and one licensed-mood anchor if available, "
                "then lexicographic place ID fill to24 sightseeing places."
            ),
            "selection_bias": (
                "Current-eligibility/source-rich convenience subset; "
                "not representative or blinded evaluation."
            ),
            "human_labels": "NOT_MEASURED",
            "members": sorted(members, key=lambda r: r["place_id"]),
            "selection": sorted(selection, key=lambda r: r["place_id"]),
        },
        "manifest_sha256",
    )
    methods = _hash_record(
        {
            "schema_version": EVALUATION_VERSION
            if scope == "all"
            else "grounded-dev-sightseeing-ablation-v2",
            **(
                {"evaluation_scope": "SIGHTSEEING_ONLY", "excluded_purposes": ["FOOD", "LODGING"]}
                if scope == "sightseeing"
                else {}
            ),
            "candidate_sha256": candidate.candidate_sha256,
            "dev_manifest_sha256": manifest["manifest_sha256"],
            "model": "glm-5.3-flash",
            "prompt_sha256": prompt_sha,
            "aggregation_policy_sha256": AGGREGATION_POLICY_SHA256,
            "kernel_config_sha256": GROUNDED_POLICY.sha256,
            "source_authority_version": SOURCE_AUTHORITY_VERSION,
            "production_vs_experiment": (
                "Fresh nationwide source-only candidate; no legacy scores. "
                "Each DEV lane uses the same semantic-cache-v2 prompt and unchanged "
                "source-authority rules, with verified reuse of identical requests."
            )
            if cache_version == "v2"
            else (
                "Parent PUBLIC100 candidate revalidates historical raw responses "
                "without new model calls. DEV24 source lanes use the same current "
                "source-authority-v2 prompt builder and fresh/identical-request-cached outputs; "
                "production historical outputs are not mixed into those experimental lanes."
            ),
            "lanes": {
                "baseline": "Common+Intro descriptive inputs",
                "detail": "baseline+Info",
                "odii": "baseline+matched Odii scripts",
                "images": "baseline core inference+stored independent licensed mood",
                "combined": "Common+Intro+Info+Odii+stored independent licensed mood",
            },
            "source_experiment": (
                "Fresh inference for genuinely distinct text requests; "
                "exact verified cache reuse for identical requests. "
                "Never mask combined model judgments after inference."
            ),
            "axis_experiment": (
                "Same combined source, subordinate judgments, user, mood, "
                "conditions, eligibility mask and equations; raw independent numericH/E/R "
                "substitute only on supported aggregate axes in nonpublishable audit engine."
            ),
            "reference_image": (
                "A real observation of a newly collected licensed destination image "
                "is used as an authored taste proxy, not a recruited user or expert label."
            )
            if cache_version == "v2"
            else (
                "Existing real GLM observation of official Gallery1916690 "
                "used as authored taste proxy, not a recruited user or expert label."
            ),
            "reference_candidate_set_sha256": reference.candidate_set_sha256,
            "reference_image_sha256": reference.payload_sha256,
            "scenario_count": len(scenarios),
            "fixed_created_at": FIXED_TIME.isoformat(),
            "model_workers": workers,
            "failure_policy": (
                "Missing five valid results is an explicit failing case; "
                "no fabricated ranking or permissive promotion report."
            ),
            "metrics": [
                "support coverage",
                "Top5 overlap/order changes",
                "source authority violations",
                "declared condition/category/relationship violations",
                "canonical replay/order invariance",
                "same-response raw/aggregate deltas",
            ],
            "ndcg": "NOT_MEASURED_NO_GENUINE_HUMAN_JUDGMENTS",
            "field_accuracy": "NOT_MEASURED",
        },
        "methods_sha256",
    )
    _immutable(output / "dev-manifest.json", manifest)
    _immutable(output / "methods.json", methods)
    _immutable(output / "scenarios.json", scenarios)
    return manifest


def rank_raw_axis_audit(
    candidates: tuple[GroundedCandidate, ...],
    preference: GroundedPreference,
    raw_axes: dict[str, dict[str, int | None]],
    pairs: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    """Plain experimental result, deliberately not a publishable v5 receipt."""
    pool = tuple(
        c for c in sorted(candidates, key=lambda c: c.place_id) if _excluded(c, preference) is None
    )
    forbidden = frozenset(frozenset(p) for p in pairs)
    if not _can_complete((), pool, forbidden):
        raise GroundedRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
    values = {}
    effective = {}
    for c in pool:
        axes = {
            a: raw_axes[c.place_id][a]
            if observed_value(c.assessment.dimensions[a]) is not None
            else None
            for a in "HER"
        }
        if any(type(v) is not int or not 0 <= v <= 100 for v in axes.values() if v is not None):
            raise ValueError("invalid independent audit axis")
        fits = [100 - abs(preference.axis_targets[a] - v) for a, v in axes.items() if v is not None]
        experience = half_up(sum(fits), len(fits)) if fits else None
        condition = fit_trace(preference.condition_targets, c.conditions).score
        mood = fit_trace(preference.mood_targets, c.moods).score
        base = combine_groups(((experience, 8000), (condition, 2000)))
        weight = 1500 if mood is not None else 0
        effective[c.place_id] = combine_groups(((base, 10000 - weight), (mood, weight)))
        values[c.place_id] = {
            **{
                k: observed_value(c.assessment.dimensions[k])
                for k in (f"M{i}" for i in range(1, 7))
            },
            **axes,
        }
    selected: tuple[GroundedCandidate, ...] = ()
    scores = []
    for _ in range(5):
        options = []
        for c in pool:
            if not _compatible(c, selected, forbidden) or not _can_complete(
                (*selected, c), pool, forbidden
            ):
                continue
            novelty = min(
                (pair_distance(values[c.place_id], values[p.place_id]) for p in selected), default=0
            )
            fit = effective[c.place_id]
            if fit is None:
                raise ValueError("audit has no supported experience")
            options.append((fit * 8500 + novelty * 1500, c, novelty))
        if not options:
            raise GroundedRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        numerator, chosen, novelty = min(options, key=lambda r: (-r[0], r[1].place_id))
        selected = (*selected, chosen)
        scores.append(
            {
                "place_id": chosen.place_id,
                "fit_score": effective[chosen.place_id],
                "novelty_score": novelty,
                "rerank_score": half_up(numerator, 10000),
            }
        )
    return {
        "kind": "NONPUBLISHABLE_RAW_AXIS_AUDIT",
        "ranking": [c.place_id for c in selected],
        "scores": scores,
        "eligible_count": len(pool),
    }


def measure_constraints(
    ranking: tuple[str, ...],
    candidates: tuple[GroundedCandidate, ...],
    preference: GroundedPreference,
    pairs: tuple[tuple[str, str], ...],
) -> tuple[list[str], int]:
    by_id = {c.place_id: c for c in candidates}
    violations = []
    checked = 2
    if len(ranking) != 5:
        violations.append("TOP5_CARDINALITY")
    if len(set(ranking)) != len(ranking):
        violations.append("DUPLICATE_PLACE")
    for pid in ranking:
        checked += 1
        if pid not in by_id:
            violations.append("UNKNOWN_PLACE:" + pid)
        elif _excluded(by_id[pid], preference) is not None:
            violations.append("INELIGIBLE:" + pid)
    forbidden = {frozenset(p) for p in pairs}
    for i, a in enumerate(ranking):
        for b in ranking[i + 1 :]:
            checked += 2
            if frozenset((a, b)) in forbidden:
                violations.append("CANNOT_COAPPEAR:" + a + ":" + b)
            if (
                a in by_id
                and b in by_id
                and by_id[a].profile.duplicate_group_id == by_id[b].profile.duplicate_group_id
            ):
                violations.append("DUPLICATE_GROUP:" + a + ":" + b)
    return violations, checked


def authority_measurements(candidates: tuple[GroundedCandidate, ...]) -> tuple[list[str], int]:
    violations = []
    checked = 0
    for c in candidates:
        for key, row in c.assessment.dimensions.items():
            if row.state == SupportState.UNKNOWN:
                continue
            for evidence in row.evidence:
                checked += 1
                if (
                    evidence.quote not in evidence.excerpt
                    or not evidence.authorizes(row.claim)
                    or (key not in "HER" and not supports_dimension(evidence, key))
                ):
                    violations.append(c.place_id + ":" + key + ":" + evidence.evidence_id)
        for row in (*c.assessment.facts.values(), *c.moods.values(), *c.conditions.values()):
            if row.state == SupportState.UNKNOWN:
                continue
            for evidence in row.evidence:
                checked += 1
                if not evidence.authorizes(row.claim) or evidence.quote not in evidence.excerpt:
                    violations.append(c.place_id + ":" + row.key + ":" + evidence.evidence_id)
    return violations, checked


def pair_identical_requests(
    *,
    analyzed: dict[str, dict[str, dict[str, Any]]],
    sources: dict[str, dict[str, DestinationEvidenceSnapshot]],
    profiles: dict[str, Any],
    lane_hashes: dict[str, str],
    provider: GroundedTextProvider,
    cache_directory: Path,
    output: Path,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Resolve retry races by first successful response time, never by score.

    Independent lane tasks can encounter failures before an identical request
    succeeds in another lane. Preserve preliminary attempts and bind all such
    lanes to the same earliest valid exact-request response, without more calls.
    """
    groups: dict[str, list[tuple[str, str]]] = {}
    for lane, rows in analyzed.items():
        for pid, row in rows.items():
            groups.setdefault(row["request_sha256"], []).append((lane, pid))
    result: dict[str, dict[str, dict[str, Any]]] = {lane: {} for lane in analyzed}
    pairings = []
    for request_sha, members in sorted(groups.items()):
        choices = []
        first_lane, first_pid = members[0]
        for attempt in (1, 2):
            directory = cache_directory / f"attempt-{attempt}"
            path = directory / (request_sha + ".json")
            if not path.is_file():
                continue
            try:
                wire, judgments, meta = provider.analyze(
                    sources[first_lane][first_pid], cache_directory=directory, live=False
                )
                record = json.loads(path.read_text())
                stamp = datetime.fromisoformat(record["retrieved_at"].replace("Z", "+00:00"))
                choices.append((stamp, attempt, meta["response_sha256"], directory))
            except ValueError:
                continue
        chosen = min(choices, key=lambda c: (c[0], c[1], c[2])) if choices else None
        pairings.append(
            {
                "request_sha256": request_sha,
                "lanes": members,
                "selected_response_sha256": chosen[2] if chosen else None,
                "selection": "EARLIEST_VALID_RESPONSE_TIMESTAMP_NOT_SCORE",
                "new_model_calls": 0,
            }
        )
        for lane, pid in members:
            previous = analyzed[lane][pid]
            if chosen is None:
                result[lane][pid] = previous
                continue
            wire, judgments, meta = provider.analyze(
                sources[lane][pid], cache_directory=chosen[3], live=False
            )
            built = build_assessment(
                profile=profiles[pid],
                judgments=judgments,
                facts=structured_facts(sources[lane][pid]),
                source_release_sha256=lane_hashes[lane],
                assessed_at=FIXED_TIME,
                independent_axes=wire.independent_axes,
            )
            paired = {
                **previous,
                "model_status": meta["validation_status"],
                "response_sha256": meta["response_sha256"],
                "assessment": built.bundle.model_dump(mode="json"),
                "independent_axes": wire.independent_axes,
                "axis_deltas": built.axis_deltas,
                "comparison_basis": built.comparison_basis,
                "paired_cache": meta,
                "pairing_policy": "identical-request-earliest-valid-v1",
                "preliminary_response_sha256": previous["response_sha256"],
                "preliminary_status": previous["model_status"],
            }
            result[lane][pid] = paired
            atomic_json(
                output / "paired-analyses" / lane / (pid.rsplit(":", 1)[-1] + ".json"), paired
            )
    atomic_json(
        output / "request-pairing.json",
        _hash_record(
            {
                "schema_version": "identical-request-earliest-valid-v1",
                "reason": (
                    "Correct retry-race implementation of preregistered identical-request "
                    "cache reuse; no outcome-based response selection."
                ),
                "groups": pairings,
                "new_model_calls": 0,
            },
            "pairing_sha256",
        ),
    )
    for pid in result["baseline"]:
        if (
            result["baseline"][pid]["request_sha256"] != result["images"][pid]["request_sha256"]
            or result["baseline"][pid]["response_sha256"]
            != result["images"][pid]["response_sha256"]
        ):
            raise ValueError("baseline and images must share exact core input and model response")
    return result


def evaluate(
    candidate: GroundedReleaseCandidate,
    reference: PhotoMoodCandidateSet,
    *,
    output: Path,
    cache_directory: Path,
    provider: GroundedTextProvider,
    live: bool = True,
    workers: int = 4,
    scope: Literal["all", "sightseeing"] = "all",
) -> dict[str, Any]:
    prompt_sha = (
        hashlib.sha256(TEXT_PROMPT_V2.encode()).hexdigest()
        if provider.cache_version == "v2"
        else TEXT_PROMPT_SHA256
    )
    manifest = preregister(
        candidate,
        reference,
        output,
        cache_version=provider.cache_version,
        workers=workers,
        scope=scope,
    )
    methods = json.loads((output / "methods.json").read_text())
    if (
        methods["prompt_sha256"] != prompt_sha
        or methods["kernel_config_sha256"] != GROUNDED_POLICY.sha256
    ):
        raise ValueError("preregistered policy changed")
    scenarios = json.loads((output / "scenarios.json").read_text())
    selected = tuple(m["place_id"] for m in manifest["members"])
    selected_set = set(selected)
    original = {
        s.place.place_id: s
        for s in map(DestinationEvidenceSnapshot.model_validate, candidate.source_snapshots)
    }
    profiles = {p.place_id: p for p in candidate.raw_release.profiles}
    moods = {m.place_id: m for m in candidate.moods}
    sources = {
        lane: {pid: source_lane(original[pid], lane) for pid in selected} for lane in SOURCE_LANES
    }
    lane_hashes = {
        lane: canonical_sha256(
            {
                "scope": "DEV",
                "lane": lane,
                "source_snapshots": {
                    pid: canonical_sha256(s.model_dump(mode="json"))
                    for pid, s in sources[lane].items()
                },
                "mood_bundles": {pid: moods[pid].bundle_sha256 for pid in selected}
                if lane in {"images", "combined"}
                else {},
            }
        )
        for lane in SOURCE_LANES
    }
    for lane in SOURCE_LANES:
        for pid, source in sources[lane].items():
            _immutable(
                output / "lanes" / lane / "sources" / (pid.rsplit(":", 1)[-1] + ".json"),
                source.model_dump(mode="json"),
            )
    analyzed: dict[str, dict[str, dict[str, Any]]] = {lane: {} for lane in SOURCE_LANES}

    def analyze(lane, pid):
        path = output / "lanes" / lane / "analyses" / (pid.rsplit(":", 1)[-1] + ".json")
        if path.is_file():
            stored = json.loads(path.read_text())
            AssessmentBundle.model_validate(stored["assessment"])
            return lane, pid, stored
        source = sources[lane][pid]
        wire = None
        judgments = {}
        attempts = []
        for attempt in (1, 2):
            try:
                wire, judgments, metadata = provider.analyze(
                    source, cache_directory=cache_directory / f"attempt-{attempt}", live=live
                )
                attempts.append({"attempt": attempt, **metadata})
                break
            except ValueError as error:
                attempts.append(
                    {
                        "attempt": attempt,
                        "status": "UNAVAILABLE",
                        "error_type": type(error).__name__,
                        "http_status": getattr(error, "http_status", None),
                        "record_path": getattr(error, "record_path", None),
                        "validation_code": getattr(error, "validation_code", None),
                    }
                )
                if getattr(error, "http_status", None) in {401, 403}:
                    raise PermissionError("MODEL_AUTHORIZATION_REJECTED") from None
                if attempt == 1 and getattr(error, "http_status", None) in {
                    429,
                    500,
                    502,
                    503,
                    504,
                }:
                    time.sleep(max(5, min(30, getattr(error, "retry_after", 0))))
        built = build_assessment(
            profile=profiles[pid],
            judgments=judgments,
            facts=structured_facts(source),
            source_release_sha256=lane_hashes[lane],
            assessed_at=FIXED_TIME,
            independent_axes=wire.independent_axes if wire else None,
        )
        stored = {
            "place_id": pid,
            "lane": lane,
            "source_bundle_sha256": lane_hashes[lane],
            "request_sha256": canonical_sha256(
                build_text_request(source, cache_version=provider.cache_version)[0]
            ),
            "model_status": attempts[-1].get("validation_status", "UNAVAILABLE")
            if wire
            else "UNAVAILABLE",
            "response_sha256": attempts[-1].get("response_sha256") if wire else None,
            "attempts": attempts,
            "assessment": built.bundle.model_dump(mode="json"),
            "independent_axes": wire.independent_axes if wire else None,
            "comparison_basis": built.comparison_basis,
            "axis_deltas": built.axis_deltas,
        }
        _immutable(path, stored)
        print(
            json.dumps(
                {
                    "stage": "DEV_SOURCE_ANALYSIS",
                    "lane": lane,
                    "place_id": pid,
                    "status": stored["model_status"],
                    "cached": attempts[-1].get("cached", False),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return lane, pid, stored

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(analyze, lane, pid) for lane in SOURCE_LANES for pid in selected]
        try:
            for future in as_completed(futures):
                lane, pid, stored = future.result()
                analyzed[lane][pid] = stored
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    analyzed = pair_identical_requests(
        analyzed=analyzed,
        sources=sources,
        profiles=profiles,
        lane_hashes=lane_hashes,
        provider=provider,
        cache_directory=cache_directory,
        output=output,
    )
    pairs = tuple(p for p in candidate.raw_release.relation_pairs if set(p) <= selected_set)
    relation = canonical_sha256({"place_ids": list(selected), "pairs": [list(p) for p in pairs]})
    case_records = []
    source_rows = []
    axis_rows = []
    failures = []
    response_hashes = {
        lane: canonical_sha256(
            {
                pid: {
                    "response_sha256": analyzed[lane][pid]["response_sha256"],
                    "status": analyzed[lane][pid]["model_status"],
                }
                for pid in selected
            }
        )
        for lane in SOURCE_LANES
    }
    for scenario in scenarios:
        sid = scenario["scenario_id"]
        profile = PreferenceProfile.model_validate(scenario["profile"])
        preference = GroundedPreference.model_validate(scenario["preference"])
        base = {c.place_id: c for c in build_candidates(candidate, (), preference, profile)}
        lane_candidates = {}
        lane_runs = {}
        for lane in SOURCE_LANES:
            candidates = []
            for pid in selected:
                assessment = AssessmentBundle.model_validate(analyzed[lane][pid]["assessment"])
                candidates.append(
                    replace(
                        base[pid],
                        assessment=assessment,
                        conditions=_source_conditions(
                            assessment, sources[lane][pid], preference, profile
                        ),
                        contextual_facts=_merge_facilities([assessment.facts]),
                        moods=base[pid].moods if lane in {"images", "combined"} else {},
                    )
                )
            pool = tuple(candidates)
            lane_candidates[lane] = pool
            authority = {
                "scope": "DEV_AUDIT_NOT_PUBLISHABLE",
                "parent_candidate_sha256": candidate.candidate_sha256,
                "dev_manifest_sha256": manifest["manifest_sha256"],
                "lane": lane,
                "source_bundle_sha256": lane_hashes[lane],
            }
            kwargs: dict[str, Any] = dict(
                preference=preference,
                release_sha256=candidate.raw_release.release_sha256,
                source_release_sha256=lane_hashes[lane],
                assessment_manifest_sha256=canonical_sha256(
                    [c.assessment.bundle_sha256 for c in pool]
                ),
                candidate_sha256=canonical_sha256(authority),
                membership_sha256=canonical_sha256(list(selected)),
                relation_sha256=relation,
                forbidden_pairs=pairs,
                created_at=FIXED_TIME,
            )
            try:
                run = rank_grounded(candidates=pool, **kwargs)
                reordered = rank_grounded(candidates=tuple(reversed(pool)), **kwargs)
                replayed = GroundedRecommendationRun.model_validate_json(run.model_dump_json())
            except ValueError as error:
                failure = {
                    "scenario_id": sid,
                    "lane": lane,
                    "error_type": type(error).__name__,
                    "code": str(error)[:150],
                }
                failures.append(failure)
                case_records.append(failure | {"status": "FAIL_NO_FABRICATED_RANKING"})
                continue
            lane_runs[lane] = run
            ranking = tuple(i.place_id for i in run.items)
            constraints, checked_constraints = measure_constraints(ranking, pool, preference, pairs)
            claims, checked_claims = authority_measurements(pool)
            violations = MeasuredViolations(
                constraint=tuple(constraints),
                unauthorized_claim=tuple(claims),
                replay=()
                if replayed.model_dump_json() == run.model_dump_json()
                else ("REPLAY_DIFFERS",),
                structural_regression=()
                if reordered.model_dump_json() == run.model_dump_json()
                else ("CANDIDATE_ORDER_CHANGED_RESULT",),
            )
            row = SourceAblationRow(
                scenario_id=sid,
                lane=cast(Lane, lane),
                preference_sha256=canonical_sha256(preference.model_dump(mode="json")),
                source_bundle_sha256=lane_hashes[lane],
                model_response_sha256=response_hashes[lane],
                ranking=ranking,
                eligible_count=len(run.eligible_place_ids),
                purpose_eligible_count=len(run.eligible_place_ids),
                supported_dimensions=sum(
                    r.value is not None for c in pool for r in c.assessment.dimensions.values()
                ),
                possible_dimensions=len(pool) * 21,
                checked_constraints=checked_constraints,
                checked_claims=checked_claims,
                violations=violations,
            )
            source_rows.append(row)
            case_records.append(
                {
                    "scenario_id": sid,
                    "lane": lane,
                    "status": "MEASURED",
                    "row": row.model_dump(mode="json"),
                    "run": run.model_dump(mode="json"),
                    "authority_scope": authority,
                    "all_candidate_ids": list(selected),
                }
            )
        if "combined" in lane_runs:
            pool = lane_candidates["combined"]
            aggregated = lane_runs["combined"]
            raw_axes = {pid: analyzed["combined"][pid]["independent_axes"] for pid in selected}
            if any(value is None for value in raw_axes.values()):
                failures.append(
                    {
                        "scenario_id": sid,
                        "lane": "AXIS_COMPARISON",
                        "code": "SAME_RESPONSE_RAW_AXES_UNAVAILABLE",
                    }
                )
                continue
            raw = rank_raw_axis_audit(pool, preference, raw_axes, pairs)
            raw_fail, _ = measure_constraints(tuple(raw["ranking"]), pool, preference, pairs)
            aggregate_fail, _ = measure_constraints(
                tuple(i.place_id for i in aggregated.items), pool, preference, pairs
            )
            claims, _ = authority_measurements(pool)
            paired = AxisComparisonRow(
                scenario_id=sid,
                preference_sha256=canonical_sha256(preference.model_dump(mode="json")),
                source_bundle_sha256=lane_hashes["combined"],
                subordinate_judgments_sha256=canonical_sha256(
                    {
                        c.place_id: {
                            k: v.model_dump(mode="json")
                            for k, v in c.assessment.dimensions.items()
                            if k not in "HER"
                        }
                        for c in pool
                    }
                ),
                model_response_sha256=response_hashes["combined"],
                raw_independent_ranking=tuple(raw["ranking"]),
                aggregated_ranking=tuple(i.place_id for i in aggregated.items),
                compared_places=len(pool),
                supported_axes=sum(
                    c.assessment.dimensions[a].value is not None for c in pool for a in "HER"
                ),
                possible_axes=len(pool) * 3,
                raw_violations=MeasuredViolations(constraint=tuple(raw_fail)),
                aggregated_violations=MeasuredViolations(
                    constraint=tuple(aggregate_fail), unauthorized_claim=tuple(claims)
                ),
            )
            axis_rows.append(paired)
            case_records.append(
                {
                    "scenario_id": sid,
                    "kind": "AXIS_COMPARISON",
                    "row": paired.model_dump(mode="json"),
                    "raw_audit": raw,
                    "axis_deltas": {
                        pid: analyzed["combined"][pid]["axis_deltas"] for pid in selected
                    },
                }
            )
    raw_report = _hash_record(
        {
            "schema_version": "grounded-dev-measurements.v1",
            "candidate_sha256": candidate.candidate_sha256,
            "methods_sha256": methods["methods_sha256"],
            "dev_manifest_sha256": manifest["manifest_sha256"],
            "cases": case_records,
            "failures": failures,
            "human_relevance_status": "NOT_MEASURED",
        },
        "measurements_sha256",
    )
    atomic_json(output / "measurements.json", raw_report)
    summary = {
        "scope": "DEV",
        "candidate_sha256": candidate.candidate_sha256,
        "dev_manifest_sha256": manifest["manifest_sha256"],
        "status": "FAIL" if failures else "COMPLETE",
        "source_rows": len(source_rows),
        "axis_rows": len(axis_rows),
        "failures": failures,
        "model_status": {
            lane: {pid: analyzed[lane][pid]["model_status"] for pid in selected}
            for lane in SOURCE_LANES
        },
        "source_top5": {},
        "axis_top5": {},
        "human_ndcg": "NOT_MEASURED_NO_HUMAN_LABELS",
    }
    for scenario in scenarios:
        rows = {r.lane: r for r in source_rows if r.scenario_id == scenario["scenario_id"]}
        if "baseline" in rows:
            summary["source_top5"][scenario["scenario_id"]] = {
                lane: {
                    "overlap_with_baseline": len(set(row.ranking) & set(rows["baseline"].ranking)),
                    "same_order": row.ranking == rows["baseline"].ranking,
                    "ranking": list(row.ranking),
                    "support": row.supported_dimensions,
                    "possible": row.possible_dimensions,
                }
                for lane, row in rows.items()
            }
    for axis_row in axis_rows:
        summary["axis_top5"][axis_row.scenario_id] = {
            "overlap": len(
                set(axis_row.raw_independent_ranking) & set(axis_row.aggregated_ranking)
            ),
            "same_order": axis_row.raw_independent_ranking == axis_row.aggregated_ranking,
            "raw": list(axis_row.raw_independent_ranking),
            "aggregate": list(axis_row.aggregated_ranking),
        }
    if not failures:
        reports_to_write: list[tuple[str, SourceAblationResults | AxisComparisonResults]] = [
            (
                "SOURCE_ABLATION",
                SourceAblationResults(
                    dev_manifest_sha256=manifest["manifest_sha256"],
                    prompt_sha256=prompt_sha,
                    aggregation_policy_sha256=AGGREGATION_POLICY_SHA256,
                    rows=tuple(source_rows),
                ),
            ),
            (
                "AXIS_COMPARISON",
                AxisComparisonResults(
                    dev_manifest_sha256=manifest["manifest_sha256"],
                    prompt_sha256=prompt_sha,
                    aggregation_policy_sha256=AGGREGATION_POLICY_SHA256,
                    rows=tuple(axis_rows),
                ),
            ),
        ]
        for kind, result in reports_to_write:
            count = (
                sum(r.violations.failure_count for r in result.rows)
                if isinstance(result, SourceAblationResults)
                else sum(r.aggregated_violations.failure_count for r in result.rows)
            )
            fields = {
                "schema_version": "grounded-promotion-report.v1",
                "kind": kind,
                "candidate_sha256": candidate.candidate_sha256,
                "config_sha256": GROUNDED_POLICY.sha256,
                "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "result": result.model_dump(mode="json"),
                "outcome": "PASS" if count == 0 else "FAIL",
                "failure_count": count,
            }
            report = GroundedPromotionReport.model_validate(_hash_record(fields, "report_sha256"))
            atomic_json(
                output / (kind.lower().replace("_", "-") + ".json"), report.model_dump(mode="json")
            )
            summary[kind.lower() + "_sha256"] = report.report_sha256
    atomic_json(output / "summary.json", summary)
    return summary
