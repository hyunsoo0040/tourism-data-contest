"""Application workflow over pinned releases and session-owned journeys."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock
from typing import Any

from itda.authenticity.api_contracts import (
    Detail,
    EvidenceView,
    FacetQuote,
    ResultItem,
    RunResult,
    ServiceInfo,
)
from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.contracts import Assessment
from itda.authenticity.intent import Intent, IntentSubmission, build_intent
from itda.authenticity.photo import PhotoReview
from itda.authenticity.ranking import rank
from itda.authenticity.release import Release
from itda.authenticity.repository import Repository, RequestConflict


class Service:
    def __init__(
        self,
        repository: Repository,
        *,
        allow_development: bool = False,
        photo_enabled: bool = False,
    ) -> None:
        self.repository = repository
        self.allow_development = allow_development
        self.photo_enabled = photo_enabled
        self._cache: dict[str, tuple[Release, tuple[Assessment, ...], Auxiliary]] = {}
        self._lock = RLock()
        self._verified_runs: set[tuple[str, str, str]] = set()

    def pinned(self, digest: str) -> tuple[Release, tuple[Assessment, ...], Auxiliary]:
        with self._lock:
            if digest not in self._cache:
                release, assessments = self.repository.get_release(digest)
                self._cache[digest] = (release, assessments, self.repository.auxiliary(release))
            return self._cache[digest]

    def info(self) -> ServiceInfo:
        active = self.repository.active_release()
        if active is None or (active.scope != "PUBLIC" and not self.allow_development):
            return ServiceInfo(
                release_sha256=None,
                scope=None,
                places=0,
                regions=(),
                photo_enabled=self.photo_enabled,
            )
        _, assessments, _ = self.pinned(active.release_sha256)
        regions: dict[str, dict[str, Any]] = {}
        for a in assessments:
            code = a.source.place.region_code[:2]
            label = a.source.place.region_name.split()[0]
            regions.setdefault(code, {"code": code, "name": label, "places": 0})["places"] += 1
        return ServiceInfo.model_validate(
            {
                "release_sha256": active.release_sha256,
                "scope": active.scope,
                "places": len(assessments),
                "regions": list(regions.values()),
                "photo_enabled": self.photo_enabled,
            }
        )

    def profile(self, session_id: str, submission: IntentSubmission) -> Intent:
        if submission.photo_receipt_sha256:
            photo = PhotoReview.model_validate(
                self.repository.confirmed_photo(session_id, submission.photo_receipt_sha256)
            )
            if photo.targets != submission.visual_targets:
                raise ValueError("PHOTO_TARGETS_DIFFER_FROM_CONFIRMATION")
        return self.repository.put_intent(
            session_id, build_intent(submission, created_at=datetime.now(UTC))
        )

    def create_run(self, session_id: str, profile_id: str, request_id: str) -> RunResult:
        previous = self.repository.find_run(session_id, request_id)
        if previous is not None:
            if previous["profile_id"] != profile_id:
                raise RequestConflict("RUN_REQUEST_CONFLICT")
            return RunResult.model_validate(self.run(session_id, previous["payload"]["run_sha256"]))
        profile = self.repository.get_intent(session_id, profile_id)
        active = self.repository.active_release()
        if active is None or (active.scope != "PUBLIC" and not self.allow_development):
            raise ValueError("NO_ACTIVE_AUTHENTICITY_RELEASE")
        release, assessments, aux = self.pinned(active.release_sha256)
        result = rank(
            assessments=assessments,
            intent=profile,
            created_at=datetime.now(UTC),
            request_id=request_id,
            forbidden_pairs=release.forbidden_pairs,
            facility_facts=aux.facilities,
            visual_references=aux.moods,
        )
        return RunResult.model_validate(
            self.repository.put_run(session_id, request_id, release, result)
        )

    def run(self, session_id: str, run_id: str) -> dict[str, Any]:
        stored = self.repository.get_run(session_id, run_id)
        profile = self.repository.get_intent(session_id, stored["profile_id"])
        release, assessments, aux = self.pinned(stored["release_sha256"])
        original = stored["payload"]
        cache_key = (run_id, release.release_sha256, profile.intent_sha256)
        with self._lock:
            if cache_key in self._verified_runs:
                return dict(original)
        recreated = rank(
            assessments=assessments,
            intent=profile,
            created_at=datetime.fromisoformat(original["created_at"].replace("Z", "+00:00")),
            request_id=original["request_id"],
            forbidden_pairs=release.forbidden_pairs,
            facility_facts=aux.facilities,
            visual_references=aux.moods,
        )
        if recreated != original:
            raise ValueError("PINNED_RUN_REPLAY_MISMATCH")
        with self._lock:
            self._verified_runs.add(cache_key)
        return recreated

    def detail(self, session_id: str, run_id: str, place_id: str) -> Detail:
        stored = self.repository.get_run(session_id, run_id)
        run = self.run(session_id, run_id)
        item = next((i for i in run["items"] if i["place_id"] == place_id), None)
        if item is None:
            raise ValueError("PLACE_NOT_IN_PINNED_RESULTS")
        _, assessments, aux = self.pinned(stored["release_sha256"])
        assessment = next(a for a in assessments if a.source.place.place_id == place_id)
        quoted = {
            c.evidence_id: c.quote.original for j in assessment.judgments for c in j.citations
        }
        evidence = []
        for e in assessment.source.evidence:
            quote = quoted.get(e.evidence_id)
            limit = 180 if e.receipt.provider == "APIFY_INSTAGRAM" else 1000
            evidence.append(
                EvidenceView(
                    evidence_id=e.evidence_id,
                    provider=e.receipt.provider,
                    role=e.source_role,
                    modality=e.modality,
                    quote=quote[:limit] if quote else None,
                    quote_truncated=bool(quote and len(quote) > limit),
                    facet_quotes=tuple(
                        FacetQuote(
                            facet=j.key,
                            quote=c.quote.original[:limit],
                            truncated=len(c.quote.original) > limit,
                        )
                        for j in assessment.judgments
                        for c in j.citations
                        if c.evidence_id == e.evidence_id
                    ),
                    excerpt=(e.text[:limit] if e.text else None),
                    uri=e.receipt.source_uri,
                    retrieved_at=e.receipt.retrieved_at,
                    reference_date=e.receipt.source_modified_at,
                    image_sha256=e.image_sha256,
                    appearance=e.appearance.model_dump(mode="json") if e.appearance else None,
                    reported_count=e.reported_count,
                    state=e.state,
                )
            )
        return Detail(
            item=ResultItem.model_validate(item),
            address=assessment.source.place.address,
            axes=assessment.axes,
            facets=assessment.facets,
            evidence=tuple(evidence),
            photos=tuple(p.model_dump() for p in aux.photos.get(place_id, ())),
            limitations=(
                "자료가 뒷받침하는 예상 경험이며 실제 만족도를 측정한 결과가 아닙니다.",
                "사진은 보이는 분위기만, SNS 수치는 해당 태그의 관측값만 설명합니다.",
            ),
        )
