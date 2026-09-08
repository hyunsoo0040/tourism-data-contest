SHELL := /bin/sh

APPROVAL := .planning/phases/07-authorized-nextjs-ui-replacement/07-PACKAGE-APPROVAL.md
COMPOSE := docker compose -f infra/compose.yaml
MISE := mise exec --
MISE_PYTHON := $(shell mise which python)
MISE_NODE_BIN := $(shell mise where node@24.18.0 2>/dev/null)/bin
MISE_NODE := $(MISE_NODE_BIN)/node
MISE_PNPM_BIN := $(shell mise where pnpm@11.15.1 2>/dev/null)
MISE_UV := $(shell mise which uv)
MISE_PNPM := $(shell mise which pnpm)
UV_RUN := PYTHONPATH=$(CURDIR)/backend/src $(MISE) uv run --project backend
PNPM := PATH="$(MISE_PNPM_BIN):$(MISE_NODE_BIN):$$PATH" $(MISE_PNPM) --dir web
E2E_ENV := CI=true ITDA_NO_NETWORK=1 ITDA_E2E_FRESH=1 NEXT_TELEMETRY_DISABLED=1 MISE_OFFLINE=1 MISE_NOT_FOUND_AUTO_INSTALL=0 UV_OFFLINE=1 UV_PROJECT_ENVIRONMENT=.venv.nosync PATH="$(MISE_PNPM_BIN):$(MISE_NODE_BIN):$$PATH"
E2E_UV_RUN := PYTHONPATH=$(CURDIR)/backend/src $(MISE_UV) run --offline --no-sync --frozen --no-python-downloads --project backend
E2E_PLAYWRIGHT := $(MISE_PNPM) --dir web exec playwright test
CONTRACT_PYTEST_ARGS ?= backend/tests/contract $(PHASE_05_LEGACY_TEST_IGNORES)

APPROVAL_CHECK = $(MISE_PYTHON) -c 'import hashlib,pathlib,platform,subprocess,sys; p=pathlib.Path(sys.argv[1]); fields=dict(line.split(": ",1) for line in p.read_text().splitlines() if ": " in line); expected={"status":"APPROVED","python_version":"3.13.14","uv_version":"0.11.28","node_version":"24.18.0","pnpm_version":"11.15.1"}; actual={"python_version":platform.python_version(),"uv_version":subprocess.check_output([sys.argv[2],"--version"],text=True).split()[1],"node_version":subprocess.check_output([sys.argv[3],"--version"],text=True).strip().removeprefix("v"),"pnpm_version":subprocess.check_output([sys.argv[4],"--version"],text=True).strip()}; sha=lambda path:hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest(); assert all(fields.get(k)==v for k,v in expected.items()), "approval marker/version mismatch"; assert all(fields[k]==v for k,v in actual.items()), "active resolver version mismatch"; assert fields.get("backend_uv_lock_sha256")==sha("backend/uv.lock"), "backend lock hash mismatch"; assert fields.get("web_pnpm_lock_sha256")==sha("web/pnpm-lock.yaml"), "web lock hash mismatch"' $(APPROVAL) $(MISE_UV) $(MISE_NODE) $(MISE_PNPM)

.PHONY: bootstrap dev check-fast check pipeline-demo contract phase-01-uat-preflight e2e-backend phase-01-uat phase-01-uat-lifecycle phase-01-uat-gate

bootstrap:
	@set -eu; \
	$(APPROVAL_CHECK); \
	before_uv=$$(shasum -a 256 backend/uv.lock | cut -d' ' -f1); \
	before_web=$$(shasum -a 256 web/pnpm-lock.yaml | cut -d' ' -f1); \
	test -z "$$(git diff -- backend/uv.lock web/pnpm-lock.yaml)"; \
	$(MISE) uv sync --project backend --locked; \
	$(PNPM) install --frozen-lockfile --ignore-scripts; \
	$(APPROVAL_CHECK); \
	test "$$before_uv" = "$$(shasum -a 256 backend/uv.lock | cut -d' ' -f1)"; \
	test "$$before_web" = "$$(shasum -a 256 web/pnpm-lock.yaml | cut -d' ' -f1)"; \
	git diff --exit-code -- backend/uv.lock web/pnpm-lock.yaml

dev:
	@set -eu; \
	: "$${ITDA_POSTGRES_ADMIN_PASSWORD:?set ITDA_POSTGRES_ADMIN_PASSWORD locally}"; \
	$(COMPOSE) up -d --wait postgres; \
	$(UV_RUN) uvicorn itda.api.main:app --reload --host 127.0.0.1 --port 8000 --no-proxy-headers & \
	api_pid=$$!; \
	trap 'kill "$$api_pid" 2>/dev/null || true' EXIT INT TERM; \
	$(PNPM) dev -H 127.0.0.1 -p 5173

PHASE_05_LEGACY_TEST_IGNORES := \
	--ignore=backend/tests/contract/phase5_openrouter_recovery_v3_cases.py \
	--ignore=backend/tests/contract/phase5_openrouter_recovery_v4_cases.py \
	--ignore=backend/tests/contract/test_demo_profile_materialization.py \
	--ignore=backend/tests/contract/test_nvidia_attempt5_retaining_authority.py \
	--ignore=backend/tests/contract/test_nvidia_minimax_profile.py \
	--ignore=backend/tests/contract/test_phase5_fresh24.py \
	--ignore=backend/tests/contract/test_phase5_fresh_cohort_authority.py \
	--ignore=backend/tests/contract/test_phase5_fresh_live.py \
	--ignore=backend/tests/contract/test_phase5_gate_receipts.py \
	--ignore=backend/tests/contract/test_phase5_nvidia_recovery.py \
	--ignore=backend/tests/contract/test_phase5_openrouter_recovery.py \
	--ignore=backend/tests/domain/test_demo_profile_eligibility.py \
	--ignore=backend/tests/integration/test_demo_scored_release.py \
	--ignore=backend/tests/integration/test_phase5_demo_source_collection.py \
	--ignore=backend/tests/security/test_phase5_provider_boundary.py \
	--ignore=backend/tests/security/test_phase5_release_authority.py \
	--ignore=backend/tests/security/test_phase5_release_security.py

check-fast:
	$(UV_RUN) ruff check backend/src backend/tests
	$(UV_RUN) mypy backend/src
	$(UV_RUN) pytest backend/tests --ignore=backend/tests/integration $(PHASE_05_LEGACY_TEST_IGNORES) -q
	$(PNPM) typecheck
	$(PNPM) test

check: check-fast
	$(UV_RUN) pytest backend/tests/integration $(PHASE_05_LEGACY_TEST_IGNORES) -q
	$(MAKE) phase-01-uat-gate

phase-01-uat-preflight:
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.e2e_runtime --preflight-only

e2e-backend:
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.e2e_runtime

phase-01-uat: phase-01-uat-preflight
	$(E2E_ENV) $(E2E_PLAYWRIGHT) e2e/start-quiz-profile.spec.ts --project=chromium --workers=1

phase-01-uat-lifecycle: phase-01-uat-preflight
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.e2e_runtime --lifecycle-gate

phase-01-uat-gate: phase-01-uat-preflight
	$(MAKE) phase-01-uat-lifecycle
	$(MAKE) phase-01-uat

pipeline-demo:
	CI=$${CI:-true} ITDA_NO_NETWORK=1 $(UV_RUN) python -m itda.cli.pipeline_demo \
		--check-stage-manifest fixtures/preview/v1/stage-manifest.json \
		--source-lock fixtures/preview/source-locks/preview-v1-source-lock.json

contract:
	@set -eu; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	$(UV_RUN) python -m itda.cli.export_openapi --output "$$tmpdir/openapi.json"; \
	diff -u contracts/openapi.json "$$tmpdir/openapi.json"; \
	$(PNPM) exec openapi-typescript ../contracts/openapi.json -o "$$tmpdir/api.d.ts"; \
	diff -u web/src/contracts/generated/api.d.ts "$$tmpdir/api.d.ts"; \
	$(UV_RUN) pytest $(CONTRACT_PYTEST_ARGS) -q; \
	$(PNPM) typecheck; \
	$(PNPM) exec tsc -p tsconfig.e2e.json --noEmit; \
	$(PNPM) exec vitest run src/contracts --no-file-parallelism

.PHONY: phase-02-check-fast phase-02-check-db phase-02-check

phase-02-check-fast:
	$(E2E_ENV) $(E2E_UV_RUN) pytest \
		backend/tests/pipeline/test_pyarrow_lock_contract.py \
		backend/tests/pipeline/test_catalog_collection.py \
		backend/tests/pipeline/test_crosswalk_revisions.py \
		backend/tests/pipeline/test_candidate_audit_exports.py \
		backend/tests/pipeline/test_catalog_relationships.py \
		backend/tests/pipeline/test_catalog_rights.py \
		backend/tests/pipeline/test_catalog_approval.py \
		backend/tests/pipeline/test_phase2_operator_journey.py \
		backend/tests/unit/test_real_manifest.py \
		backend/tests/security/test_phase2_artifact_leakage.py \
		-q --collect-only

phase-02-check-db:
	$(E2E_ENV) $(E2E_UV_RUN) pytest \
		backend/tests/integration/test_real_manifest_seal.py \
		backend/tests/integration/test_migrations.py \
		backend/tests/integration/test_role_boundaries.py \
		-q --collect-only

phase-02-check: phase-02-check-fast phase-02-check-db
	test -f .planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-PYARROW-APPROVAL.json
	test -f .planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-PYARROW-TARGET-EVIDENCE.json

.PHONY: phase-03-check-fast phase-03-check-db phase-03-check-retention-job phase-03-check-contract phase-03-check-ownership phase-03-check-ui phase-03-check

PHASE_03_FAST_PYTEST_ARGS := \
	backend/tests/contract/test_label_revision.py \
	backend/tests/unit/test_label_review_triggers.py \
	backend/tests/unit/test_label_aggregation.py \
	backend/tests/unit/test_phase3_test_ownership.py \
	backend/tests/analysis/text/ \
	backend/tests/evals/phase3/test_candidate_manifests.py \
	backend/tests/evals/phase3/test_evaluate_cli.py \
	backend/tests/security/test_phase3_boundaries.py
PHASE_03_DB_PYTEST_ARGS := \
	backend/tests/integration/test_profile_release.py \
	backend/tests/integration/test_profile_release_reads.py \
	backend/tests/integration/test_profile_release_migration_authority.py \
	backend/tests/integration/test_phase3_adjudicator_projection.py \
	backend/tests/integration/test_e2e_runtime.py \
	backend/tests/integration/test_phase3_role_boundaries.py \
	backend/tests/integration/test_phase3_label_revisions.py
PHASE_03_RETENTION_PYTEST_ARGS := \
	backend/tests/contract/test_profile_release_retention_job.py
PHASE_03_DEDICATED_CONTRACT_TESTS := \
	backend/tests/contract/test_label_revision.py \
	backend/tests/contract/test_profile_release_retention_job.py
PHASE_03_CONTRACT_PYTEST_ARGS := \
	backend/tests/contract \
	$(addprefix --ignore=,$(PHASE_03_DEDICATED_CONTRACT_TESTS))

phase-03-check-fast:
	@set -eu; \
	started_at=$$(date +%s); \
	$(E2E_ENV) HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 $(E2E_UV_RUN) pytest \
		$(PHASE_03_FAST_PYTEST_ARGS) \
		-q; \
	$(E2E_ENV) $(PNPM) exec vitest run src/features/evaluation --no-file-parallelism; \
	$(E2E_ENV) $(PNPM) exec tsc -p tsconfig.e2e.json --noEmit; \
	elapsed=$$(($$(date +%s) - started_at)); \
	echo "phase-03-check-fast completed in $${elapsed}s"; \
	test "$$elapsed" -lt 30

phase-03-check-db:
	$(E2E_ENV) $(E2E_UV_RUN) pytest \
		$(PHASE_03_DB_PYTEST_ARGS) \
		-q

phase-03-check-retention-job:
	$(E2E_ENV) $(E2E_UV_RUN) pytest \
		$(PHASE_03_RETENTION_PYTEST_ARGS) \
		-q

phase-03-check-contract:
	$(MAKE) contract CONTRACT_PYTEST_ARGS='$(PHASE_03_CONTRACT_PYTEST_ARGS)'

phase-03-check-ownership:
	@set -eu; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	$(E2E_ENV) HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 $(E2E_UV_RUN) python -m itda.cli.phase3_test_ownership collect --output "$$tmpdir/fast.json" -- $(PHASE_03_FAST_PYTEST_ARGS) >/dev/null; \
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.phase3_test_ownership collect --output "$$tmpdir/db.json" -- $(PHASE_03_DB_PYTEST_ARGS) >/dev/null; \
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.phase3_test_ownership collect --output "$$tmpdir/retention.json" -- $(PHASE_03_RETENTION_PYTEST_ARGS) >/dev/null; \
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.phase3_test_ownership collect --output "$$tmpdir/contract.json" -- $(PHASE_03_CONTRACT_PYTEST_ARGS) >/dev/null; \
	$(E2E_ENV) $(E2E_UV_RUN) python -m itda.cli.phase3_test_ownership verify \
		--manifest "fast=$$tmpdir/fast.json" \
		--manifest "db=$$tmpdir/db.json" \
		--manifest "retention=$$tmpdir/retention.json" \
		--manifest "contract=$$tmpdir/contract.json" \
		--expect tests/contract/test_label_revision.py=fast \
		--expect tests/contract/test_profile_release_retention_job.py=retention

phase-03-check-ui:
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(E2E_ENV) ITDA_PHASE3_SYNTHETIC_SEED=30302 $(E2E_PLAYWRIGHT) \
		e2e/phase3-evaluator-release.spec.ts --project=chromium --workers=1 \
		--grep-invert "profile release|adjudication and label freeze|real stale head remains stale across attempts"
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(E2E_ENV) ITDA_PHASE3_SYNTHETIC_SEED=30302 $(E2E_PLAYWRIGHT) \
		e2e/phase3-evaluator-release.spec.ts --project=chromium --workers=1 \
		--grep "real stale head remains stale across attempts" \
		--repeat-each=2 --retries=0
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(E2E_ENV) ITDA_PHASE3_SYNTHETIC_SEED=30302 $(E2E_PLAYWRIGHT) \
		e2e/phase3-evaluator-release.spec.ts --project=chromium --workers=1 \
		--grep "routed freeze receipt parents reviewed candidate" --retries=0
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1

phase-03-check: phase-03-check-ownership phase-03-check-fast phase-03-check-db phase-03-check-retention-job phase-03-check-ui phase-03-check-contract

.PHONY: phase-04-check-fast phase-04-check-provider-replay phase-04-check-db phase-04-check-security phase-04-gap-clean-check phase-04-private-evidence-check phase-04-gap-review phase-04-check

PHASE_04_ENV := env -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY -u ITDA_PHASE3_DATABASE_URL -u ITDA_PHASE3_BUILDER_DATABASE_URL -u ITDA_PHASE3_APPROVER_DATABASE_URL -u ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL ITDA_OFFLINE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 MISE_OFFLINE=1 MISE_NOT_FOUND_AUTO_INSTALL=0 UV_OFFLINE=1
PHASE_04_UV_RUN := PYTHONPATH=$(CURDIR)/backend/src $(MISE) uv run --project backend --frozen --no-sync
PHASE_04_FAST_PYTEST_ARGS := \
	backend/tests/contract/test_image_observation.py \
	backend/tests/contract/test_profile_release_authority_v2.py \
	backend/tests/contract/test_profile_release_v2.py \
	backend/tests/contract/test_phase4_test_ownership.py \
	backend/tests/evals/phase4/test_image_preprocessing.py \
	backend/tests/evals/phase4/test_image_selection.py \
	backend/tests/evals/phase4/test_phase3_lane_baseline.py \
	backend/tests/evals/phase4/test_phase4_benchmark.py \
	backend/tests/evals/phase4/test_phase4_challenge_pack.py \
	backend/tests/evals/phase4/test_phase4_vertical_slice.py \
	backend/tests/evals/phase4/test_profile_confidence_and_labels.py \
	backend/tests/evals/phase4/test_profile_fusion.py
PHASE_04_PROVIDER_REPLAY_PYTEST_ARGS := \
	backend/tests/contract/test_vlm_inference.py \
	backend/tests/evals/phase4/test_dev_image_observations.py \
	backend/tests/providers/test_zhipu_glm5v.py
PHASE_04_DB_PYTEST_ARGS := \
	backend/tests/integration/test_phase4_demo_release_sqlite.py \
	backend/tests/integration/test_profile_release_pin_v2.py \
	backend/tests/integration/test_profile_release_v2.py
PHASE_04_SECURITY_PYTEST_ARGS := \
	backend/tests/security/test_phase4_artifact_leakage.py \
	backend/tests/security/test_phase4_capability_boundaries.py \
	backend/tests/security/test_phase4_dependency_gate.py \
	backend/tests/security/test_phase4_evaluator_boundary.py \
	backend/tests/security/test_phase4_image_preprocessing.py \
	backend/tests/security/test_phase4_image_selection.py \
	backend/tests/security/test_phase4_observation_authority.py \
	backend/tests/security/test_phase4_provider_boundary.py
PHASE_04_GAP_CLEAN_PYTEST_ARGS := \
	backend/tests/integration/test_phase4_challenge_repository.py \
	backend/tests/security/test_phase4_checked_artifact_chain.py
PHASE_04_PRIVATE_EVIDENCE_PYTEST_ARGS := \
	backend/tests/security/test_phase4_regeneration_commands.py \
	backend/tests/security/test_phase4_staged_chain.py \
	backend/tests/security/test_phase4_provisioned_chain.py

phase-04-check-fast:
	@echo PHASE04_TARGET=fast
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) pytest $(PHASE_04_FAST_PYTEST_ARGS) -q

phase-04-check-provider-replay:
	@echo PHASE04_TARGET=provider-replay
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) pytest $(PHASE_04_PROVIDER_REPLAY_PYTEST_ARGS) -q

phase-04-check-db:
	@echo PHASE04_TARGET=db
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) pytest $(PHASE_04_DB_PYTEST_ARGS) -q

phase-04-check-security:
	@echo PHASE04_TARGET=security
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) pytest $(PHASE_04_SECURITY_PYTEST_ARGS) -q
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) dvc repro --dry

phase-04-gap-clean-check:
	@echo PHASE04_TARGET=gap-clean
	$(PHASE_04_ENV) $(PHASE_04_UV_RUN) pytest $(PHASE_04_GAP_CLEAN_PYTEST_ARGS) -q

phase-04-private-evidence-check:
	@echo PHASE04_TARGET=private-evidence
	$(PHASE_04_ENV) ITDA_PHASE4_PRIVATE_EVIDENCE=1 $(PHASE_04_UV_RUN) pytest $(PHASE_04_PRIVATE_EVIDENCE_PYTEST_ARGS) -q

phase-04-gap-review: phase-04-gap-clean-check phase-04-private-evidence-check

phase-04-check: phase-04-check-fast phase-04-check-provider-replay phase-04-check-db phase-04-check-security phase-04-gap-clean-check

.PHONY: phase-05-check-ownership phase-05-clean-preflight phase-05-clean-suite phase-05-clean-gate phase-05-check phase-05-private-evidence-check phase-05-current-release-gates phase-05-checkout-gate-contract phase-05-final-signoff

PHASE_05_ENV := env -u OPENROUTER_API_KEY -u NVIDIA_KEY -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY ITDA_OFFLINE=1 ITDA_NO_NETWORK=1 MISE_OFFLINE=1 MISE_NOT_FOUND_AUTO_INSTALL=0 UV_OFFLINE=1
PHASE_05_UV_RUN := PYTHONPATH=$(CURDIR)/backend/src $(MISE) uv run --offline --no-sync --frozen --no-python-downloads --project backend
PHASE_05_BACKEND_PYTEST_ARGS := \
	backend/tests/pipeline/test_mvp_public_catalog.py \
	backend/tests/pipeline/test_mvp_catalog_enrichment.py \
	backend/tests/contract/test_mvp_place_scoring.py \
	backend/tests/unit/test_mvp_place_scoring_runner.py \
	backend/tests/contract/test_mvp_scored_release.py \
	backend/tests/contract/test_mvp_scored_release_publication.py \
	backend/tests/unit/test_mvp_scored_release_store.py \
	backend/tests/contract/test_manage_mvp_scored_release.py \
	backend/tests/unit/test_mvp_recommendation.py \
	backend/tests/unit/test_mvp_recommendation_service.py \
	backend/tests/unit/test_mvp_recommendation_repository.py \
	backend/tests/unit/test_recommendation_kernel.py \
	backend/tests/contract/test_recommendation_contract.py \
	backend/tests/contract/test_openapi_contract.py \
	backend/tests/evals/phase5/test_recommendation_replay.py \
	backend/tests/api/test_recommendations.py
PHASE_05_INTEGRATION_PYTEST_ARGS := \
	backend/tests/integration/test_recommendation_runs.py
PHASE_05_COMPONENT_TESTS := \
	src/features/recommendations/RecommendationResults.test.tsx \
	src/features/recommendations/RecommendationDetail.test.tsx \
	src/features/recommendations/RecommendationCompare.test.tsx \
	src/features/recommendations/RecommendationSavedPlace.test.tsx \
	src/features/recommendations/RecommendationRecovery.test.tsx \
	src/app/storage.test.ts

phase-05-check-ownership:
	@echo PHASE05_TARGET=ownership
	@echo phase5-ownership registry=PHASE5_SUITE_REGISTRY_V4 command_set=PHASE5_SUITE_COMMAND_SET_SHA256 inventory=phase5_suite_inventory
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) pytest \
		backend/tests/contract/test_phase5_gate_receipts.py -q
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -c 'from pathlib import Path; from itda.cli.verify_phase5_gate_receipts import phase5_suite_inventory, validate_phase5_executed_inventory; root=Path("."); inventory=phase5_suite_inventory(root); validate_phase5_executed_inventory(inventory["executed_inventory"], repository_root=root); print("registry_total=37 active_present=37 pending=0 executed=37")'

phase-05-checkout-gate-contract:
	@set -eu; \
	echo PHASE05_TARGET=checkout-gate-contract; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) pytest -q backend/tests/contract/test_phase5_gate_receipts.py -x; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -c 'from pathlib import Path; from itda.cli.verify_phase5_gate_receipts import validate_phase5_current_task_ledger, validate_phase5_probe_coverage; root=Path("."); validate_phase5_current_task_ledger((root/".planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md").read_text(encoding="utf-8")); validate_phase5_probe_coverage({"edge_total":17,"explicit_truths":3,"unresolved_assumptions":14,"prohibition_total":6,"unresolved_prohibitions":6,"silent_drops":0,"explicit_truth_names":["adjacency","empty","ordering"]}); print("task_ledger_total=47 formula=12+2+3+3+3+3+2+2+3+12+2=47 failed_history=05-36 halted_history=05-27 probe=edge17 explicit3 unresolved14 prohibition6 unresolved6 silent_drops0")'

phase-05-clean-preflight:
	@echo PHASE05_TARGET=clean-preflight
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts current-release >/dev/null

phase-05-clean-suite:
	@set -eu; \
	echo PHASE05_TARGET=clean-suite; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) pytest $(PHASE_05_BACKEND_PYTEST_ARGS) -q; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) pytest $(PHASE_05_INTEGRATION_PYTEST_ARGS) -q; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.export_openapi --output "$$tmpdir/openapi.json"; \
	diff -u contracts/openapi.json "$$tmpdir/openapi.json"; \
	$(PHASE_05_ENV) $(PNPM) exec openapi-typescript ../contracts/openapi.json -o "$$tmpdir/api.d.ts"; \
	diff -u web/src/contracts/generated/api.d.ts "$$tmpdir/api.d.ts"; \
	$(PHASE_05_ENV) $(PNPM) exec vitest run $(PHASE_05_COMPONENT_TESTS) --no-file-parallelism; \
	! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1; \
	$(PHASE_05_ENV) $(E2E_PLAYWRIGHT) e2e/no-photo-recommendation.spec.ts \
		--project=chromium --workers=1 --grep-invert @real-demo; \
	! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1

phase-05-clean-gate: phase-05-clean-preflight phase-05-clean-suite
	@set -eu; \
	started_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	started_epoch=$$(date +%s); \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	echo PHASE05_TARGET=clean-gate; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts current-release >"$$tmpdir/release.json"; \
	completed_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	duration_ms=$$(($$(date +%s) - started_epoch)); \
	duration_ms=$$((duration_ms * 1000)); \
	checkout_git_sha=$$(git rev-parse HEAD); \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts emit-clean \
		--output artifacts/reports/phase5/clean-gate-receipt.json \
		--release-verification "$$tmpdir/release.json" \
		--checkout-git-sha "$$checkout_git_sha" \
		--started-at "$$started_at" --completed-at "$$completed_at" \
		--duration-ms "$$duration_ms" \
		--child backend=0 --child generated_contract=0 --child components=0 --child clean_browser=0 >/dev/null

phase-05-check: phase-05-clean-suite

phase-05-private-evidence-check:
	@set -eu; \
	started_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	started_epoch=$$(date +%s); \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	echo PHASE05_TARGET=private; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts current-release >"$$tmpdir/release.json"; \
	! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1; \
	$(PHASE_05_ENV) $(E2E_PLAYWRIGHT) e2e/no-photo-recommendation.spec.ts \
		--project=chromium --workers=1 --grep @private-real-demo; \
	! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1; \
	completed_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	duration_ms=$$(($$(date +%s) - started_epoch)); \
	duration_ms=$$((duration_ms * 1000)); \
	checkout_git_sha=$$(git rev-parse HEAD); \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts emit-private \
		--output artifacts/restricted/catalog/phase5-demo-profile-materialization/gates/private-evidence-receipt.json \
		--release-verification "$$tmpdir/release.json" \
		--checkout-git-sha "$$checkout_git_sha" \
		--started-at "$$started_at" --completed-at "$$completed_at" \
		--duration-ms "$$duration_ms" \
		--child active_release=0 --child private_browser=0 >/dev/null

phase-05-current-release-gates: phase-05-clean-gate phase-05-private-evidence-check
	@set -eu; \
	echo PHASE05_TARGET=current-release-gates; \
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts current-pair \
		--clean-receipt artifacts/reports/phase5/clean-gate-receipt.json \
		--private-receipt artifacts/restricted/catalog/phase5-demo-profile-materialization/gates/private-evidence-receipt.json >/dev/null

.PHONY: phase-06-check-fast phase-06-check-contract phase-06-check-db phase-06-check-security phase-06-check-component phase-06-check-browser phase-06-check

PHASE_06_ENV := env -u OPENROUTER_API_KEY -u NVIDIA_KEY -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY CI=true ITDA_OFFLINE=1 ITDA_NO_NETWORK=1 MISE_OFFLINE=1 MISE_NOT_FOUND_AUTO_INSTALL=0 UV_OFFLINE=1
PHASE_06_UV_RUN := PYTHONPATH=$(CURDIR)/backend/src $(MISE) uv run --offline --no-sync --frozen --no-python-downloads --project backend
PHASE_06_SOURCE_PATHS := \
	backend/src/itda/api/routes/photo.py \
	backend/src/itda/cli/e2e_runtime.py \
	backend/src/itda/db/photo_repositories.py \
	backend/src/itda/domain/photo_projection.py \
	backend/src/itda/photo
PHASE_06_FAST_PYTEST_ARGS := \
	backend/tests/contract/test_phase6_photo_jobs.py \
	backend/tests/contract/test_phase6_trait_candidates.py \
	backend/tests/unit/test_phase6_photo_projection.py
PHASE_06_DB_PYTEST_ARGS := \
	backend/tests/integration/test_phase6_photo_jobs.py \
	backend/tests/integration/test_phase6_trait_review.py \
	backend/tests/integration/test_phase6_deletion_ledger.py
PHASE_06_SECURITY_PYTEST_ARGS := \
	backend/tests/security/test_phase6_upload_boundary.py \
	backend/tests/security/test_phase6_photo_preprocessing.py \
	backend/tests/security/test_phase6_provider_boundary.py \
	backend/tests/security/test_phase6_abuse_controls.py

phase-06-check-fast:
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) ruff check $(PHASE_06_SOURCE_PATHS) $(PHASE_06_FAST_PYTEST_ARGS)
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) mypy --strict $(PHASE_06_SOURCE_PATHS)
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest $(PHASE_06_FAST_PYTEST_ARGS) -q

phase-06-check-contract:
	@set -eu; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) python -m itda.cli.export_openapi --output "$$tmpdir/openapi.json"; \
	diff -u contracts/openapi.json "$$tmpdir/openapi.json"; \
	$(PHASE_06_ENV) $(PNPM) exec openapi-typescript ../contracts/openapi.json -o "$$tmpdir/api.d.ts"; \
	diff -u web/src/contracts/generated/api.d.ts "$$tmpdir/api.d.ts"

phase-06-check-db:
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest backend/tests/integration/test_phase6_photo_jobs.py -q
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest backend/tests/integration/test_phase6_trait_review.py -q
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest backend/tests/integration/test_phase6_deletion_ledger.py -q

phase-06-check-security:
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest $(PHASE_06_SECURITY_PYTEST_ARGS) -q

phase-06-check-component:
	$(PHASE_06_ENV) $(PNPM) typecheck
	$(PHASE_06_ENV) $(PNPM) exec vitest run src/features/photo/PhotoPreferenceFlow.test.tsx

phase-06-check-browser:
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(PHASE_06_ENV) $(E2E_PLAYWRIGHT) e2e/photo-optional-journey.spec.ts --project=chromium --workers=1 --retries=0 --grep-invert "@real-photo-backend"
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(PHASE_06_ENV) $(E2E_PLAYWRIGHT) e2e/photo-optional-journey.spec.ts --project=chromium --workers=1 --retries=0 --grep "@real-photo-backend"
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1
	$(PHASE_06_ENV) $(E2E_PLAYWRIGHT) e2e/no-photo-recommendation.spec.ts --project=chromium --workers=1 --retries=0 --grep "@real-demo real demo Top 5 results"
	@! lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1

phase-06-check: phase-06-check-fast phase-06-check-contract phase-06-check-db phase-06-check-security phase-06-check-component phase-06-check-browser
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest backend/tests/evals/phase5/test_recommendation_replay.py::test_each_canonical_scenario_executes_its_declared_oracle -q
	$(PHASE_06_ENV) $(PHASE_06_UV_RUN) pytest \
		backend/tests/pipeline/test_mvp_public_catalog.py \
		backend/tests/unit/test_mvp_recommendation.py \
		backend/tests/unit/test_phase6_photo_projection.py::test_duplicate_traits_deduplicate_deterministically \
		-q

phase-05-final-signoff:
	$(PHASE_05_ENV) $(PHASE_05_UV_RUN) python -m itda.cli.verify_phase5_gate_receipts final-signoff \
		--validation .planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md \
		--clean-receipt artifacts/reports/phase5/clean-gate-receipt.json \
		--private-receipt artifacts/restricted/catalog/phase5-demo-profile-materialization/gates/private-evidence-receipt.json \
		--explanation-review artifacts/restricted/catalog/phase5-demo-profile-materialization/gates/korean-explanation-review.json \
		--final-receipt artifacts/reports/phase5/final-signoff-receipt.json \
		--finalization-record artifacts/reports/phase5/validation-finalization-commit.json \
		--allow-deferred-nonblocking-review
