#!/usr/bin/env bash
set -euo pipefail

readonly marker="CR-10_STALE_INVALID_CHAIN"

set +e
output="$(
  rtk proxy env \
    -u ZHIPUAI_API_KEY \
    -u BIGMODEL_API_KEY \
    -u ITDA_PHASE3_DATABASE_URL \
    -u ITDA_PHASE3_BUILDER_DATABASE_URL \
    -u ITDA_PHASE3_APPROVER_DATABASE_URL \
    -u ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL \
    ITDA_OFFLINE=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    MISE_OFFLINE=1 \
    MISE_NOT_FOUND_AUTO_INSTALL=0 \
    UV_OFFLINE=1 \
    mise exec -- \
    uv run --project backend --frozen --no-sync \
    pytest -q backend/tests/security/test_phase4_checked_artifact_chain.py \
    -x 2>&1
)"
status=$?
set -e

printf '%s\n' "$output"
marker_count="$(printf '%s\n' "$output" | grep -Fxc "$marker" || true)"

if [[ "$status" -ne 0 && "$marker_count" -eq 1 ]]; then
  exit 0
fi

printf 'expected nonzero pytest status and exactly one %s marker; status=%s count=%s\n' \
  "$marker" "$status" "$marker_count" >&2
exit 1
