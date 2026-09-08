"""Cross-phase contracts for Phase 3 support under the Phase 4 authority boundary."""

from __future__ import annotations

from tests.integration import test_profile_release


def test_fixed_root_authority_helper_is_support_code_not_a_pytest_test() -> None:
    helper = getattr(test_profile_release, "profile_release_build_authority", None)

    assert callable(helper)
    assert not callable(getattr(test_profile_release, "test_profile_release_build_authority", None))
