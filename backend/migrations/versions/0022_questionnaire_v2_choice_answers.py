"""Version-couple the frozen answers checks for the questionnaire-v2 contract.

Revision 0022 follows the questionnaire v1/v2 split: new submissions are
questionnaire-v2 (twelve choice answers, strict values 1..3), while legacy
questionnaire-v1 rows keep their exact stored shape. The JSON answers checks
become version-coupled: questionnaire-v1 rows keep q1..q9 with integer values
1..5, questionnaire-v2 rows require exactly q1..q12 with integer values 1..3.
The constraints reuse the explicit 0001 key/type/range form (no subqueries or
``jsonb_each_text``) and keep their exact 0001 names, additively, after
immutable revision 0021. No legacy row is rewritten.
"""

# ruff: noqa: E501

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_questionnaire_v2_choice_answers"
down_revision = "0021_phase6_proof_bound_photo_terminal_authority"
branch_labels = None
depends_on = None

_V1_REQUIRED_KEYS = ", ".join(f"'q{number}'" for number in range(1, 10))
_V1_VALUE_CHECKS = " AND ".join(
    (
        f"jsonb_typeof(answers->'q{number}') = 'number' "
        f"AND (answers->>'q{number}') ~ '^[1-5]$'"
    )
    for number in range(1, 10)
)
_V1_ANSWERS_CHECK = (
    "jsonb_typeof(answers) = 'object' "
    f"AND answers ?& ARRAY[{_V1_REQUIRED_KEYS}] "
    f"AND (answers - ARRAY[{_V1_REQUIRED_KEYS}]) = '{{}}'::jsonb "
    f"AND {_V1_VALUE_CHECKS}"
)

_V2_REQUIRED_KEYS = ", ".join(f"'q{number}'" for number in range(1, 13))
_V2_VALUE_CHECKS = " AND ".join(
    (
        f"jsonb_typeof(answers->'q{number}') = 'number' "
        f"AND (answers->>'q{number}') ~ '^[1-3]$'"
    )
    for number in range(1, 13)
)
_V2_ANSWERS_CHECK = (
    "jsonb_typeof(answers) = 'object' "
    f"AND answers ?& ARRAY[{_V2_REQUIRED_KEYS}] "
    f"AND (answers - ARRAY[{_V2_REQUIRED_KEYS}]) = '{{}}'::jsonb "
    f"AND {_V2_VALUE_CHECKS}"
)

_VERSION_COUPLICED_ANSWERS_CHECK = (
    "((questionnaire_version = 'questionnaire-v1' AND (" + _V1_ANSWERS_CHECK + ")) OR "
    "(questionnaire_version = 'questionnaire-v2' AND (" + _V2_ANSWERS_CHECK + ")))"
)

# The physical constraint names follow the project naming convention
# ck_%(table_name)s_%(constraint_name)s applied when revision 0001 created the
# tables (its logical names are ck_draft_answers / ck_profile_answers). These
# exact physical names are what revision 0022 must drop and recreate. Raw
# ALTER TABLE statements are used because op.create_check_constraint would
# apply the naming convention a second time and double the prefix.
_TARGET_CONSTRAINTS: tuple[tuple[str, str], ...] = (
    ("journey_drafts", "ck_journey_drafts_ck_draft_answers"),
    ("preference_profiles", "ck_preference_profiles_ck_profile_answers"),
)


def _recreate_check(table: str, name: str, expression: str) -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(f"ALTER TABLE app.{table} DROP CONSTRAINT IF EXISTS {name}")
    )
    bind.execute(sa.text(f"ALTER TABLE app.{table} ADD CONSTRAINT {name} CHECK ({expression})"))


def upgrade() -> None:
    for table, name in _TARGET_CONSTRAINTS:
        _recreate_check(table, name, _VERSION_COUPLICED_ANSWERS_CHECK)


def downgrade() -> None:
    bind = op.get_bind()
    v2_rows = bind.execute(
        sa.text(
            "SELECT count(*) FROM app.preference_profiles "
            "WHERE questionnaire_version = 'questionnaire-v2' "
            "UNION ALL "
            "SELECT count(*) FROM app.journey_drafts "
            "WHERE questionnaire_version = 'questionnaire-v2'"
        )
    ).scalars()
    if any(count > 0 for count in v2_rows):
        raise RuntimeError(
            "downgrade to 0021 requires zero questionnaire-v2 rows in "
            "app.preference_profiles and app.journey_drafts; remove or archive "
            "v2 rows explicitly before downgrading"
        )
    for table, name in _TARGET_CONSTRAINTS:
        _recreate_check(table, name, _V1_ANSWERS_CHECK)
