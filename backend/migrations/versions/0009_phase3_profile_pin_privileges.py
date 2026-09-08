"""Correct immutable profile pin INSERT authority after the 0008 release migration."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0009_phase3_profile_pin_privileges"
down_revision = "0008_phase3_profile_releases"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PIN_RELATIONS = (
    "dev_eval.profile_release_session_pins",
    "dev_eval.profile_release_result_pins",
)


def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid PostgreSQL identifier for {name}")
    return value


def _quoted_identifier(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _change_privilege(statement: str, role: str | None) -> None:
    if role is not None:
        op.execute(sa.text(f"{statement} {_quoted_identifier(role)}"))


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    approver = _configured_identifier("label_approver_role")
    relations = ", ".join(_PIN_RELATIONS)

    _change_privilege(f"GRANT INSERT ON {relations} TO", builder)
    _change_privilege(f"REVOKE INSERT ON {relations} FROM", approver)


def downgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    approver = _configured_identifier("label_approver_role")
    relations = ", ".join(_PIN_RELATIONS)

    _change_privilege(f"REVOKE INSERT ON {relations} FROM", builder)
    _change_privilege(f"GRANT INSERT ON {relations} TO", approver)
