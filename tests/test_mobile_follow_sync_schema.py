# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant follow-sync schema shape; these tests do not enable sync."""

import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy import ForeignKeyConstraint

from alembic import op as _alembic_op  # noqa: F401 — load installed Alembic before server path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observal-server"))
from models.mobile_follow_sync import Base  # noqa: E402

TABLES = {
    "partitions",
    "subjects",
    "operations",
    "changes",
    "leases",
    "pins",
    "page_throttles",
    "approvals",
    "consents",
    "nonces",
    "privacy_actions",
}
KEY = {"server_id", "project_id", "owner_id", "cohort"}


def test_all_private_rows_have_composite_owner_key_and_parent_cascade():
    assert {t.removeprefix("mobile_follow_") for t in Base.metadata.tables if t.startswith("mobile_follow_")} == TABLES
    for name in TABLES - {"partitions"}:
        table = Base.metadata.tables[f"mobile_follow_{name}"]
        assert {c.name for c in table.primary_key.columns} >= KEY
        assert any(
            {c.name for c in constraint.columns} == KEY and constraint.ondelete == "CASCADE"
            for constraint in table.constraints
            if isinstance(constraint, ForeignKeyConstraint)
        ) or name in {"pins", "page_throttles"}
        if name in {"pins", "page_throttles"}:
            assert any(
                KEY | {"lease_id"} == {c.name for c in constraint.columns} and constraint.ondelete == "CASCADE"
                for constraint in table.constraints
                if isinstance(constraint, ForeignKeyConstraint)
            )
    for name in ("subjects", "operations", "changes", "pins"):
        table = Base.metadata.tables[f"mobile_follow_{name}"]
        assert any(fk.column.table.name == "users" for fk in table.c.subject_id.foreign_keys)


def test_070_has_irreversible_downgrade_and_explicit_fences():
    path = ROOT / "observal-server/alembic/versions/070_mobile_follow_sync_state.py"
    spec = importlib.util.spec_from_file_location("mobile_follow_070_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.down_revision == "069_mobile_publication_clock"
    with pytest.raises(RuntimeError, match="restore an isolated backup"):
        module.downgrade()
    source = path.read_text()
    for fence in (
        "mobile_follow_erase_subject",
        "CHECK (normal_outcomes BETWEEN 0 AND 10000)",
        "CHECK (reserved_outcomes BETWEEN 0 AND 1000)",
        "CHECK (pin_bytes BETWEEN 0 AND 2097152)",
        "CHECK (history_bytes BETWEEN 0 AND 16777216)",
        "uq_mobile_follow_current_recovery",
        "uq_mobile_follow_change_device",
        "CHECK (expires_at >= admitted_at + interval '90 days')",
    ):
        assert fence in source
