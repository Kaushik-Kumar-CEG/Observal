# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Typed counts must expire before any supporting ClickHouse raw-line TTL."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from jobs.mobile_evidence import _source_retained_until
from services.mobile_activity_query import _trace_from, qualified_zero_subset


def _row(offset: int, stamp: datetime) -> dict:
    return {"line_offset": offset, "timestamp": stamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]}


def test_earliest_source_line_controls_typed_expiry_and_old_history_stays_unknown():
    now = datetime.now(UTC)
    header = now - timedelta(days=31)
    recent = now - timedelta(minutes=5)
    until = _source_retained_until([_row(0, header), _row(1, recent)], "a" * 64)
    assert until == header.replace(microsecond=(header.microsecond // 1000) * 1000) + timedelta(days=29)
    assert until < now, "a recent event must not resurrect a root whose header raw_line may have expired"
    retained = _source_retained_until([_row(0, now - timedelta(days=1))], "b" * 64)
    assert retained is not None and retained > now


def test_missing_or_suffix_source_cannot_claim_a_retention_floor():
    now = datetime.now(UTC)
    assert _source_retained_until([_row(0, now)], None) is None
    assert _source_retained_until([_row(9, now)], "a" * 64) is None
    assert _source_retained_until([{"line_offset": 0}], "a" * 64) is None
    assert _source_retained_until([{"line_offset": 0, "timestamp": "not-a-date"}], "a" * 64) is None
    assert _source_retained_until([{"line_offset": 0, "timestamp": "1960-01-01 00:00:00"}], "a" * 64) is None


@pytest.mark.asyncio
async def test_tool_free_self_user_zero_requires_complete_unexpired_source():
    class InspectReadOnlySql:
        async def execute(self, statement, _params):
            sql = str(statement)
            assert "pub.status='complete'" in sql
            assert "pub.source_retained_until>now()" in sql
            assert "pub.source_revision=z.source_revision" in sql
            return SimpleNamespace(all=lambda: [])

    now = datetime.now(UTC)
    assert (
        await qualified_zero_subset(InspectReadOnlySql(), uuid.uuid4(), "default", now - timedelta(days=7), now) is None
    )


def test_all_typed_kinds_require_root_or_every_intermediate_source_ttl():
    for kind in ("mcp", "skill", "hook"):
        sql = _trace_from(kind)
        assert "pub.source_retained_until>now()" in sql
        assert "e.run_incarnation=e.root_run_incarnation AND e.session_id=run.session_id" in sql
        assert "WITH RECURSIVE chain AS" in sql
        assert "ancestor_pub.source_retained_until>now()" in sql
        assert "ancestor_pub.status IN ('complete','partial')" in sql
        assert "bool_or(ancestor.run_incarnation=e.root_run_incarnation" in sql
        assert "parent.header_hash=chain.parent_header_hash" in sql
        assert "root_pub" not in sql, "root fact's own pub and child ancestry already cover the root"
