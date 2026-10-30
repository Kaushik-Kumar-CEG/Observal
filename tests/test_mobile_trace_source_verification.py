# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Typed Pi positives require the exact retained ClickHouse source revision."""

import hashlib
import inspect
import json
import uuid
from unittest.mock import AsyncMock

import pytest

from services import mobile_activity_query as query


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _DB:
    def __init__(self, facts, ancestry=None):
        self.facts = facts
        self.ancestry = ancestry if ancestry is not None else facts

    async def execute(self, sql, _params):
        return _Rows(self.ancestry if "WITH RECURSIVE chain" in str(sql) else self.facts)


class _Response:
    def __init__(self, lines):
        self.lines = lines

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": self.lines}


@pytest.mark.asyncio
async def test_typed_source_rechecks_missing_repaired_and_exact_revision(monkeypatch):
    actor = uuid.uuid4()
    digest = "a" * 64
    revision = hashlib.sha256(json.dumps([[0, digest]], separators=(",", ":")).encode()).hexdigest()
    db = _DB([(actor, "pi-exact-session", uuid.uuid4())], [(actor, "pi-exact-session", revision, 0)])
    row = {
        "user_id": str(actor),
        "session_id": "pi-exact-session",
        "line_offset": 0,
        "line_hash": digest,
        "raw_line_truncated": 0,
        "raw_length": 43,
    }
    monkeypatch.setattr(query, "_query", AsyncMock(return_value=_Response([row])))
    assert await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")
    monkeypatch.setattr(query, "_query", AsyncMock(return_value=_Response([])))
    assert not await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")
    monkeypatch.setattr(query, "_query", AsyncMock(return_value=_Response([{**row, "line_hash": "b" * 64}])))
    assert not await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")
    monkeypatch.setattr(query, "_query", AsyncMock(side_effect=ConnectionError("unavailable")))
    assert not await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")


@pytest.mark.asyncio
async def test_over_budget_source_is_unavailable_without_clickhouse_read(monkeypatch):
    check = AsyncMock()
    monkeypatch.setattr(query, "_source_verified", check)
    rows = [(uuid.uuid4(), f"session-{i}", uuid.uuid4()) for i in range(query.MAX_SESSIONS + 1)]
    assert not await query._trace_sources_verified(_DB(rows), "SELECT * FROM scoped_facts", {}, "disposable")
    check.assert_not_awaited()
    assert await query._trace_sources_verified(_DB([]), "SELECT * FROM scoped_facts", {}, "disposable")


@pytest.mark.asyncio
async def test_child_fact_requires_retained_root_and_intermediate_ancestor(monkeypatch):
    actor = uuid.uuid4()
    digest = "a" * 64
    revision = hashlib.sha256(json.dumps([[0, digest]], separators=(",", ":")).encode()).hexdigest()
    child = (actor, "child", revision, 0)
    parent = (actor, "root", revision, 0)
    child_fact = [(actor, "child", uuid.uuid4())]
    child_line = {
        "user_id": str(actor),
        "session_id": "child",
        "line_offset": 0,
        "line_hash": digest,
        "raw_line_truncated": 0,
        "raw_length": 43,
    }
    parent_line = {**child_line, "session_id": "root"}
    db = _DB(child_fact, [child, parent])
    monkeypatch.setattr(query, "_query", AsyncMock(return_value=_Response([child_line])))
    assert not await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")
    monkeypatch.setattr(query, "_query", AsyncMock(return_value=_Response([child_line, parent_line])))
    assert await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")
    db.ancestry = [child, (actor, "root", None, None)]
    assert not await query._trace_sources_verified(db, "SELECT * FROM scoped_facts", {}, "disposable")


def test_all_typed_positive_paths_recheck_source_before_publishing():
    for method in (query.trace_union, query.trace_pair_batch, query.trace_component_page):
        body = inspect.getsource(method)
        assert body.index("_trace_sources_verified(") < body.rfind("return")
