# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Old local source is a candidate only with complete uploader/root/pin/approval proof."""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from services import mobile_history_audit as audit
from tests.test_mobile_evidence_projection import _call, _result

HASH = "v2_" + "a" * 64
ACTOR = uuid.uuid4()
COMPONENT = uuid.uuid4()
VERSION = uuid.uuid4()
ROOT = uuid.uuid4()
SESSION = "synthetic-local-history"


def source(now: datetime):
    stamp = now - timedelta(minutes=3)
    header = json.dumps({"type": "session", "id": SESSION, "timestamp": stamp.isoformat()})
    messages = [
        {
            "type": "message",
            "timestamp": (stamp + timedelta(seconds=1)).isoformat(),
            "message": {"role": "user", "content": "synthetic"},
        },
        {
            "type": "message",
            "timestamp": (stamp + timedelta(seconds=2)).isoformat(),
            "message": {"role": "assistant", "content": [_call("id1"), _call("id2")]},
        },
        {"type": "message", "timestamp": (stamp + timedelta(seconds=3)).isoformat(), "message": _result("id1")},
        {"type": "message", "timestamp": (stamp + timedelta(seconds=4)).isoformat(), "message": _result("id2")},
    ]
    rows = []
    for offset, raw in enumerate([header, *(json.dumps(item) for item in messages)]):
        rows.append(
            {
                "project_id": "default",
                "user_id": str(ACTOR),
                "harness": "pi",
                "session_id": SESSION,
                "line_offset": offset,
                "line_hash": hashlib.sha256(raw.encode()).hexdigest(),
                "raw_line": raw,
                "raw_line_truncated": 0,
                "is_source_record": 1,
                "layer_hash": HASH,
                "timestamp": (stamp + timedelta(seconds=offset)).isoformat(),
                "parent_session_id": None,
                "event_type": "tool_result" if offset >= 3 else "tool_call",
            }
        )
    run = SimpleNamespace(
        run_incarnation=ROOT,
        header_hash=rows[0]["line_hash"],
        root_verified=True,
        origin_witness="pi_session_start_root_v1",
        parent_session_id=None,
        source_status="complete",
    )
    return rows, run


class Result:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows

    def mappings(self):
        return self


class PinsDB:
    def __init__(self, *, approved=True, complete=True, typed_without_receipts=False):
        self.approved = approved
        self.complete = complete
        self.typed_without_receipts = typed_without_receipts

    async def execute(self, statement, params):
        sql = str(statement)
        if "FROM mobile_verified_layers" in sql:
            return Result(
                [
                    SimpleNamespace(
                        layer_hash=HASH,
                        expected_components=1 if self.complete else 2,
                        expected_skills=int(self.typed_without_receipts),
                        expected_hooks=int(self.typed_without_receipts),
                    )
                ]
            )
        if "FROM mobile_layer_components" in sql:
            return Result([{"layer_hash": HASH, "alias": "alpha", "component_id": COMPONENT, "version_id": VERSION}])
        if self.typed_without_receipts and "FROM mobile_skill_layer_components" in sql:
            return Result(
                [
                    {
                        "layer_hash": HASH,
                        "scope": "user",
                        "alias": "review",
                        "component_id": COMPONENT,
                        "version_id": VERSION,
                        "location_sha256": "a" * 64,
                        "content_sha256": "b" * 64,
                    }
                ]
            )
        if self.typed_without_receipts and "FROM mobile_hook_layer_components" in sql:
            return Result(
                [
                    {
                        "layer_hash": HASH,
                        "binding_sha256": "c" * 64,
                        "component_id": COMPONENT,
                        "version_id": VERSION,
                        "event": "PreToolUse",
                    }
                ]
            )
        return Result([])


@pytest.mark.asyncio
async def test_historical_calls_require_root_witness_complete_pins_and_recorded_approval(monkeypatch):
    now = datetime.now(UTC)
    rows, run = source(now)
    assert audit._root_source(rows, run, SESSION, now)
    monkeypatch.setattr(audit, "_registry_at_event", lambda *args: _approved(args))

    async def _approved(args):
        return args[0].approved

    facts = await audit._candidates(PinsDB(), "default", ACTOR, rows, run, now)
    assert len(facts["mcp"]) == 2 and facts["skill"] == facts["hook"] == []
    asserted = await audit._candidates(PinsDB(typed_without_receipts=True), "default", ACTOR, rows, run, now)
    assert len(asserted["mcp"]) == 2 and asserted["skill"] == asserted["hook"] == [], (
        "installed pins alone cannot fabricate skill loads or hook executions"
    )
    assert await audit._candidates(PinsDB(complete=False), "default", ACTOR, rows, run, now) == {
        "mcp": [],
        "skill": [],
        "hook": [],
    }
    assert (await audit._candidates(PinsDB(approved=False), "default", ACTOR, rows, run, now))["mcp"] == []
    assert not audit._root_source(rows, SimpleNamespace(**{**vars(run), "origin_witness": None}), SESSION, now)
    assert not audit._root_source([{**rows[0], "raw_line_truncated": 1}, *rows[1:]], run, SESSION, now)
    assert not audit._root_source([{**rows[0], "parent_session_id": "unknown"}, *rows[1:]], run, SESSION, now)
    assert not audit._root_source(rows[1:], run, SESSION, now)


@pytest.mark.asyncio
async def test_every_kind_requires_original_author_and_latest_recorded_event_time_approval():
    class ApprovalDB:
        async def scalar(self, sql, params):
            text_sql = str(sql)
            assert "mobile_listing_provenance" in text_sql and "p.original_author_id" in text_sql
            assert "p.captured_at<=:when" in text_sql
            assert "mobile_publication_events e" in text_sql and "later.recorded_at" in text_sql
            assert "e.status='approved'" in text_sql and "e.recorded_at<=:when" in text_sql
            assert "l.is_private=false" in text_sql and params["version"] == VERSION
            return 1

    for kind in ("mcp", "skill", "hook"):
        assert await audit._registry_at_event(ApprovalDB(), kind, COMPONENT, VERSION, datetime.now(UTC))


@pytest.mark.asyncio
async def test_history_audit_outputs_only_small_cell_suppression_and_never_writes(monkeypatch):
    now = datetime.now(UTC)

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"user_id": str(ACTOR), "harness": "pi", "session_id": SESSION}]}

    async def query(sql, params):
        assert "session_events FINAL" in sql and "LIMIT {limit:UInt32}" in sql
        return Response()

    class DB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def execute(self, sql, params=None):
            assert "INSERT" not in str(sql) and "UPDATE" not in str(sql) and "DELETE" not in str(sql)
            if "SET TRANSACTION READ ONLY" in str(sql):
                return Result([])
            if "FROM mobile_run_instances" in str(sql):
                return SimpleNamespace(first=lambda: source(now)[1])
            raise AssertionError("unexpected read")

        async def scalar(self, sql, params=None):
            return 1

        async def rollback(self):
            pass

    monkeypatch.setattr(audit, "_query", query)
    monkeypatch.setattr(audit, "async_session", DB)
    monkeypatch.setattr(audit, "_rows", lambda *args: _source(now))

    async def _source(now):
        return source(now)[0]

    monkeypatch.setattr(audit, "_candidates", lambda *args: _facts(now))

    async def _facts(now):
        return {"mcp": [now - timedelta(minutes=1)] * 40, "skill": [], "hook": []}

    result = await audit.audit_local_history(now=now)
    assert result["status"] == "bounded" and result["source_sessions_examined"] == "suppressed"
    assert result["periods"]["1w"]["pi"]["mcp"]["candidate_roots"] is None
    assert result["periods"]["1m"]["unsupported"]["mcp"]["status"] == "unsupported"


@pytest.mark.asyncio
async def test_history_audit_overflow_refuses_to_publish_any_partial_period_count(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"user_id": str(ACTOR), "session_id": str(index), "harness": "pi"} for index in range(51)]}

    async def query(*args):
        return Response()

    monkeypatch.setattr(audit, "_query", query)
    result = await audit.audit_local_history(limit=50)
    assert result == {"status": "incomplete", "reason": "bounded_page_overflow", "periods": {}}


@pytest.mark.asyncio
async def test_local_cli_enforces_ten_session_bound_and_json_only(monkeypatch, capsys):
    from scripts.audit_mobile_history import main

    async def bounded(*, limit):
        assert limit == 10
        return {"status": "bounded", "periods": {}}

    monkeypatch.setattr(audit, "audit_local_history", bounded)
    await main()
    assert json.loads(capsys.readouterr().out) == {"status": "bounded", "periods": {}}


def test_local_audit_refuses_unapproved_and_nonloopback_configuration(monkeypatch):
    from scripts.audit_mobile_history import _local_only

    monkeypatch.delenv("MOBILE_LOCAL_HISTORY_AUDIT", raising=False)
    with pytest.raises(SystemExit):
        _local_only()
    monkeypatch.setenv("MOBILE_LOCAL_HISTORY_AUDIT", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:placeholder@nonlocal.example:5432/db")
    monkeypatch.setenv("CLICKHOUSE_URL", "clickhouse://127.0.0.1:8123/db")
    with pytest.raises(SystemExit):
        _local_only()
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:placeholder@localhost:5432/db")
    with pytest.raises(SystemExit):
        _local_only()  # no potentially redirected localhost DNS resolution
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:placeholder@127.0.0.1:5432/db")
    _local_only()
    monkeypatch.setenv("DATABASE_URL", "malformed credential DSN")
    with pytest.raises(SystemExit) as rejected:
        _local_only()
    assert "malformed" not in str(rejected.value)
