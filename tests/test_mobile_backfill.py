# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Retained-source replay is bounded, resumable and scoped to live verified senders."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jobs import mobile_evidence as mobile

USER = str(uuid.UUID("11111111-1111-4111-8111-111111111111"))


class Reply:
    def __init__(self, rows):
        self.rows = rows

    def raise_for_status(self):
        return None

    def json(self):
        return {"data": self.rows}


class Db:
    def __init__(self, *, eligible=True):
        self.queries = []
        self.eligible = eligible
        self.committed = 0

    async def execute(self, sql, params=None):
        self.queries.append((str(sql), params))
        return SimpleNamespace(first=lambda: SimpleNamespace(project_id="", user_id="", session_id="", skip_count=0))

    async def scalar(self, sql, params):
        return 1 if self.eligible else None

    async def commit(self):
        self.committed += 1


class Context:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *args):
        pass


def candidate(n, *, user=USER, hash_value="v2_" + "a" * 64):
    return {"project_id": "default", "user_id": user, "session_id": f"session-{n:03}", "hashes": [hash_value]}


@pytest.mark.asyncio
async def test_scan_persists_last_key_and_queues_only_first_fifty_live_mapped_sessions(monkeypatch):
    db = Db()
    mock_query = AsyncMock(return_value=Reply([candidate(n) for n in range(51)]))
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    monkeypatch.setattr(mobile, "_query", mock_query)
    monkeypatch.setattr(mobile.ds, "get_bool", AsyncMock(return_value=True))
    monkeypatch.setattr(mobile.ds, "get_int", AsyncMock(return_value=365))
    result = await mobile.scan_retained_mobile_sources({})
    assert result == {"status": "scanned", "candidates": 51, "queued": 50}
    queue = [args for sql, args in db.queries if "INSERT INTO mobile_projection_queue" in sql]
    assert len(queue) == 50 and queue[-1]["session"] == "session-049"
    cursor = [args for sql, args in db.queries if "UPDATE mobile_backfill_cursor" in sql]
    assert cursor == [{"project": "default", "user": USER, "session": "session-049", "skip": 0}]
    assert db.committed == 1
    assert "LIMIT 51" in mock_query.await_args.args[0]
    assert "timestamp>=now()-INTERVAL {days:UInt32} DAY" in mock_query.await_args.args[0]
    assert mock_query.await_args.args[1]["param_days"] == 365


@pytest.mark.asyncio
async def test_scan_rewinds_only_after_end_and_ignores_deleted_or_unverified_users(monkeypatch):
    db = Db(eligible=False)
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    monkeypatch.setattr(mobile.ds, "get_bool", AsyncMock(return_value=False))
    monkeypatch.setattr(
        mobile,
        "_query",
        AsyncMock(
            return_value=Reply(
                [candidate(1), candidate(2, user="not-a-uuid"), candidate(3, hash_value="v2_" + "x" * 64)]
            )
        ),
    )
    result = await mobile.scan_retained_mobile_sources({})
    assert result == {"status": "scanned", "candidates": 3, "queued": 0}
    assert not any("INSERT INTO mobile_projection_queue" in sql for sql, _ in db.queries)
    assert [args for sql, args in db.queries if "UPDATE mobile_backfill_cursor" in sql] == [
        {"project": "", "user": "", "session": "", "skip": 0}
    ]
    assert "timestamp>=now()-INTERVAL" not in mobile._query.await_args.args[0]


@pytest.mark.asyncio
async def test_erased_prefix_longer_than_one_page_does_not_starve_later_live_sender(monkeypatch):
    live = uuid.UUID("22222222-2222-4222-8222-222222222222")

    class ErasedPrefixDb(Db):
        def __init__(self):
            super().__init__()
            self.cursor = {"project_id": "", "user_id": "", "session_id": "", "skip_count": 0}

        async def execute(self, sql, params=None):
            self.queries.append((str(sql), params))
            if "FOR UPDATE SKIP LOCKED" in str(sql):
                return SimpleNamespace(first=lambda: SimpleNamespace(**self.cursor))
            if "UPDATE mobile_backfill_cursor" in str(sql):
                self.cursor = {
                    "project_id": params["project"],
                    "user_id": params["user"],
                    "session_id": params["session"],
                    "skip_count": params["skip"],
                }
            return SimpleNamespace()

        async def scalar(self, sql, params):
            return 1 if params.get("owner", params.get("user")) == live else None

    db = ErasedPrefixDb()
    dead_before = str(uuid.UUID("11111111-1111-4111-8111-111111111111"))
    dead_after = str(uuid.UUID("33333333-3333-4333-8333-333333333333"))
    keys = [candidate(n, user=dead_before if n <= 50 else dead_after) for n in range(101)]
    keys[51] = candidate(51, user=str(live))

    async def source(_sql, params):
        return Reply(keys[params["param_offset"] : params["param_offset"] + 51])

    mock_query = AsyncMock(side_effect=source)
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    monkeypatch.setattr(mobile, "_query", mock_query)
    monkeypatch.setattr(mobile.ds, "get_bool", AsyncMock(return_value=False))
    first = await mobile.scan_retained_mobile_sources({})
    assert first == {"status": "scanned", "candidates": 51, "queued": 0}
    assert db.cursor == {"project_id": "", "user_id": "", "session_id": "", "skip_count": 50}
    second = await mobile.scan_retained_mobile_sources({})
    assert second == {"status": "scanned", "candidates": 51, "queued": 1}
    assert db.cursor["user_id"] == str(live) and db.cursor["session_id"] == "session-051"
    assert db.cursor["skip_count"] == 0
    assert [entry.args[1]["param_offset"] for entry in mock_query.await_args_list] == [0, 50]
    assert all(dead_before not in str(item) and dead_after not in str(item) for item in db.cursor.values())


@pytest.mark.asyncio
async def test_poison_queue_reschedules_pending_and_processes_qualified_after_it(monkeypatch):
    class QueueDb(Db):
        def __init__(self):
            super().__init__()
            self.scans = 0

        async def execute(self, sql, params=None):
            self.queries.append((str(sql), params))
            if "FOR UPDATE SKIP LOCKED" in str(sql):
                self.scans += 1
                rows = (
                    [("default", uuid.UUID(USER), "pi", f"pending-{n}", n) for n in range(50)]
                    if self.scans == 1
                    else [("default", uuid.UUID(USER), "pi", "qualified", 51)]
                )
                return SimpleNamespace(all=lambda: rows)
            return SimpleNamespace()

    db = QueueDb()
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    replay = AsyncMock(side_effect=[{"status": "pending_mapping"}] * 50 + [{"status": "complete"}])
    monkeypatch.setattr(mobile, "project_pi_session", replay)
    first = await mobile.run_mobile_projection_queue({})
    second = await mobile.run_mobile_projection_queue({})
    assert first == {"attempted": 50, "completed": 0, "failed": False}
    assert second == {"attempted": 1, "completed": 1, "failed": False}
    assert "requested_at<=now()" in db.queries[0][0]
    assert "attempts=q.attempts+1" in db.queries[0][0]
    assert "INTERVAL '3 minutes'" in db.queries[0][0]
    retries = [sql for sql, _ in db.queries if "INTERVAL '5 minutes'" in sql]
    assert len(retries) == 50 and all("requested_at=:claimed" in sql for sql in retries)
    assert db.committed == 53  # Two durable claims; each projection outcome releases its own transaction.


@pytest.mark.asyncio
async def test_parent_projection_releases_claimed_child_row_before_nested_requeue(monkeypatch):
    class ParentChildDb(Db):
        async def execute(self, sql, params=None):
            self.queries.append((str(sql), params))
            if "FOR UPDATE SKIP LOCKED" in str(sql):
                return SimpleNamespace(
                    all=lambda: [
                        ("default", uuid.UUID(USER), "pi", "parent", 1),
                        ("default", uuid.UUID(USER), "pi", "child", 2),
                    ]
                )
            return SimpleNamespace()

    db = ParentChildDb()
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    seen = []

    async def replay(_ctx, _project, _user, _harness, session):
        assert db.committed >= 1, "parent cannot requeue its still-locked child"
        seen.append(session)
        return {"status": "complete"}

    monkeypatch.setattr(mobile, "project_pi_session", replay)
    assert await mobile.run_mobile_projection_queue({}) == {"attempted": 2, "completed": 2, "failed": False}
    assert seen == ["parent", "child"]
    assert db.committed == 3
    assert all("requested_at=:claimed" in sql for sql, _ in db.queries[1:])
    assert all(args["claimed"] in (1, 2) for _, args in db.queries[1:])


@pytest.mark.asyncio
async def test_retention_sweep_revokes_purged_source_and_limits_rechecks(monkeypatch):
    class ReaperDb(Db):
        async def execute(self, sql, params=None):
            self.queries.append((str(sql), params))
            if "LIMIT 500" in str(sql):
                assert "last_checked_at" in str(sql)
                return SimpleNamespace(
                    all=lambda: [
                        ("default", uuid.UUID(USER), "pi", "purged"),
                        ("default", uuid.UUID(USER), "pi", "retained"),
                    ]
                )
            return SimpleNamespace()

    db = ReaperDb()
    replay = AsyncMock(side_effect=[{"status": "pending_source"}, {"status": "complete"}])
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    monkeypatch.setattr(mobile, "project_pi_session", replay)
    assert await mobile.run_mobile_retention_sweep({}) == {"checked": 2, "revoked": 1, "failed": False}
    assert [call.args[-1] for call in replay.await_args_list] == ["purged", "retained"]
    assert len([sql for sql, _ in db.queries if "SET last_checked_at=now()" in sql]) == 2
    assert db.committed == 1


@pytest.mark.asyncio
async def test_retention_sweep_does_not_starve_after_first_poison_source(monkeypatch):
    class ReaperDb(Db):
        async def execute(self, sql, params=None):
            self.queries.append((str(sql), params))
            if "LIMIT 500" in str(sql):
                return SimpleNamespace(
                    all=lambda: [
                        ("default", uuid.UUID(USER), "pi", "poison"),
                        ("default", uuid.UUID(USER), "pi", "after-poison"),
                    ]
                )
            return SimpleNamespace()

    db = ReaperDb()
    replay = AsyncMock(side_effect=[RuntimeError("unavailable"), {"status": "complete"}])
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
    monkeypatch.setattr(mobile, "project_pi_session", replay)
    assert await mobile.run_mobile_retention_sweep({}) == {"checked": 2, "revoked": 0, "failed": True}
    assert replay.await_count == 2 and db.committed == 1
