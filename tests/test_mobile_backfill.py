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
        return SimpleNamespace(first=lambda: SimpleNamespace(project_id="", user_id="", session_id=""))

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
    result = await mobile.scan_retained_mobile_sources({})
    assert result == {"status": "scanned", "candidates": 51, "queued": 50}
    queue = [args for sql, args in db.queries if "INSERT INTO mobile_projection_queue" in sql]
    assert len(queue) == 50 and queue[-1]["session"] == "session-049"
    cursor = [args for sql, args in db.queries if "UPDATE mobile_backfill_cursor" in sql]
    assert cursor == [{"project": "default", "user": USER, "session": "session-049"}]
    assert db.committed == 1
    assert "LIMIT 51" in mock_query.await_args.args[0]


@pytest.mark.asyncio
async def test_scan_rewinds_only_after_end_and_ignores_deleted_or_unverified_users(monkeypatch):
    db = Db(eligible=False)
    monkeypatch.setattr(mobile, "async_session", lambda: Context(db))
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
        {"project": "", "user": "", "session": ""}
    ]


@pytest.mark.asyncio
async def test_retention_sweep_revokes_purged_source_and_limits_rechecks(monkeypatch):
    class ReaperDb:
        async def execute(self, sql):
            assert "updated_at<now()-INTERVAL '1 day'" in str(sql)
            assert "LIMIT 50" in str(sql)
            return SimpleNamespace(
                all=lambda: [
                    ("default", uuid.UUID(USER), "pi", "purged"),
                    ("default", uuid.UUID(USER), "pi", "retained"),
                ]
            )

    replay = AsyncMock(side_effect=[{"status": "pending_source"}, {"status": "complete"}])
    monkeypatch.setattr(mobile, "async_session", lambda: Context(ReaperDb()))
    monkeypatch.setattr(mobile, "project_pi_session", replay)
    assert await mobile.run_mobile_retention_sweep({}) == {"checked": 2, "revoked": 1, "failed": False}
    assert [call.args[-1] for call in replay.await_args_list] == ["purged", "retained"]
