# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Prompted roots are independently sourced, not inferred from MCP invocations."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from services import mobile_general_sessions as general

SUBJECT = uuid.UUID("11111111-1111-4111-8111-111111111111")
END = datetime(2026, 9, 30, tzinfo=UTC)
START = END - timedelta(days=7)


class Response:
    def __init__(self, records):
        self.records = records

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": self.records}


class Result:
    def __init__(self, ids):
        self.ids = ids

    def all(self):
        return self.ids


class Db:
    def __init__(self, surviving=None):
        self.surviving = surviving if surviving is not None else [SUBJECT]

    async def scalars(self, query):
        return Result(self.surviving)

    async def scalar(self, query, params):
        return 1 if params["hash"] == "v2_" + "a" * 64 else None


def line(offset, kind, timestamp, *, parent=None, content="prompt"):
    message = {"role": "user" if kind == "user_prompt" else "assistant", "content": content}
    return {
        "line_offset": offset,
        "line_hash": "hash" + str(offset),
        "layer_hash": "v2_" + "a" * 64,
        "raw_line_truncated": False,
        "raw_line": json.dumps({"type": "message", "timestamp": timestamp, "message": message}),
        "event_type": kind,
        "parent_session_id": parent,
    }


@pytest.mark.asyncio
async def test_pre_window_prompt_and_three_linked_children_count_one_root(monkeypatch):
    yesterday = (END - timedelta(days=1)).isoformat()
    early = (START - timedelta(days=1)).isoformat()
    rows = {"root": [line(0, "user_prompt", early)]}
    for i in range(3):
        rows[f"child-{i}"] = [line(0, "assistant_text", yesterday, parent="root")]
    monkeypatch.setattr(
        general,
        "_query",
        AsyncMock(return_value=Response([{"user_id": str(SUBJECT), "session_id": f"child-{i}"} for i in range(3)])),
    )
    monkeypatch.setattr(
        general, "_rows", AsyncMock(side_effect=lambda project, user, harness, session: rows.get(session))
    )
    actual = await general.prompted_roots(Db(), "default", START, END, subject=SUBJECT)
    assert actual == {"active_accounts": 1, "roots": 1, "eligible_sessions": 3}


@pytest.mark.asyncio
async def test_unprompted_and_purged_unrelated_sessions_do_not_erase_positive_root(monkeypatch):
    yesterday = (END - timedelta(days=1)).isoformat()
    rows = {
        "prompted": [line(0, "user_prompt", yesterday)],
        "unprompted": [line(0, "assistant_text", yesterday)],
        "purged-prefix": [line(42, "assistant_text", yesterday)],
    }
    monkeypatch.setattr(
        general,
        "_query",
        AsyncMock(return_value=Response([{"user_id": str(SUBJECT), "session_id": sid} for sid in rows])),
    )
    monkeypatch.setattr(general, "_rows", AsyncMock(side_effect=lambda project, user, harness, session: rows[session]))
    assert await general.prompted_roots(Db(), "default", START, END, subject=SUBJECT) == {
        "active_accounts": 1,
        "roots": 1,
        "eligible_sessions": 1,
    }


@pytest.mark.asyncio
async def test_purged_parent_invalid_time_and_deactivated_user_cannot_create_numeric_reading(monkeypatch):
    timestamp = (END - timedelta(days=1)).isoformat()
    source = {"child": [line(0, "assistant_text", timestamp, parent="root")]}
    monkeypatch.setattr(
        general, "_query", AsyncMock(return_value=Response([{"user_id": str(SUBJECT), "session_id": "child"}]))
    )
    monkeypatch.setattr(
        general, "_rows", AsyncMock(side_effect=lambda project, user, harness, session: source.get(session))
    )
    assert await general.prompted_roots(Db(), "default", START, END, subject=SUBJECT) is None
    source["root"] = [line(0, "user_prompt", (START - timedelta(days=1)).isoformat())]
    source["child"][0]["raw_line"] = json.dumps({"type": "message", "message": {"role": "assistant", "content": "x"}})
    assert await general.prompted_roots(Db(), "default", START, END, subject=SUBJECT) is None
    assert await general.prompted_roots(Db([]), "default", START, END, subject=SUBJECT) is None


@pytest.mark.asyncio
async def test_legacy_or_unregistered_sender_cannot_create_general_or_platform_count(monkeypatch):
    timestamp = (END - timedelta(days=1)).isoformat()
    row = line(0, "user_prompt", timestamp)
    monkeypatch.setattr(
        general, "_query", AsyncMock(return_value=Response([{"user_id": str(SUBJECT), "session_id": "root"}]))
    )
    monkeypatch.setattr(general, "_rows", AsyncMock(return_value=[row]))
    row["layer_hash"] = "legacy-hash"
    assert await general.prompted_roots(Db(), "default", START, END, subject=SUBJECT) is None
    row["layer_hash"] = "v2_" + "b" * 64
    assert await general.prompted_roots(Db(), "default", START, END) is None


@pytest.mark.asyncio
async def test_platform_overflow_never_returns_a_truncated_numeric_cohort(monkeypatch):
    monkeypatch.setattr(
        general,
        "_query",
        AsyncMock(return_value=Response([{"user_id": str(SUBJECT), "session_id": str(i)} for i in range(101)])),
    )
    monkeypatch.setattr(general, "_rows", AsyncMock())
    assert await general.prompted_roots(Db(), "default", START, END) is None
    general._rows.assert_not_awaited()
