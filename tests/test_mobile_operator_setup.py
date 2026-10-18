# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Mobile operator workflow cannot open without exact closed cohort and atomic audit."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes.admin import mobile_setup as ops
from models.user import UserRole


def _req():
    return ops.MobileTestSetup(
        server_id=uuid.uuid4(),
        author_viewer_id=uuid.uuid4(),
        user_viewer_id=uuid.uuid4(),
        acknowledgement="isolated-disposable-synthetic-only-v1",
    )


def _status(req):
    return ops.MobileTestStatus(
        blocked=True,
        generation=3,
        server_id=req.server_id,
        author_viewer_id=req.author_viewer_id,
        user_viewer_id=req.user_viewer_id,
        configured=True,
        trace_headlines=False,
    )


@pytest.mark.asyncio
async def test_open_requires_exact_cohort_and_audit_before_commit(monkeypatch):
    req = _req()
    events = []

    async def execute(sql, _params):
        events.append("barrier")
        return SimpleNamespace(scalar_one_or_none=lambda: 4)

    async def audit(_db, _actor, action, _cohort, generation):
        assert action == "open" and generation == 4
        events.append("durable_audit")

    async def commit():
        events.append("commit")

    db = SimpleNamespace(scalar=AsyncMock(return_value=req.server_id), execute=execute, commit=commit)
    monkeypatch.setattr(ops, "_lock", AsyncMock())
    monkeypatch.setattr(ops, "_status", AsyncMock(return_value=_status(req)))
    monkeypatch.setattr(
        ops,
        "_settings",
        AsyncMock(return_value={"mobile.trace_qualification_server_id": "", "mobile.trace_qualification_ack": ""}),
    )
    monkeypatch.setattr(ops, "_record_transition", audit)
    monkeypatch.setattr(ops, "synthetic_principals_valid", AsyncMock(return_value=True))
    monkeypatch.setattr(ops, "_audit", AsyncMock())
    actor = SimpleNamespace(id=uuid.uuid4(), role=UserRole.super_admin)
    await ops.mobile_test_open(req, db, actor)
    assert events == ["barrier", "durable_audit", "commit"]
    events.clear()
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_open(req.model_copy(update={"user_viewer_id": uuid.uuid4()}), db, actor)
    assert denied.value.status_code == 409 and events == []


@pytest.mark.asyncio
async def test_setup_refuses_a_real_email_even_with_correct_server_and_ack(monkeypatch):
    req = _req()
    author = SimpleNamespace(id=req.author_viewer_id, email="person@real.example", role=UserRole.super_admin)
    user = SimpleNamespace(id=req.user_viewer_id, email="actor@example.invalid", role=UserRole.user)
    db = SimpleNamespace(
        scalar=AsyncMock(return_value=req.server_id),
        scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: [author, user])),
    )
    monkeypatch.setattr(ops, "_lock", AsyncMock())
    monkeypatch.setattr(ops, "_status", AsyncMock(return_value=_status(req)))
    monkeypatch.setattr(
        ops,
        "_settings",
        AsyncMock(return_value={"mobile.trace_qualification_server_id": "", "mobile.trace_qualification_ack": ""}),
    )
    write = AsyncMock()
    monkeypatch.setattr(ops, "_write", write)
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_setup(req, db, author)
    assert denied.value.status_code == 422
    write.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoke_commits_closed_barrier_before_settings_and_never_reopens(monkeypatch):
    req = _req()
    events = []
    db = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one=lambda: 7)),
        commit=AsyncMock(side_effect=lambda: events.append("commit")),
    )
    monkeypatch.setattr(ops, "_lock", AsyncMock())
    monkeypatch.setattr(ops, "_status", AsyncMock(return_value=_status(req)))
    monkeypatch.setattr(ops, "get_redis", lambda: object())
    monkeypatch.setattr(ops, "revoke_user_tokens", AsyncMock(side_effect=lambda *_args: events.append("revoke_grant")))
    monkeypatch.setattr(ops, "_record_transition", AsyncMock(side_effect=lambda *_args: events.append("durable_audit")))
    monkeypatch.setattr(ops, "_audit", AsyncMock())
    monkeypatch.setattr(ops, "_write", AsyncMock(side_effect=lambda *_args: events.append("clear_settings")))
    monkeypatch.setattr(ops, "_refresh", AsyncMock())
    actor = SimpleNamespace(id=uuid.uuid4(), role=UserRole.super_admin)
    await ops.mobile_test_revoke(db, actor)
    assert events == [
        "clear_settings",
        "durable_audit",
        "commit",
        "revoke_grant",
        "revoke_grant",
        "clear_settings",
        "durable_audit",
        "commit",
    ]
    assert db.execute.await_count == 2  # each transaction denies before releasing its project lock


@pytest.mark.asyncio
async def test_revocation_pending_prevents_concurrent_setup_and_reopen(monkeypatch):
    req = _req()
    pending = _status(req).model_copy(update={"revocation_pending": True})
    actor = SimpleNamespace(id=req.author_viewer_id, role=UserRole.super_admin)
    db = SimpleNamespace(scalar=AsyncMock(return_value=req.server_id), execute=AsyncMock())
    monkeypatch.setattr(ops, "_lock", AsyncMock())
    monkeypatch.setattr(ops, "_status", AsyncMock(return_value=pending))
    monkeypatch.setattr(
        ops,
        "_settings",
        AsyncMock(return_value={"mobile.trace_qualification_server_id": "", "mobile.trace_qualification_ack": ""}),
    )
    for action in (ops.mobile_test_setup, ops.mobile_test_open):
        with pytest.raises(HTTPException) as denied:
            await action(req, db, actor)
        assert denied.value.status_code == 409
    db.execute.assert_not_awaited()
