# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Supported Following operator control is explicit, synthetic-only and audited."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.routes.admin import mobile_setup as ops


def fixture(monkeypatch):
    req = ops.MobileFollowTestControl(
        server_id=uuid.uuid4(),
        author_viewer_id=uuid.uuid4(),
        user_viewer_id=uuid.uuid4(),
        cohort_generation=3,
        enabled=True,
        acknowledgement=ops._ACK,
        owner_decisions_acknowledgement=ops.ACK_VALUE,
        review_receipt_sha256="a" * 64,
    )
    state = ops.MobileTestStatus(
        blocked=False,
        generation=3,
        server_id=req.server_id,
        author_viewer_id=req.author_viewer_id,
        user_viewer_id=req.user_viewer_id,
        configured=True,
        trace_headlines=False,
        follow_sync_review_sha256="b" * 64,
    )
    db = SimpleNamespace(scalar=AsyncMock(side_effect=[req.server_id, True, "running"]), commit=AsyncMock())
    monkeypatch.setattr(ops, "_lock", AsyncMock())
    monkeypatch.setattr(ops, "_status", AsyncMock(return_value=state))
    monkeypatch.setattr(
        ops,
        "_settings",
        AsyncMock(return_value={"mobile.trace_qualification_server_id": "", "mobile.trace_qualification_ack": ""}),
    )
    monkeypatch.setattr(ops, "synthetic_principals_valid", AsyncMock(return_value=True))
    monkeypatch.setattr(ops, "routes_installed", lambda: True)
    for name in ["_write", "_record_transition", "_refresh", "_audit"]:
        monkeypatch.setattr(ops, name, AsyncMock())
    return req, state, db, SimpleNamespace(id=uuid.uuid4())


@pytest.mark.asyncio
async def test_reviewed_control_records_digest_and_audit_before_commit(monkeypatch):
    req, state, db, actor = fixture(monkeypatch)
    events = []
    ops._write.side_effect = lambda *_: events.append("write")
    ops._record_transition.side_effect = lambda *_: events.append("audit")
    db.commit.side_effect = lambda: events.append("commit")
    await ops.mobile_test_follow_sync(req, db, actor)
    assert events == ["write", "audit", "commit"]
    assert ops._write.await_args.args[1] == {
        ops.ENABLE_KEY: "true",
        ops.ACK_KEY: ops.ACK_VALUE,
        ops._FOLLOW_REVIEW_KEY: "a" * 64,
    }
    args = ops._record_transition.await_args.args
    assert args[2] == "follow_open" and args[3].follow_sync_review_sha256 == "a" * 64
    assert args[4] == state.generation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"acknowledgement": ""},
        {"owner_decisions_acknowledgement": ""},
        {"review_receipt_sha256": None},
        {"cohort_generation": 2},
        {"author_viewer_id": uuid.uuid4()},
        {"server_id": uuid.uuid4()},
    ],
)
async def test_missing_attestation_or_stale_scope_never_writes(monkeypatch, change):
    req, _, db, actor = fixture(monkeypatch)
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_follow_sync(req.model_copy(update=change), db, actor)
    assert denied.value.status_code in (409, 422)
    ops._write.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["closed", "unconfigured", "revoking", "live", "expired", "worker", "identity", "install"]
)
async def test_control_denies_unsafe_environment(monkeypatch, failure):
    req, state, db, actor = fixture(monkeypatch)
    if failure in ("closed", "unconfigured", "revoking", "live"):
        key, value = {
            "closed": ("blocked", True),
            "unconfigured": ("configured", False),
            "revoking": ("revocation_pending", True),
            "live": ("trace_headlines", True),
        }[failure]
        ops._status.return_value = state.model_copy(update={key: value})
    elif failure == "expired":
        db.scalar.side_effect = [req.server_id, False]
    elif failure == "worker":
        db.scalar.side_effect = [req.server_id, True, "stale"]
    elif failure == "identity":
        ops.synthetic_principals_valid.return_value = False
    else:
        monkeypatch.setattr(ops, "routes_installed", lambda: False)
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_follow_sync(req, db, actor)
    assert denied.value.status_code == 409
    ops._write.assert_not_awaited()


@pytest.mark.asyncio
async def test_close_preserves_ack_without_new_worker_or_review_requirement(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    await ops.mobile_test_follow_sync(
        req.model_copy(
            update={"enabled": False, "owner_decisions_acknowledgement": None, "review_receipt_sha256": None}
        ),
        db,
        actor,
    )
    assert db.scalar.await_count == 1
    assert ops._write.await_args.args[1] == {ops.ENABLE_KEY: "false"}
    args = ops._record_transition.await_args.args
    assert args[2] == "follow_close" and args[3].follow_sync_review_sha256 == "b" * 64


@pytest.mark.asyncio
async def test_audit_failure_does_not_commit_gate(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    ops._record_transition.side_effect = RuntimeError("scratch audit unavailable")
    with pytest.raises(RuntimeError):
        await ops.mobile_test_follow_sync(req, db, actor)
    db.commit.assert_not_awaited()
    ops._refresh.assert_not_awaited()


@pytest.mark.parametrize("change", [{"enabled": "true"}, {"review_receipt_sha256": "not-a-digest"}])
def test_input_does_not_coerce_enabled_or_accept_arbitrary_review_text(change):
    with pytest.raises(ValidationError):
        ops.MobileFollowTestControl(
            server_id=uuid.uuid4(),
            author_viewer_id=uuid.uuid4(),
            user_viewer_id=uuid.uuid4(),
            cohort_generation=3,
            acknowledgement=ops._ACK,
            **({"enabled": True} | change),
        )


def test_setup_and_revoke_reset_both_stale_authority_and_review_reference():
    assert ops._FOLLOW_CLOSED == {ops.ACK_KEY: "", ops.ENABLE_KEY: "false", ops._FOLLOW_REVIEW_KEY: ""}
