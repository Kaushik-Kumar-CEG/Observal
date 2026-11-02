# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Owner risk acceptance is not review and cannot authorize production."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes.admin import mobile_setup as ops
from services import mobile_follow_enablement as gate
from tests.test_mobile_follow_operator_control import fixture


def risk_req(req):
    return req.model_copy(
        update={
            "review_receipt_sha256": None,
            "owner_decisions_acknowledgement": None,
            "risk_acceptance_acknowledgement": gate.RISK_ACK_VALUE,
            "risk_acceptance_sha256": "c" * 64,
        }
    )


@pytest.mark.asyncio
async def test_risk_default_off_and_separate_durable_provenance(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    req = risk_req(req)
    monkeypatch.delenv(gate.RISK_INSTALL_ENV, raising=False)
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_follow_sync(req, db, actor)
    assert denied.value.status_code == 409
    ops._write.assert_not_awaited()
    monkeypatch.setenv(gate.RISK_INSTALL_ENV, "1")
    db.scalar.side_effect = [req.server_id, True, "running"]
    await ops.mobile_test_follow_sync(req, db, actor)
    changes = ops._write.await_args.args[1]
    assert changes[ops._FOLLOW_REVIEW_KEY] == ""
    assert changes[gate.RISK_KEY] == "c" * 64 and changes[gate.ACK_KEY] == gate.RISK_ACK_VALUE
    args = ops._record_transition.await_args.args
    assert args[2] == "follow_risk_open"
    assert args[3].follow_sync_review_sha256 is None
    assert args[3].follow_sync_risk_sha256 == "c" * 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"review_receipt_sha256": "a" * 64},
        {"owner_decisions_acknowledgement": gate.ACK_VALUE},
        {"risk_acceptance_sha256": None},
        {"risk_acceptance_acknowledgement": ""},
    ],
)
async def test_risk_cannot_impersonate_review_or_implicit_acceptance(monkeypatch, change):
    req, _, db, actor = fixture(monkeypatch)
    monkeypatch.setenv(gate.RISK_INSTALL_ENV, "1")
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_follow_sync(risk_req(req).model_copy(update=change), db, actor)
    assert denied.value.status_code == 422
    ops._write.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key,value",
    [
        ("trace_headlines", "true"),
        ("mobile.trace_qualification_ack", "approved"),
        ("mobile.trace_qualification_server_id", str(uuid.uuid4())),
        ("mobile.auth_enabled", "false"),
        ("mobile.synthetic_test_enabled", "false"),
        ("mobile.synthetic_test_viewer_id", "invalid"),
        (gate.RISK_KEY, ""),
        ("mobile.synthetic_test_ack", ""),
    ],
)
async def test_risk_gate_never_falls_back_to_live_or_invalid_scope(monkeypatch, key, value):
    monkeypatch.setenv(gate.RISK_INSTALL_ENV, "1")
    values = {
        "mobile.auth_enabled": "true",
        "mobile.synthetic_test_enabled": "true",
        "mobile.synthetic_test_ack": ops._ACK,
        "mobile.synthetic_test_server_id": str(uuid.uuid4()),
        "mobile.synthetic_test_viewer_id": str(uuid.uuid4()),
        "mobile.synthetic_test_self_user_viewer_id": str(uuid.uuid4()),
        gate.RISK_KEY: "c" * 64,
        key: value,
    }
    db = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: list(values.items()))),
        scalar=AsyncMock(return_value=True),
    )
    assert not await gate._ack_authorized(db, {gate.ACK_KEY: gate.RISK_ACK_VALUE})


@pytest.mark.asyncio
@pytest.mark.parametrize("valid_barrier,valid_people", [(False, True), (True, False), (True, True)])
async def test_risk_requires_current_expiry_server_pair_and_disposable_people(monkeypatch, valid_barrier, valid_people):
    monkeypatch.setenv(gate.RISK_INSTALL_ENV, "1")
    values = {
        "mobile.auth_enabled": "true",
        "mobile.synthetic_test_enabled": "true",
        "mobile.synthetic_test_ack": ops._ACK,
        "mobile.synthetic_test_server_id": str(uuid.uuid4()),
        "mobile.synthetic_test_viewer_id": str(uuid.uuid4()),
        "mobile.synthetic_test_self_user_viewer_id": str(uuid.uuid4()),
        gate.RISK_KEY: "c" * 64,
    }
    db = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: list(values.items()))),
        scalar=AsyncMock(side_effect=[valid_barrier, False]),
    )
    monkeypatch.setattr("services.mobile_read_control.synthetic_principals_valid", AsyncMock(return_value=valid_people))
    assert await gate._ack_authorized(db, {gate.ACK_KEY: gate.RISK_ACK_VALUE}) is (valid_barrier and valid_people)


def test_setup_and_revoke_clear_risk_authority():
    assert ops._FOLLOW_CLOSED[gate.RISK_KEY] == ""
