# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Persistent configuration is explicit, server-bound, audited and never consent."""

import json
import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.routes.admin import mobile_setup as ops
from services import dynamic_settings as ds
from tests.test_mobile_follow_operator_control import fixture as operator_fixture


def fixture(monkeypatch):
    req, state, db, actor = operator_fixture(monkeypatch)
    db.scalar.side_effect = [req.server_id, True, True, "running"]
    return req, state, db, actor


def configuration(req, *, available=True, risk=False):
    permit = (
        ops.MobileFollowRiskPermission(
            author_viewer_id=req.author_viewer_id,
            user_viewer_id=req.user_viewer_id,
            cohort_generation=req.cohort_generation,
            acknowledgement=ops.RISK_ACK_VALUE,
            risk_acceptance_sha256="c" * 64,
        )
        if risk
        else None
    )
    return ops.MobileFollowConfiguration(server_id=req.server_id, available=available, risk_permission=permit)


def test_absent_configuration_and_seeding_policy_default_off():
    assert ds.DEFAULTS[ops.AVAILABILITY_KEY] == "false"
    assert ds.DEFAULTS[ops.RISK_PERMISSION_KEY] == ""
    assert ds.DEFAULTS["deployment.seed_demo_accounts"] == "false"


@pytest.mark.asyncio
async def test_availability_configuration_is_durable_but_issues_no_authority(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    events = []
    ops._write.side_effect = lambda *_: events.append("write")
    ops._record_transition.side_effect = lambda *_: events.append("audit")
    db.commit.side_effect = lambda: events.append("commit")
    await ops.mobile_test_configure(configuration(req), db, actor)
    assert events == ["write", "audit", "commit"]
    assert ops._write.await_args.args[1] == {ops.AVAILABILITY_KEY: "true"}
    assert ops._record_transition.await_args.args[2] == "follow_cfg_open"
    assert db.scalar.await_count == 2


@pytest.mark.asyncio
async def test_separate_risk_arm_records_exact_scope_without_opening_following(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    await ops.mobile_test_configure(configuration(req, risk=True), db, actor)
    changes = ops._write.await_args.args[1]
    assert set(changes) == {ops.AVAILABILITY_KEY, ops.RISK_PERMISSION_KEY}
    assert json.loads(changes[ops.RISK_PERMISSION_KEY]) == {
        "server_id": str(req.server_id),
        "author_viewer_id": str(req.author_viewer_id),
        "user_viewer_id": str(req.user_viewer_id),
        "cohort_generation": req.cohort_generation,
        "risk_acceptance_sha256": "c" * 64,
    }
    assert ops._record_transition.await_args.args[2] == "follow_risk_arm"
    assert ops._record_transition.await_args.args[3].follow_sync_review_sha256 is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "server",
        "live",
        "revoking",
        "active",
        "clock",
        "worker",
        "expired",
        "closed",
        "pair",
        "generation",
        "people",
        "ack",
    ],
)
async def test_unsafe_configure_or_risk_arm_never_writes(monkeypatch, failure):
    req, state, db, actor = fixture(monkeypatch)
    config = configuration(req, risk=True)
    if failure == "server":
        config.server_id = uuid.uuid4()
    elif failure == "live":
        ops._status.return_value = state.model_copy(update={"trace_headlines": True})
    elif failure == "revoking":
        ops._status.return_value = state.model_copy(update={"revocation_pending": True})
    elif failure == "active":
        ops._settings.return_value[ops.ENABLE_KEY] = "true"
    elif failure == "clock":
        db.scalar.side_effect = [req.server_id, False]
    elif failure == "worker":
        db.scalar.side_effect = [req.server_id, True, True, "stale"]
    elif failure == "expired":
        db.scalar.side_effect = [req.server_id, True, False]
    elif failure == "closed":
        ops._status.return_value = state.model_copy(update={"blocked": True})
    elif failure == "pair":
        config.risk_permission.author_viewer_id = uuid.uuid4()
    elif failure == "generation":
        config.risk_permission.cohort_generation += 1
    elif failure == "people":
        ops.synthetic_principals_valid.return_value = False
    elif failure == "ack":
        config.risk_permission.acknowledgement = ""
    with pytest.raises(HTTPException):
        await ops.mobile_test_configure(config, db, actor)
    ops._write.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_disable_closes_activity_without_destroying_bounded_recovery(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    await ops.mobile_test_configure(configuration(req, available=False), db, actor)
    assert ops._write.await_args.args[1] == {ops.AVAILABILITY_KEY: "false", ops.ENABLE_KEY: "false"}
    assert db.scalar.await_count == 1


@pytest.mark.asyncio
async def test_no_permission_arm_while_disabled_or_audit_failure_commit(monkeypatch):
    req, _, db, actor = fixture(monkeypatch)
    with pytest.raises(HTTPException):
        await ops.mobile_test_configure(configuration(req, available=False, risk=True), db, actor)
    ops._write.assert_not_awaited()
    ops._record_transition.side_effect = RuntimeError("audit unavailable")
    db.scalar.side_effect = [req.server_id, True]
    with pytest.raises(RuntimeError):
        await ops.mobile_test_configure(configuration(req), db, actor)
    db.commit.assert_not_awaited()


def test_configuration_boolean_never_coerces_text():
    with pytest.raises(ValidationError):
        ops.MobileFollowConfiguration(server_id=uuid.uuid4(), available="true")
