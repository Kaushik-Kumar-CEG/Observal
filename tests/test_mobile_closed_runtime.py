# SPDX-FileCopyrightText: 2026 Kaushik Kumar
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Rollback never enables new Following activity from retained settings."""

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.routes.admin import mobile_setup as ops
from services import mobile_follow_enablement as gate


@pytest.mark.asyncio
async def test_closed_bridge_cannot_admit_new_activity_or_enable_controls(monkeypatch):
    monkeypatch.setenv("OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL", "1")
    monkeypatch.setenv("OBSERVAL_FOLLOW_SYNTHETIC_RISK_INSTALL", "1")
    with pytest.raises(HTTPException) as denied:
        await gate.require_operator_approval(None)
    assert denied.value.status_code == 404
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_configure(
            ops.MobileFollowConfiguration(server_id=uuid.uuid4(), available=True), None, SimpleNamespace()
        )
    assert denied.value.status_code == 409
    with pytest.raises(HTTPException) as denied:
        await ops.mobile_test_follow_sync(
            ops.MobileFollowTestControl(
                server_id=uuid.uuid4(),
                author_viewer_id=uuid.uuid4(),
                user_viewer_id=uuid.uuid4(),
                cohort_generation=1,
                enabled=True,
                acknowledgement=ops._ACK,
                owner_decisions_acknowledgement=ops.ACK_VALUE,
                review_receipt_sha256="a" * 64,
            ),
            None,
            SimpleNamespace(),
        )
    assert denied.value.status_code == 409


def test_closed_runtime_exposes_its_policy_to_admin_status():
    status = ops.MobileTestStatus(
        blocked=True,
        generation=1,
        server_id=None,
        author_viewer_id=None,
        user_viewer_id=None,
        configured=False,
        trace_headlines=False,
    )
    assert status.follow_sync_runtime_closed is True
    assert status.follow_sync_available is False
