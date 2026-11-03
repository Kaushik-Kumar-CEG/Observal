# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Startup permission cannot be changed by a lower-privilege administrator."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes.admin import enterprise_settings as es
from models.enterprise_config import RESTART_PENDING_KEY
from models.user import UserRole
from schemas.admin import EnterpriseConfigUpdate
from tests.test_enterprise_settings_routes import _actor, _db, _one

KEY = "deployment.seed_demo_accounts"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [UserRole.admin, UserRole.reviewer, UserRole.user])
async def test_lower_privilege_cannot_enable_or_delete_demo_policy(role):
    db = _db()
    with pytest.raises(HTTPException) as denied:
        await es.upsert_setting(KEY, EnterpriseConfigUpdate(value="true"), db, _actor(role))
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as denied:
        await es.delete_setting(KEY, db, _actor(role))
    assert denied.value.status_code == 403
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["yes", "1", "TRUE", ""])
async def test_demo_policy_rejects_implicit_or_malformed_opt_in(value):
    db = _db()
    with pytest.raises(HTTPException) as denied:
        await es.upsert_setting(KEY, EnterpriseConfigUpdate(value=value), db, _actor(UserRole.super_admin))
    assert denied.value.status_code == 422
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_super_admin_persists_policy_and_restart_marker_with_audit(monkeypatch):
    cfg = SimpleNamespace(key=KEY, value="false")
    db = _db(_one(cfg), _one(None))
    monkeypatch.setattr(es.ds, "is_externally_managed", lambda _: False)
    monkeypatch.setattr(es.ds, "invalidate", AsyncMock())
    monkeypatch.setattr(es.ds, "refresh_sync_cache", AsyncMock())
    audit = AsyncMock()
    monkeypatch.setattr(es, "emit_security_event", audit)
    result = await es.upsert_setting(KEY, EnterpriseConfigUpdate(value="true"), db, _actor(UserRole.super_admin))
    assert result.value == "true"
    db.commit.assert_awaited_once()
    marker = db.add.call_args.args[0]
    assert marker.key == RESTART_PENDING_KEY and KEY in marker.value
    audit.assert_awaited_once()
