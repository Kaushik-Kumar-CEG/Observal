# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.deps import get_current_user, get_db
from api.routes import mobile
from models.user import UserRole
from services import mobile_usage
from services.dynamic_settings import DEFAULTS, settings_schema


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({}, {"value": None, "state": "not_recorded"}),
        ({"complete": 2, "observed": 0}, {"value": 0, "state": "complete"}),
        ({"complete": 2, "observed": 1, "unknown": 1}, {"value": 1, "state": "partial"}),
    ],
)
def test_honest_metric_states(row, expected):
    assert mobile_usage.metric(row) == expected


def test_union_reuses_actual_publication_and_scoped_source_sql():
    end = datetime.now(UTC)
    ids = [("mcp", str(uuid4())), ("skill", str(uuid4())), ("hook", str(uuid4()))]
    sql, params = mobile_usage.union_sql(ids, "project", (end - timedelta(days=7), end), ["actor"])
    assert "uniqExactIf((user_id, harness, session_id), observed)" in sql
    assert sql.count(" UNION ALL ") == 2
    assert "countIf(status = 'failed') = 0" in sql
    assert "s.revision != p.source_revision" in sql
    assert "identity_conflict" in sql
    assert "confirmed_loads > 0 OR invocations > 0" in sql
    assert "hook_context" in sql
    assert "'actor'" not in sql
    for i, (_, identifier) in enumerate(ids):
        assert params[f"param_component_id_{i}"] == identifier
        assert params[f"param_mobile_users_{i}"] == "['actor']"
        assert f"{{component_id_{i}:String}}" in sql


def test_switch_off_default_and_registered():
    assert DEFAULTS["mobile.enabled"] == "false"
    assert any(item["key"] == "mobile.enabled" for section in settings_schema() for item in section["settings"])


@pytest.fixture
def api(monkeypatch):
    actor = SimpleNamespace(id=uuid4(), name="Actor", username=None, role=UserRole.user, _trace_privacy=False)
    app = FastAPI()
    app.include_router(mobile.router)
    db = SimpleNamespace(get=AsyncMock(return_value=actor))
    app.dependency_overrides[get_current_user] = lambda: actor
    app.dependency_overrides[get_db] = lambda: db
    enabled = AsyncMock(return_value=True)
    query = AsyncMock(return_value={"value": 2, "state": "complete"})
    component = {"type": "mcp", "id": str(uuid4()), "name": "Probe", "author": mobile.person(actor)}
    monkeypatch.setattr(mobile, "get_bool", enabled)
    monkeypatch.setattr(mobile, "components", AsyncMock(return_value=[component]))
    monkeypatch.setattr(mobile, "is_deleted_account", lambda _: False)
    monkeypatch.setattr(mobile, "usage", query)
    return SimpleNamespace(
        client=TestClient(app), actor=actor, db=db, enabled=enabled, query=query, component=component
    )


def test_disabled_and_unauthenticated_never_query(api):
    api.enabled.return_value = False
    response = api.client.get(f"/api/v1/mobile/people/{api.actor.id}/summary")
    assert response.status_code == 403
    assert response.json()["detail"] == "Mobile access is off"
    api.query.assert_not_awaited()
    assert api.client.get("/api/v1/mobile/capabilities").json()["enabled"] is False


@pytest.mark.parametrize(
    ("role", "private", "allowed"),
    [
        (UserRole.user, False, False),
        (UserRole.reviewer, False, False),
        (UserRole.admin, True, False),
        (UserRole.admin, False, True),
        (UserRole.super_admin, True, True),
    ],
)
def test_viewing_matrix_on_every_metric_route(api, role, private, allowed):
    api.actor.role, api.actor._trace_privacy = role, private
    target = uuid4()
    for path in [
        f"/people/{target}/summary",
        f"/people/{target}/components?scope=author",
        f"/people/{target}/components/mcp/{api.component['id']}?scope=user",
    ]:
        response = api.client.get("/api/v1/mobile" + path)
        assert response.status_code == (200 if allowed else 403), response.text
    if not allowed:
        api.query.assert_not_awaited()
        api.db.get.assert_not_awaited()


def test_author_contributing_users_are_scoped_and_user_is_subject(api):
    response = api.client.get(f"/api/v1/mobile/people/{api.actor.id}/summary")
    assert response.status_code == 200, response.text
    assert all(call.args[3] == [str(api.actor.id)] for call in api.query.await_args_list)
    # Both metrics use exactly one time window for this response.
    assert api.query.await_args_list[0].args[2] == api.query.await_args_list[1].args[2]


def test_telemetry_failure_is_503_never_zero(api):
    api.query.side_effect = RuntimeError("ClickHouse unavailable")
    response = api.client.get(f"/api/v1/mobile/people/{api.actor.id}/summary")
    assert response.status_code == 503
    assert "value" not in response.json()


def test_bounds_and_ids_rejected_before_telemetry(api):
    for suffix in [
        "/people/not-uuid/summary",
        f"/people/{api.actor.id}/summary?days=0",
        f"/people/{api.actor.id}/components?scope=bad",
    ]:
        assert api.client.get("/api/v1/mobile" + suffix).status_code == 422
    api.query.assert_not_awaited()
