# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Disposable phone principals cannot count or name outside test actors."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.deps import get_db, get_mobile_user
from api.routes import mobile_activity as activity
from models.user import UserRole


@pytest.mark.asyncio
async def test_disposable_principals_rechecked_under_share_locks_after_email_or_role_edit():
    from services.mobile_read_control import synthetic_principals_valid

    author, actor = uuid.uuid4(), uuid.uuid4()
    rows = [
        SimpleNamespace(id=author, email="author@example.test", role="super_admin", auth_provider="local"),
        SimpleNamespace(id=actor, email="actor@example.invalid", role="reviewer", auth_provider="local"),
    ]
    db = SimpleNamespace(execute=AsyncMock(side_effect=lambda *_args: SimpleNamespace(all=lambda: rows)))
    assert await synthetic_principals_valid(db, author, actor)
    assert "FOR SHARE" in str(db.execute.call_args.args[0])
    rows[1].email = "actor@real.example"
    assert not await synthetic_principals_valid(db, author, actor)
    rows[1].email = "actor@example.invalid"
    rows[0].role = "user"
    assert not await synthetic_principals_valid(db, author, actor)
    rows[0].role = "super_admin"
    rows[1].auth_provider = "deactivated"
    assert not await synthetic_principals_valid(db, author, actor)


@pytest.mark.asyncio
async def test_test_admin_cannot_request_third_subject_or_global_overview(monkeypatch):
    author, actor, outsider = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    viewer = SimpleNamespace(id=author, role=UserRole.super_admin)
    db = SimpleNamespace(
        scalar=AsyncMock(),
        scalars=AsyncMock(),
        execute=AsyncMock(),
    )
    values = {
        "mobile.synthetic_test_enabled": "true",
        "mobile.synthetic_test_viewer_id": str(author),
        "mobile.synthetic_test_self_user_viewer_id": str(actor),
    }
    monkeypatch.setattr(activity.ds, "get", AsyncMock(side_effect=lambda key: values.get(key, "")))
    monkeypatch.setattr(activity, "active_mobile_cohort", AsyncMock(return_value="synthetic-author"))
    app = FastAPI()
    app.include_router(activity.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_mobile_user] = lambda: viewer
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        denied = [
            await client.get(f"/api/v1/mobile-activity/v1/people/{outsider}/summary?scope=user&period=1w"),
            await client.post(
                "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": [str(outsider)], "period": "1w"}
            ),
            await client.get(
                f"/api/v1/mobile-activity/v1/people/{outsider}/user/components?period=1w&window_anchor=x&expected_revision=y"
            ),
            await client.get("/api/v1/mobile-activity/v1/platform/overview?period=1w"),
        ]
    assert all(response.status_code == 403 and response.content == b"" for response in denied)
    db.scalar.assert_not_awaited()
    db.scalars.assert_not_awaited()


@pytest.mark.asyncio
async def test_test_actor_source_sql_filter_applies_to_union_pair_and_component(monkeypatch):
    from services import mobile_activity_query as query

    monkeypatch.setattr("services.mobile_read_control.readable", AsyncMock(return_value=True))
    actor, outsider = uuid.uuid4(), uuid.uuid4()
    executed = []

    async def execute(sql, params=None):
        executed.append((str(sql), params))
        if "AS roots" in str(sql) and "GROUP BY" not in str(sql):
            return SimpleNamespace(one=lambda: SimpleNamespace(roots=0, calls=0, skill_loads=0, hook_runs=0, days=0))
        return SimpleNamespace(all=lambda: [])

    db = SimpleNamespace(execute=execute)
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    await query.trace_union(db, outsider, "author", "default", now - timedelta(days=7), now, actor_ids={actor})
    await query.trace_pair_batch(db, [outsider], actor, "default", now - timedelta(days=7), now, actor_ids={actor})
    await query.trace_component_page(db, outsider, "author", "default", now - timedelta(days=7), now, actor_ids={actor})
    statements = [(sql, params) for sql, params in executed if "AS roots" in sql]
    assert len(statements) == 3
    assert all(
        "e.user_id=ANY(CAST(:actor_ids AS uuid[]))" in sql and params["actor_ids"] == [actor]
        for sql, params in statements
    )
