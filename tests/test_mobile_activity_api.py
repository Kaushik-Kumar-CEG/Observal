# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only mobile routes must not infer counts from registry presence."""

import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jsonschema
import pytest
import yaml
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.deps import get_db, get_mobile_user
from api.routes.mobile_activity import router
from models.user import UserRole

_CONTRACT = yaml.safe_load(
    (Path(__file__).resolve().parents[1] / "contracts/mobile-activity-v1/openapi.yaml").read_text()
)


def assert_wire(schema: str, payload: dict) -> None:
    jsonschema.Draft202012Validator(
        {"components": _CONTRACT["components"], "$ref": f"#/components/schemas/{schema}"}
    ).validate(payload)


@pytest.fixture
def app(monkeypatch):
    from api.routes import mobile_activity as activity

    application = FastAPI()
    application.include_router(router)
    viewer = SimpleNamespace(id=uuid.uuid4(), role=UserRole.user)
    other = SimpleNamespace(id=uuid.uuid4(), role=UserRole.user)
    db = SimpleNamespace(
        scalar=AsyncMock(return_value=other),
        scalars=AsyncMock(return_value=SimpleNamespace(all=lambda: [viewer.id, other.id])),
        execute=AsyncMock(return_value=SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: []))),
    )
    application.dependency_overrides[get_mobile_user] = lambda: viewer
    application.dependency_overrides[get_db] = lambda: db
    enabled = AsyncMock(return_value=False)
    monkeypatch.setattr(activity.ds, "get_bool", enabled)
    monkeypatch.setattr(
        activity, "_paired_window", lambda _viewer, period, _anchor: (activity._window(period), "anchor")
    )
    monkeypatch.setattr(activity, "_scope_revision", AsyncMock(return_value="revision"))
    monkeypatch.setattr(activity, "trace_union", AsyncMock(return_value=None))
    monkeypatch.setattr(activity, "trace_pair_batch", AsyncMock(return_value=({}, {})))
    monkeypatch.setattr(activity, "trace_component_page", AsyncMock(return_value=None))
    monkeypatch.setattr(activity, "prompted_roots", AsyncMock(return_value=None))
    return application, viewer, other, db, enabled


@pytest.mark.asyncio
async def test_platform_and_cross_person_restricted_before_lookup(app):
    api, viewer, other, db, enabled = app
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        platform = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
        self_author = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=author&period=1w")
        other_user = await c.get(f"/api/v1/mobile-activity/v1/people/{other.id}/summary?scope=user&period=1w")
        direct = await c.get(
            f"/api/v1/mobile-activity/v1/people/{other.id}/author/components/mcp/{uuid.uuid4()}"
            "?period=1w&window_anchor=anchor&expected_revision=revision"
        )
        batch = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            json={"subject_ids": [str(other.id)], "period": "1w"},
        )
    assert [r.status_code for r in (platform, self_author, other_user, direct, batch)] == [403] * 5
    assert all(r.content == b"" for r in (platform, self_author, other_user, direct, batch))
    db.scalar.assert_not_awaited()
    db.scalars.assert_not_awaited()
    assert enabled.await_count == 5


@pytest.mark.asyncio
async def test_self_readings_are_never_unqualified_zeros(app):
    api, viewer, other, db, enabled = app
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        response = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1m")
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "user" and body["window"]["timezone"] == "UTC"
    assert_wire("PersonSummary", body)
    for field in (
        "mcp_calls",
        "confirmed_skill_loads",
        "recorded_hook_runs",
        "component_trace_union",
        "active_days_utc",
        "general_sessions",
    ):
        assert body[field] == {
            "value": None,
            "status": "not_recorded",
            "reasons": ["unavailable"],
            "coverage": {
                "eligible_sessions": None,
                "source_start": None,
                "source_end": None,
                "supported_harnesses": [],
                "supported_kinds": [],
                "projection": "unavailable",
            },
        }


@pytest.mark.asyncio
async def test_only_positive_evidenced_mcp_metrics_can_be_partial(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    monkeypatch.setattr(
        activity,
        "trace_union",
        AsyncMock(return_value={"calls": 40, "roots": 1, "days": 1}),
    )
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        response = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w")
    assert response.status_code == 200
    body = response.json()
    assert body["mcp_calls"]["value"] == 40 and body["mcp_calls"]["status"] == "partial"
    assert body["component_trace_union"]["value"] == body["active_days_utc"]["value"] == 1
    assert body["confirmed_skill_loads"]["value"] is None
    assert body["general_sessions"]["value"] is None


@pytest.mark.asyncio
async def test_admin_platform_suppression_and_trace_privacy(app):
    api, viewer, other, db, enabled = app
    viewer.role = UserRole.admin
    enabled.return_value = True  # trace_privacy enabled
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        restricted = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
        assert restricted.status_code == 403 and restricted.content == b""
        enabled.return_value = False
        response = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
    assert response.status_code == 200
    body = response.json()
    assert body["active_accounts"] == body["prompted_root_sessions"]
    assert body["active_accounts"]["value"] is None
    assert body["window"]["end"].endswith("T00:00:00Z")
    assert body["window"]["period"] == "1w"


@pytest.mark.asyncio
async def test_small_and_purged_platform_cohorts_have_identical_redacted_metadata(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    viewer.role = UserRole.admin
    observed = AsyncMock(return_value={"active_accounts": 9, "roots": 40, "eligible_sessions": 40})
    monkeypatch.setattr(activity, "prompted_roots", observed)
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        small = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
        observed.return_value = None
        purged = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
        observed.return_value = {"active_accounts": 10, "roots": 40, "eligible_sessions": 40}
        qualified = await c.get("/api/v1/mobile-activity/v1/platform/overview?period=1w")
    assert small.status_code == purged.status_code == qualified.status_code == 200
    assert small.json()["active_accounts"] == purged.json()["active_accounts"]
    assert small.json()["prompted_root_sessions"] == purged.json()["prompted_root_sessions"]
    assert qualified.json()["active_accounts"]["value"] == 10
    assert qualified.json()["prompted_root_sessions"]["value"] == 40
    assert qualified.json()["active_accounts"]["status"] == "partial"
    for response in (small, purged, qualified):
        assert_wire("PlatformOverview", response.json())


@pytest.mark.asyncio
async def test_nested_component_wire_and_direct_id_authorization(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    component_id = uuid.uuid4()
    row = {
        "id": component_id,
        "name": "Synthetic MCP",
        "calls": 40,
        "roots": 1,
        "original_author_id": viewer.id,
        "author_username": "author",
        "author_name": "Synthetic",
    }
    monkeypatch.setattr(activity, "_paired_window", lambda *_args: (activity._window("1w"), "anchor"))
    monkeypatch.setattr(activity, "_scope_revision", AsyncMock(return_value="rev"))
    observed = AsyncMock(return_value=[row])
    monkeypatch.setattr(activity, "trace_component_page", observed)
    db.scalar.return_value = SimpleNamespace(id=viewer.id, name="Synthetic")
    base = f"/api/v1/mobile-activity/v1/people/{viewer.id}/user/components"
    suffix = "?period=1w&window_anchor=anchor&expected_revision=rev"
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        page = await c.get(f"{base}{suffix}")
        detail = await c.get(f"{base}/mcp/{component_id}{suffix}")
        skill = await c.get(f"{base}/skill/{component_id}{suffix}")
        observed.return_value = []
        unknown = await c.get(f"{base}/mcp/{uuid.uuid4()}{suffix}")
        stale = await c.get(f"{base}/mcp/{component_id}?period=1w&window_anchor=anchor&expected_revision=old")
    assert page.status_code == detail.status_code == 200
    assert skill.status_code == unknown.status_code == 404 and skill.json() == unknown.json()
    assert stale.status_code == 409
    assert_wire("ComponentPage", page.json())
    assert_wire("ComponentDetail", detail.json())
    assert page.json()["items"][0] == detail.json()["component"]


@pytest.mark.asyncio
async def test_paired_author_and_user_are_independent_root_unions_in_one_batch(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    viewer.role = UserRole.admin
    observed = AsyncMock(return_value=({viewer.id: {"roots": 10000}}, {viewer.id: {"roots": 4000}}))
    monkeypatch.setattr(activity, "trace_pair_batch", observed)
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        response = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            json={"subject_ids": [str(viewer.id), str(other.id)], "period": "1w"},
        )
        enabled.return_value = True
        private = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": [str(viewer.id)], "period": "1w"}
        )
    assert response.status_code == private.status_code == 200
    body = response.json()
    assert_wire("PairedBatch", body)
    assert body["items"][0]["author_usage"]["value"] == 10000
    assert body["items"][0]["user_usage"]["value"] == 4000
    assert body["items"][1]["author_usage"]["value"] is None
    assert private.json()["items"][0]["author_usage"] == {"status": "restricted"}
    assert private.json()["items"][0]["user_usage"]["value"] == 4000
    assert observed.await_count == 2
    assert observed.await_args_list[1].kwargs["include_author"] is False


@pytest.mark.asyncio
async def test_mixed_twelve_person_batch_never_looks_up_forbidden_subjects(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    strangers = [uuid.uuid4() for _ in range(11)]
    observed = AsyncMock(return_value=({}, {viewer.id: {"roots": 4000}}))
    monkeypatch.setattr(activity, "trace_pair_batch", observed)
    ids = [str(viewer.id), *map(str, strangers)]
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        response = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": ids, "period": "1w"}
        )
        forbidden = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": ids[1:], "period": "1w"}
        )
    assert response.status_code == 200 and forbidden.status_code == 403 and forbidden.content == b""
    assert_wire("PairedBatch", response.json())
    rows = response.json()["items"]
    assert len(rows) == 12 and rows[0]["author_usage"] == {"status": "restricted"}
    assert rows[0]["author_revision"] == "restricted" and rows[0]["user_usage"]["value"] == 4000
    assert all(
        row["author_usage"] == row["user_usage"] == {"status": "restricted"}
        and row["author_revision"] == row["user_revision"] == "restricted"
        for row in rows[1:]
    )
    db.scalars.assert_not_awaited()
    observed.assert_awaited_once()
    assert observed.call_args.kwargs["include_author"] is False
    assert observed.call_args.args[1] == [viewer.id]


@pytest.mark.asyncio
async def test_deactivated_subject_and_malformed_batch_fail_closed(app):
    api, viewer, other, db, enabled = app
    db.scalar.return_value = None
    viewer.role = UserRole.admin
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        missing = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w")
        duplicate = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": [str(viewer.id)] * 2, "period": "1w"}
        )
        oversized = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            json={"subject_ids": [str(uuid.uuid4()) for _ in range(21)], "period": "1w"},
        )
    assert (missing.status_code, duplicate.status_code, oversized.status_code) == (404, 422, 422)
