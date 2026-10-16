# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only mobile routes must not infer counts from registry presence."""

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jsonschema
import pytest
import yaml
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from api.deps import get_db, get_mobile_user
from api.routes.mobile_activity import router
from models.user import UserRole
from services.crypto import init_key_manager

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
    monkeypatch.setattr(activity, "qualified_zero_subset", AsyncMock(return_value=None))
    monkeypatch.setattr(activity, "trace_pair_batch", AsyncMock(return_value=({}, {})))
    monkeypatch.setattr(activity, "trace_component_page", AsyncMock(return_value=None))
    monkeypatch.setattr(activity, "prompted_roots", AsyncMock(return_value=None))
    return application, viewer, other, db, enabled


@pytest.mark.asyncio
async def test_signed_revision_and_component_keyset_fit_wire_bounds_and_bind_scope(tmp_path):
    from api.routes import mobile_activity as activity

    init_key_manager(key_dir=str(tmp_path / "keys"), key_password=None)
    viewer = SimpleNamespace(id=uuid.uuid4())
    subject = uuid.uuid4()
    db = SimpleNamespace(scalar=AsyncMock(side_effect=[10**20] * 6))
    anchor = "x" * 413
    author = await activity._scope_revision(db, viewer, subject, "author", anchor)
    same_author = await activity._scope_revision(db, viewer, subject, "author", anchor)
    user = await activity._scope_revision(db, viewer, subject, "user", anchor)
    assert author == same_author and author != user
    other_viewer_db = SimpleNamespace(scalar=AsyncMock(side_effect=[10**20, 10**20]))
    assert author != await activity._scope_revision(
        other_viewer_db, SimpleNamespace(id=uuid.uuid4()), subject, "author", anchor
    )
    assert len(author) <= 512 and len(user) <= 512
    binding = activity._page_binding(viewer, subject, "author", anchor, author)
    cursor = activity._cursor({**binding, "last_roots": 10000, "last_id": str(uuid.uuid4())})
    assert len(cursor) <= 512
    with pytest.raises(HTTPException) as exc:
        activity._read_cursor(cursor, activity._page_binding(viewer, subject, "user", anchor, user))
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_published_keyset_pages_use_same_viewer_and_latest_approval(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, _other, db, _enabled = app
    values = [
        {"kind": "mcp", "id": uuid.uuid4(), "name": "A", "namespace": "s", "slug": "a", "is_current_owner": True},
        {"kind": "skill", "id": uuid.uuid4(), "name": "B", "namespace": "s", "slug": "b", "is_current_owner": False},
    ]
    monkeypatch.setattr(activity, "sign_token", lambda claims: json.dumps(claims))
    monkeypatch.setattr(activity, "verify_token", json.loads)

    async def execute(sql, params):
        assert ":last_kind" in str(sql) or "last_kind" not in params
        assert "ORDER BY e.recorded_at DESC,e.id DESC" in str(sql)
        assert "l.is_private = false" in str(sql)
        assert params["viewer"] == viewer.id
        after = params.get("last_kind")
        candidates = [v for v in values if after is None or (v["kind"], v["id"]) > (after, params["last_id"])]
        return SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: candidates[: params["limit"]]))

    db.execute.side_effect = execute
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        first = await c.get("/api/v1/mobile-activity/v1/published?limit=1")
        assert first.status_code == 200, first.text
        assert_wire("PublishedPage", first.json())
        assert len(first.json()["items"]) == 1 and not first.json()["complete"]
        cursor = first.json()["next_cursor"]
        second = await c.get("/api/v1/mobile-activity/v1/published", params={"limit": 1, "cursor": cursor})
        assert second.status_code == 200 and second.json()["complete"] and not second.json()["next_cursor"]
        assert first.json()["items"][0]["id"] != second.json()["items"][0]["id"]
        forged = json.loads(cursor)
        forged["sub"] = str(uuid.uuid4())
        denied = await c.get("/api/v1/mobile-activity/v1/published", params={"limit": 1, "cursor": json.dumps(forged)})
        assert denied.status_code == 409


@pytest.mark.asyncio
async def test_synthetic_capability_requires_exact_server_viewer_ack_and_unblocked_read(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, _other, db, _enabled = app
    viewer.role = UserRole.super_admin
    server = uuid.uuid4()
    db.scalar.return_value = server
    settings = {
        "mobile.synthetic_test_ack": "isolated-disposable-synthetic-only-v1",
        "mobile.synthetic_test_server_id": str(server),
        "mobile.synthetic_test_viewer_id": str(viewer.id),
    }
    monkeypatch.setattr(activity.ds, "get", AsyncMock(side_effect=lambda key: settings.get(key, "")))
    states = {"mobile.auth_enabled": True, "mobile.synthetic_test_enabled": True}
    monkeypatch.setattr(activity.ds, "get_bool", AsyncMock(side_effect=lambda key: states.get(key, False)))
    barrier = AsyncMock(return_value=False)
    monkeypatch.setattr(activity, "readable", barrier)
    observed = AsyncMock(return_value={"roots": 1, "calls": 40, "days": 1})
    monkeypatch.setattr(activity, "trace_union", observed)
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        closed = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert closed.json()["synthetic_test_cohort"] is False
        assert_wire("Capabilities", closed.json())
        barrier.return_value = True
        opened = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert opened.json()["synthetic_test_cohort"] is True
        assert opened.json()["trace_headlines"] is False
        assert opened.json()["supported_kinds"] == ["mcp_calls"]
        assert_wire("Capabilities", opened.json())
        observed.return_value = {"roots": 1, "calls": 1, "skill_loads": 1, "hook_runs": 1, "days": 1}
        mixed = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert mixed.json()["supported_kinds"] == ["mcp_calls", "confirmed_skill_loads", "recorded_hook_runs"]
        assert_wire("Capabilities", mixed.json())
        observed.return_value = {"roots": 1, "calls": 0, "skill_loads": 1, "hook_runs": 0, "days": 1}
        skill_only = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert skill_only.json()["synthetic_test_cohort"] is True
        assert skill_only.json()["supported_kinds"] == ["confirmed_skill_loads"]
        observed.return_value = None
        missing_source = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert missing_source.json()["synthetic_test_cohort"] is False
        observed.return_value = {"roots": 1, "calls": 40, "days": 1}
        settings["mobile.synthetic_test_server_id"] = str(uuid.uuid4())
        wrong_server = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert wrong_server.json()["synthetic_test_cohort"] is False
        settings["mobile.synthetic_test_server_id"] = str(server)
        settings["mobile.synthetic_test_viewer_id"] = str(uuid.uuid4())
        wrong_viewer = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert wrong_viewer.json()["synthetic_test_cohort"] is False
        settings["mobile.synthetic_test_viewer_id"] = str(viewer.id)
        settings["mobile.synthetic_test_ack"] = ""
        unacknowledged = await c.get("/api/v1/mobile-activity/v1/capabilities")
        assert unacknowledged.json()["synthetic_test_cohort"] is False


@pytest.mark.asyncio
async def test_synthetic_self_user_viewer_requires_exact_identity_source_and_denies_other_scopes(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, _enabled = app
    viewer.role = UserRole.user
    server = uuid.uuid4()
    db.scalar.return_value = server
    settings = {
        "mobile.synthetic_test_ack": "isolated-disposable-synthetic-only-v1",
        "mobile.synthetic_test_server_id": str(server),
        "mobile.synthetic_test_viewer_id": str(other.id),
        "mobile.synthetic_test_self_user_viewer_id": str(viewer.id),
    }
    monkeypatch.setattr(activity.ds, "get", AsyncMock(side_effect=lambda key: settings.get(key, "")))
    monkeypatch.setattr(
        activity.ds,
        "get_bool",
        AsyncMock(side_effect=lambda key: key in {"mobile.auth_enabled", "mobile.synthetic_test_enabled"}),
    )
    monkeypatch.setattr(activity, "readable", AsyncMock(return_value=True))
    source = AsyncMock(return_value={"roots": 1, "calls": 40, "days": 1})
    monkeypatch.setattr(activity, "trace_union", source)
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as client:
        allowed = await client.get("/api/v1/mobile-activity/v1/capabilities")
        assert allowed.status_code == 200 and allowed.json()["synthetic_test_cohort"] is True
        assert allowed.json()["trace_headlines"] is False
        assert allowed.json()["supported_kinds"] == ["mcp_calls"]
        assert source.await_args.args[2] == "user"
        denied = await client.get(f"/api/v1/mobile-activity/v1/people/{other.id}/summary?scope=user&period=1w")
        assert denied.status_code == 403 and denied.content == b""
        denied = await client.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=author&period=1w")
        assert denied.status_code == 403 and denied.content == b""
        source.return_value = None
        assert (await client.get("/api/v1/mobile-activity/v1/capabilities")).json()["synthetic_test_cohort"] is False
        source.return_value = {"roots": 1, "calls": 40, "days": 1}
        settings["mobile.synthetic_test_server_id"] = str(uuid.uuid4())
        assert (await client.get("/api/v1/mobile-activity/v1/capabilities")).json()["synthetic_test_cohort"] is False
        settings["mobile.synthetic_test_server_id"] = str(server)
        settings["mobile.synthetic_test_self_user_viewer_id"] = str(uuid.uuid4())
        assert (await client.get("/api/v1/mobile-activity/v1/capabilities")).json()["synthetic_test_cohort"] is False


@pytest.mark.asyncio
async def test_paired_window_anchor_preserves_end_as_of_microseconds(tmp_path):
    from api.routes import mobile_activity as activity

    init_key_manager(key_dir=str(tmp_path / "keys"), key_password=None)
    viewer = SimpleNamespace(id=uuid.uuid4())
    initial, anchor = activity._paired_window(viewer, "1w", None)
    anchored, reused = activity._paired_window(viewer, "1w", anchor)
    assert reused == anchor
    assert anchored == initial
    assert anchored.start <= anchored.end == anchored.as_of
    assert anchored.end.microsecond != 0 or initial.end.microsecond == 0


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
async def test_blocked_paired_read_returns_no_zero_cohort_or_scope_revision(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, _db, _enabled = app
    zero = AsyncMock(return_value={"roots": 0, "calls": 0, "days": 0, "eligible_sessions": 1})
    revisions = AsyncMock(return_value="must-never-disclose")
    monkeypatch.setattr(activity, "qualified_zero_subset", zero)
    monkeypatch.setattr(activity, "_scope_revision", revisions)
    monkeypatch.setattr(activity, "readable", AsyncMock(return_value=False))
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        response = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries",
            json={"subject_ids": [str(viewer.id), str(other.id)], "period": "1w"},
        )
    assert response.status_code == 200
    assert_wire("PairedBatch", response.json())
    self_row, foreign = response.json()["items"]
    assert self_row["user_usage"]["value"] is None
    assert self_row["user_usage"]["coverage"]["eligible_sessions"] is None
    assert self_row["user_revision"] == "unqualified"
    assert self_row["author_usage"] == {"status": "restricted"}
    assert foreign["author_usage"] == foreign["user_usage"] == {"status": "restricted"}
    assert foreign["author_revision"] == foreign["user_revision"] == "restricted"
    zero.assert_not_awaited()
    revisions.assert_not_awaited()


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
async def test_only_self_verified_zero_subset_is_partial_and_other_kinds_remain_unavailable(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    zero = AsyncMock(return_value={"calls": 0, "roots": 0, "days": 0, "eligible_sessions": 1})
    monkeypatch.setattr(activity, "qualified_zero_subset", zero)
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        own = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w")
        paired = await c.post(
            "/api/v1/mobile-activity/v1/people/summaries", json={"subject_ids": [str(viewer.id)], "period": "1w"}
        )
        forbidden = await c.get(f"/api/v1/mobile-activity/v1/people/{other.id}/summary?scope=user&period=1w")
    assert own.status_code == 200
    assert own.json()["mcp_calls"]["value"] == 0
    assert own.json()["mcp_calls"]["status"] == "partial"
    assert own.json()["mcp_calls"]["coverage"]["eligible_sessions"] == 1
    assert paired.json()["items"][0]["user_usage"]["coverage"]["eligible_sessions"] == 1
    assert own.json()["confirmed_skill_loads"]["value"] is None
    assert own.json()["general_sessions"]["value"] is None
    assert forbidden.status_code == 403 and forbidden.content == b""
    assert zero.await_count == 2


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
    assert body["component_trace_union"]["coverage"]["eligible_sessions"] is None
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
    assert page.json()["items"][0]["component_traces"]["coverage"]["eligible_sessions"] is None


@pytest.mark.asyncio
async def test_permissioned_skill_detail_and_positive_only_summary_keep_other_kinds_unrecorded(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    skill_id = uuid.uuid4()
    row = {
        "kind": "skill",
        "id": skill_id,
        "name": "Synthetic skill",
        "calls": 0,
        "skill_loads": 2,
        "roots": 1,
        "original_author_id": other.id,
        "author_username": "original",
        "author_name": "Synthetic",
    }
    monkeypatch.setattr(activity, "_paired_window", lambda *_args: (activity._window("1w"), "anchor"))
    monkeypatch.setattr(activity, "_scope_revision", AsyncMock(return_value="rev"))
    monkeypatch.setattr(activity, "trace_component_page", AsyncMock(return_value=[row]))
    monkeypatch.setattr(
        activity,
        "trace_union",
        AsyncMock(
            return_value={
                "roots": 1,
                "calls": 0,
                "skill_loads": 2,
                "days": 1,
            }
        ),
    )
    monkeypatch.setattr(activity, "prompted_roots", AsyncMock(return_value=None))
    db.scalar.return_value = SimpleNamespace(id=viewer.id, name="Synthetic")
    base = f"/api/v1/mobile-activity/v1/people/{viewer.id}/user"
    suffix = "?period=1w&window_anchor=anchor&expected_revision=rev"
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        page = await c.get(f"{base}/components{suffix}")
        detail = await c.get(f"{base}/components/skill/{skill_id}{suffix}")
        mismatched = await c.get(f"{base}/components/mcp/{skill_id}{suffix}")
        summary = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w")
    assert page.status_code == detail.status_code == summary.status_code == 200
    assert mismatched.status_code == 404
    assert_wire("ComponentPage", page.json())
    assert_wire("ComponentDetail", detail.json())
    assert_wire("PersonSummary", summary.json())
    component = detail.json()["component"]
    assert component["kind"] == "skill" and component["confirmed_skill_loads"]["value"] == 2
    assert component["mcp_calls"]["value"] is None
    assert summary.json()["component_trace_union"]["value"] == 1
    assert summary.json()["confirmed_skill_loads"]["value"] == 2
    assert summary.json()["mcp_calls"]["value"] is None
    assert summary.json()["recorded_hook_runs"]["value"] is None


@pytest.mark.asyncio
async def test_hook_run_detail_stays_typed_and_silent_absence_never_becomes_zero(app, monkeypatch):
    from api.routes import mobile_activity as activity

    api, viewer, other, db, enabled = app
    hook_id = uuid.uuid4()
    hook_row = {
        "kind": "hook",
        "id": hook_id,
        "name": "Synthetic hook",
        "calls": 0,
        "skill_loads": 0,
        "hook_runs": 1,
        "roots": 1,
        "original_author_id": other.id,
        "author_username": "original",
        "author_name": "Synthetic",
    }
    monkeypatch.setattr(activity, "_paired_window", lambda *_args: (activity._window("1w"), "anchor"))
    monkeypatch.setattr(activity, "_scope_revision", AsyncMock(return_value="rev"))
    monkeypatch.setattr(activity, "trace_component_page", AsyncMock(return_value=[hook_row]))
    monkeypatch.setattr(
        activity,
        "trace_union",
        AsyncMock(
            return_value={
                "roots": 1,
                "calls": 0,
                "skill_loads": 0,
                "hook_runs": 1,
                "days": 1,
            }
        ),
    )
    monkeypatch.setattr(activity, "prompted_roots", AsyncMock(return_value=None))
    db.scalar.return_value = SimpleNamespace(id=viewer.id, name="Synthetic")
    base = f"/api/v1/mobile-activity/v1/people/{viewer.id}/user"
    suffix = "?period=1w&window_anchor=anchor&expected_revision=rev"
    async with AsyncClient(transport=ASGITransport(app=api), base_url="http://test") as c:
        detail = await c.get(f"{base}/components/hook/{hook_id}{suffix}")
        mismatched = await c.get(f"{base}/components/skill/{hook_id}{suffix}")
        summary = await c.get(f"/api/v1/mobile-activity/v1/people/{viewer.id}/summary?scope=user&period=1w")
    assert detail.status_code == summary.status_code == 200 and mismatched.status_code == 404
    assert_wire("ComponentDetail", detail.json())
    assert_wire("PersonSummary", summary.json())
    assert detail.json()["component"]["recorded_hook_runs"]["value"] == 1
    assert detail.json()["component"]["confirmed_skill_loads"]["value"] is None
    assert summary.json()["recorded_hook_runs"]["value"] == 1
    assert summary.json()["mcp_calls"]["value"] is None
    assert summary.json()["confirmed_skill_loads"]["value"] is None


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
    assert body["items"][0]["author_usage"]["coverage"]["eligible_sessions"] is None
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
