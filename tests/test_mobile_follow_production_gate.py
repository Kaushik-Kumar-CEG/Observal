# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Normal API installs all follow routes only behind explicit dual approval."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException

from routes import include_rest_routes
from services import mobile_follow_enablement as gate


class Database:
    def __init__(self, entries=None, broken=False):
        self.entries = entries or {}
        self.broken = broken
        self.queries = 0

    async def execute(self, statement, params):
        if "pg_advisory_xact_lock_shared" in str(statement):
            assert params == {"key": "mobile-read:default"}
            self.barrier_taken = True
            return None
        assert self.barrier_taken, "project lock must precede config row locks"
        assert "enterprise_config" in str(statement)
        assert params == {
            "ack": gate.ACK_KEY,
            "enabled": gate.ENABLE_KEY,
            "worker": gate.WORKER_KEY,
            "available": gate.AVAILABILITY_KEY,
        }
        assert "FOR SHARE" in str(statement) and "90 seconds" in str(statement)
        self.queries += 1
        if self.broken:
            raise ConnectionError("do not leak DB diagnostics")
        return SimpleNamespace(all=lambda: list(self.entries.items()))


@pytest.mark.parametrize("install", (None, "", "true", "0", "1"))
def test_normal_api_registers_guarded_shapes_independent_of_obsolete_environment(monkeypatch, install):
    if install is None:
        monkeypatch.delenv("OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL", raising=False)
    else:
        monkeypatch.setenv("OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL", install)
    app = FastAPI()
    include_rest_routes(app)
    routes = [route for route in app.routes if route.path.startswith("/api/v1/mobile-follow-sync/v1/")]
    assert len(routes) == 18
    assert all(any(d.dependency is gate.require_activity_or_recovery for d in r.dependencies) for r in routes)


def test_explicit_install_registers_exactly_eighteen_as_one_gated_set(monkeypatch):
    monkeypatch.delenv("OBSERVAL_FOLLOW_SYNC_V105_ROUTE_INSTALL", raising=False)
    app = FastAPI()
    include_rest_routes(app)
    routes = [route for route in app.routes if route.path.startswith("/api/v1/mobile-follow-sync/v1/")]
    assert len(routes) == 18
    assert {r.path.rsplit("/", 1)[-1] for r in routes} >= {
        "snapshot",
        "operations",
        "write-approval",
        "write-grant",
        "write-authorization",
        "browser-action-challenge",
        "consent",
    }
    assert all(
        any(dependency.dependency is gate.require_activity_or_recovery for dependency in route.dependencies)
        for route in routes
    )
    assert gate.RECOVERY_ROUTES & {
        ("POST", "/api/v1/mobile-follow-sync/v1/write-grant"),
        ("GET", "/api/v1/mobile-follow-sync/v1/operations/{operation_id}"),
    }
    assert not gate.RECOVERY_ROUTES & {
        ("GET", "/api/v1/mobile-follow-sync/v1/snapshot"),
        ("GET", "/api/v1/mobile-follow-sync/v1/export"),
        ("GET", "/api/v1/mobile-follow-sync/v1/changes"),
        ("GET", "/api/v1/mobile-follow-sync/v1/availability"),
        ("GET", "/api/v1/mobile-follow-sync/v1/consent/state"),
        ("POST", "/api/v1/mobile-follow-sync/v1/write-authorization"),
        ("POST", "/api/v1/mobile-follow-sync/v1/write-approval"),
        ("POST", "/api/v1/mobile-follow-sync/v1/operations"),
    }
    browser_routes = [
        r
        for r in routes
        if r.path.rsplit("/", 1)[-1]
        in {"write-authorization", "write-approval", "write-grant", "browser-action-challenge"}
    ]
    assert len(browser_routes) == 4
    assert all(
        any(d.dependency is gate.require_user_verifying_approval for d in r.dependencies) for r in browser_routes
    )
    assert all(
        not any(d.dependency is gate.require_user_verifying_approval for d in r.dependencies)
        for r in routes
        if r not in browser_routes
    )
    assert all(
        any(d.dependency is gate.require_user_verifying_mutation for d in r.dependencies)
        for r in routes
        if r.path.endswith(("/operations", "/consent", "/consent/withdraw", "/removals"))
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "path", "admitted"),
    [
        ("GET", "/api/v1/mobile-follow-sync/v1/operations/{operation_id}", True),
        ("POST", "/api/v1/mobile-follow-sync/v1/operations/{operation_id}", False),
        *[
            ("GET", "/api/v1/mobile-follow-sync/v1/" + path, False)
            for path in ("availability", "consent/state", "snapshot", "export", "changes")
        ],
    ],
)
async def test_operator_closure_only_admits_same_owner_status_path_to_independent_auth(method, path, admitted):
    # The actual endpoint still independently checks the mobile credential,
    # current cohort, owner partition and privacy/erasure fences.
    db = Database({gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "false", gate.WORKER_KEY: "running"})
    request = SimpleNamespace(method=method, scope={"route": SimpleNamespace(path=path)})
    if admitted:
        await gate.require_activity_or_recovery(request, db)
        assert db.queries == 1
    else:
        with pytest.raises(HTTPException) as denied:
            await gate.require_activity_or_recovery(request, db)
        assert denied.value.status_code == 404
        assert db.queries == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entries", "broken", "expected"),
    [
        ({gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "false", gate.WORKER_KEY: "stale"}, False, 404),
        ({gate.ENABLE_KEY: "false", gate.WORKER_KEY: "running"}, False, 404),
        ({gate.ACK_KEY: gate.ACK_VALUE, gate.WORKER_KEY: "running"}, False, 404),
        ({}, True, 503),
    ],
)
async def test_status_recovery_rejects_worker_loss_missing_approval_or_db_failure(entries, broken, expected):
    db = Database(entries, broken=broken)
    request = SimpleNamespace(method="GET", scope={"route": SimpleNamespace(path=gate.STATUS_RECOVERY_ROUTE[1])})
    with pytest.raises(HTTPException) as denied:
        await gate.require_activity_or_recovery(request, db)
    assert denied.value.status_code == expected
    assert db.queries == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("operations", "consent", "consent/withdraw", "removals", "removals/lookup"))
async def test_normal_mutations_marked_for_credential_and_action_checks(path):
    request = SimpleNamespace(state=SimpleNamespace(), method="POST", url=SimpleNamespace(path=path))
    await gate.require_user_verifying_mutation(request)
    assert request.state.normal_follow_router is True


@pytest.mark.asyncio
async def test_operator_acceptance_marks_browser_routes_without_supplying_action_proof():
    db = Database(
        {
            gate.ACK_KEY: gate.ACK_VALUE,
            gate.ENABLE_KEY: "true",
            gate.WORKER_KEY: "running",
            gate.AVAILABILITY_KEY: "true",
        }
    )
    await gate.require_operator_approval(db)
    request = SimpleNamespace(state=SimpleNamespace())
    await gate.require_user_verifying_approval(request)
    assert request.state.normal_follow_router is True
    assert db.queries == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entries",
    (
        {},
        {gate.ENABLE_KEY: "true"},
        {gate.ACK_KEY: gate.ACK_VALUE},
        {gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "true"},
    ),
)
async def test_missing_approval_or_missing_operator_switch_stays_closed(entries):
    db = Database(entries)
    with pytest.raises(HTTPException) as denied:
        await gate.require_operator_approval(db)
    assert denied.value.status_code == 404
    assert db.queries == 1


@pytest.mark.asyncio
async def test_fresh_db_loss_fails_closed_without_disclosing_dsn():
    db = Database(broken=True)
    with pytest.raises(HTTPException) as denied:
        await gate.require_operator_approval(db)
    assert denied.value.status_code == 503
    assert denied.value.headers == {"Retry-After": "1"}
    assert "do not leak" not in str(denied.value.detail)


@pytest.mark.asyncio
async def test_only_both_exact_owner_and_operator_decisions_allow_request():
    db = Database(
        {
            gate.ACK_KEY: gate.ACK_VALUE,
            gate.ENABLE_KEY: "true",
            gate.WORKER_KEY: "running",
            gate.AVAILABILITY_KEY: "true",
        }
    )
    await gate.require_operator_approval(db)
    await gate.require_operator_approval(db)
    assert db.queries == 2  # No process-local/Redis cached permission after operator revocation.
