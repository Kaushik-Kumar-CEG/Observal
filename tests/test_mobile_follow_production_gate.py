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
        assert "enterprise_config" in str(statement)
        assert params == {"ack": gate.ACK_KEY, "enabled": gate.ENABLE_KEY, "worker": gate.WORKER_KEY}
        assert "FOR SHARE" in str(statement) and "90 seconds" in str(statement)
        self.queries += 1
        if self.broken:
            raise ConnectionError("do not leak DB diagnostics")
        return SimpleNamespace(all=lambda: list(self.entries.items()))


@pytest.mark.parametrize("install", (None, "", "true", "0"))
def test_normal_api_does_not_register_follow_routes_by_default(monkeypatch, install):
    if install is None:
        monkeypatch.delenv(gate.ROUTE_INSTALL_ENV, raising=False)
    else:
        monkeypatch.setenv(gate.ROUTE_INSTALL_ENV, install)
    app = FastAPI()
    include_rest_routes(app)
    assert not [route for route in app.routes if route.path.startswith("/api/v1/mobile-follow-sync/v1/")]


def test_explicit_install_registers_exactly_eighteen_as_one_gated_set(monkeypatch):
    monkeypatch.setenv(gate.ROUTE_INSTALL_ENV, "1")
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
        any(
            dependency.dependency
            is (
                gate.require_activity_or_recovery
                if r.endpoint.__module__ in {"api.routes.mobile_follow_write", "api.routes.mobile_follow_browser"}
                else gate.require_operator_approval
            )
            for dependency in r.dependencies
        )
        for r in routes
    )
    assert gate.RECOVERY_ROUTES & {("POST", "/api/v1/mobile-follow-sync/v1/write-grant")}
    assert not gate.RECOVERY_ROUTES & {
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
@pytest.mark.parametrize("path", ("operations", "consent", "consent/withdraw", "removals", "removals/lookup"))
async def test_normal_mutations_marked_for_credential_and_action_checks(path):
    request = SimpleNamespace(state=SimpleNamespace(), method="POST", url=SimpleNamespace(path=path))
    await gate.require_user_verifying_mutation(request)
    assert request.state.normal_follow_router is True


@pytest.mark.asyncio
async def test_operator_acceptance_marks_browser_routes_without_supplying_action_proof():
    db = Database({gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "true", gate.WORKER_KEY: "running"})
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
    db = Database({gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "true", gate.WORKER_KEY: "running"})
    await gate.require_operator_approval(db)
    await gate.require_operator_approval(db)
    assert db.queries == 2  # No process-local/Redis cached permission after operator revocation.
