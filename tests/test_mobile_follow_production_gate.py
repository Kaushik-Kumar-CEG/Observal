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
        assert params == {"ack": gate.ACK_KEY, "enabled": gate.ENABLE_KEY}
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


def test_explicit_install_registers_exactly_seventeen_as_one_gated_set(monkeypatch):
    monkeypatch.setenv(gate.ROUTE_INSTALL_ENV, "1")
    app = FastAPI()
    include_rest_routes(app)
    routes = [route for route in app.routes if route.path.startswith("/api/v1/mobile-follow-sync/v1/")]
    assert len(routes) == 17
    assert {r.path.rsplit("/", 1)[-1] for r in routes} >= {
        "snapshot",
        "operations",
        "write-approval",
        "write-grant",
        "write-authorization",
        "consent",
    }
    assert all(
        any(dependency.dependency is gate.require_operator_approval for dependency in r.dependencies) for r in routes
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("entries", ({}, {gate.ENABLE_KEY: "true"}, {gate.ACK_KEY: gate.ACK_VALUE}))
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
    db = Database({gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "true"})
    await gate.require_operator_approval(db)
    await gate.require_operator_approval(db)
    assert db.queries == 2  # No process-local/Redis cached permission after operator revocation.
