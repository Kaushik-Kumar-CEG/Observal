# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Normal installed routes keep privacy recovery open after activity shutdown."""

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import jwt
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from api.deps import get_db
from api.routes import mobile_follow_write as write
from routes import include_rest_routes
from services import mobile_follow_auth as auth
from services import mobile_follow_enablement as gate

ROOT = "/api/v1/mobile-follow-sync/v1"


class Database:
    def __init__(self, entries):
        self.entries = entries
        self.gate_queries = 0

    async def execute(self, statement, params):
        assert "enterprise_config" in str(statement)
        self.gate_queries += 1
        return SimpleNamespace(all=lambda: list(self.entries.items()))

    async def commit(self):
        pass

    async def rollback(self):
        pass


@pytest.mark.parametrize("failure", ["operator_off", "worker_lost"])
def test_installed_privacy_recovery_does_not_require_activity_gate(monkeypatch, failure):
    monkeypatch.setenv(gate.ROUTE_INSTALL_ENV, "1")
    entries = {gate.ACK_KEY: gate.ACK_VALUE, gate.ENABLE_KEY: "true", gate.WORKER_KEY: "running"}
    entries[gate.ENABLE_KEY if failure == "operator_off" else gate.WORKER_KEY] = (
        "false" if failure == "operator_off" else "stale"
    )
    db = Database(entries)
    owner, server, withdrawal, removal, browser_withdrawal = (uuid.uuid4() for _ in range(5))
    now = int(datetime.now(UTC).timestamp())
    calls = []
    cohort_enabled = True
    account_enabled = True

    def token(value):
        assert value == "phone-write"
        return dict(
            type="follow-write",
            browser_action_epoch=1,
            aud=auth.AUDIENCE,
            scope=auth.SCOPE,
            client_id=auth.MOBILE_CLIENT_ID,
            device_id="device",
            owner_generation=1,
            iat=now,
            iat_us=now * 1_000_000,
            exp=now + 60,
            project_id=auth.PROJECT,
            server_id=str(server),
            sub=str(owner),
            cohort="live",
        )

    async def account(payload, db, *, device_id):
        calls.append(("account", device_id))
        if not account_enabled:
            raise HTTPException(401, "Revoked credential")
        return SimpleNamespace(id=owner)

    async def identity(db):
        return server

    async def cohort(db, user, server_id):
        calls.append(("cohort", user.id))
        if not cohort_enabled:
            raise HTTPException(403, "Follow cohort unavailable")
        return "live"

    async def partition(db, user, server_id, cohort_name, *, exclusive=False, create=False):
        calls.append(("partition", exclusive))
        return SimpleNamespace(owner_generation=1, consent_state="available", removal_state="none")

    async def admitted(db, key, **kwargs):
        calls.append(("admit", kwargs["kind"]))
        assert key.owner_id == owner and key.cohort == "live"
        return dict(
            action_id=str(kwargs["action_id"]), status="pending", owner_generation=2, recovery_mode="state_only"
        )

    async def status(db, key, action_id, *, kind):
        calls.append(("status", kind))
        if action_id not in (withdrawal, removal, browser_withdrawal):
            raise write.store.StoreFenceError("unknown")
        assert key.owner_id == owner
        return dict(action_id=str(action_id), status="pending", owner_generation=2, recovery_mode="state_only")

    async def lookup(db, key, **kwargs):
        calls.append(("lookup", key.owner_id))
        return dict(action_id=str(removal), status="pending", owner_generation=2, recovery_mode="nonce_lookup_90d")

    def browser_token(value, *, allow_mobile=False):
        if value == "web":
            return {"sub": str(owner), "type": "access"}
        raise jwt.InvalidTokenError("not a browser token")

    async def locked_partition(db, key, *, create=False):
        calls.append(("browser_partition", key.owner_id))

    monkeypatch.setattr(write, "decode_access_token", browser_token)
    monkeypatch.setattr(write.settings, "get_sync", lambda key: "https://observal.example")
    monkeypatch.setattr(write.store, "locked_partition", locked_partition)

    def read_token(value, *, allow_mobile=False):
        if value != "phone-read" or not allow_mobile:
            raise jwt.InvalidTokenError("not a phone read token")
        return dict(
            client_id=auth.MOBILE_CLIENT_ID, aud=auth.MOBILE_AUDIENCE, scope=auth.MOBILE_SCOPE, device_id="device"
        )

    monkeypatch.setattr(auth, "decode_access_token", read_token)
    monkeypatch.setattr(auth, "verify_token", token)
    monkeypatch.setattr(auth, "_account", account)
    monkeypatch.setattr(auth, "_identity", identity)
    monkeypatch.setattr(auth, "_cohort", cohort)
    monkeypatch.setattr(auth, "_partition", partition)
    monkeypatch.setattr(write.privacy, "admit_privacy_action", admitted)
    monkeypatch.setattr(write.privacy, "privacy_status", status)
    monkeypatch.setattr(write.privacy, "removal_by_nonce", lookup)
    # Status path rechecks owner/cohort and takes the exclusive partition lock.
    app = FastAPI()
    include_rest_routes(app)

    async def session():
        yield db

    app.dependency_overrides[get_db] = session
    with TestClient(app) as client:
        body = {"confirm": True, "withdrawal_id": str(withdrawal), "owner_generation": 1}
        response = client.post(ROOT + "/consent/withdraw", json=body, headers={"Authorization": "Bearer phone-write"})
        assert response.status_code == 202, (response.json(), calls)
        browser_headers = {"Authorization": "Bearer web", "Origin": "https://observal.example"}
        assert (
            client.post(
                ROOT + "/consent/withdraw",
                json={**body, "withdrawal_id": str(browser_withdrawal)},
                headers=browser_headers,
            ).status_code
            == 202
        )
        assert (
            client.get(
                ROOT + f"/consent/withdrawals/{browser_withdrawal}",
                headers={"Authorization": "Bearer web"},
            ).status_code
            == 200
        )
        for path in (f"/consent/withdrawals/{withdrawal}", f"/removals/{removal}"):
            assert client.get(ROOT + path, headers={"Authorization": "Bearer phone-read"}).status_code == 200
        assert (
            client.post(
                ROOT + "/removals/lookup",
                json={"nonce": "n" * 24, "original_owner_generation": 1},
                headers={"Authorization": "Bearer phone-read"},
            ).status_code
            == 200
        )
        for path in (f"/consent/withdrawals/{withdrawal}", f"/removals/{removal}"):
            assert client.get(ROOT + path).status_code == 401
        cohort_enabled = False
        assert (
            client.get(ROOT + f"/removals/{removal}", headers={"Authorization": "Bearer phone-read"}).status_code == 403
        )
        cohort_enabled = True
        account_enabled = False
        assert (
            client.post(
                ROOT + "/consent/withdraw", json=body, headers={"Authorization": "Bearer phone-write"}
            ).status_code
            == 401
        )
        assert (
            client.get(
                ROOT + f"/consent/withdrawals/{withdrawal}", headers={"Authorization": "Bearer phone-read"}
            ).status_code
            == 401
        )
        account_enabled = True
        assert (
            client.get(
                ROOT + f"/consent/withdrawals/{uuid.uuid4()}", headers={"Authorization": "Bearer phone-read"}
            ).status_code
            == 404
        )
        assert client.post(ROOT + "/consent/withdraw", json=body).status_code == 401
        for path in ("/consent", "/operations", "/removals", "/removals/prepare"):
            # The frozen write error wrapper reports an unavailable error for
            # an operator 404; either way the handler must never run.
            assert client.post(ROOT + path).status_code in (404, 503)
        for path in ("/availability", "/snapshot", "/operations/" + str(uuid.uuid4())):
            assert client.get(ROOT + path).status_code == 404
    assert ("browser_partition", owner) in calls
    assert ("admit", "withdrawal") in calls
    assert ("status", "withdrawal") in calls and ("status", "removal") in calls
    assert ("lookup", owner) in calls
    assert ("partition", True) in calls and ("cohort", owner) in calls
    assert db.gate_queries >= 7


def test_uninstalled_recovery_paths_are_404(monkeypatch):
    monkeypatch.delenv(gate.ROUTE_INSTALL_ENV, raising=False)
    app = FastAPI()
    include_rest_routes(app)
    with TestClient(app) as client:
        for method, path in (
            ("post", "/consent/withdraw"),
            ("get", "/consent/withdrawals/" + str(uuid.uuid4())),
            ("post", "/removals/lookup"),
            ("get", "/removals/" + str(uuid.uuid4())),
        ):
            assert getattr(client, method)(ROOT + path).status_code == 404
