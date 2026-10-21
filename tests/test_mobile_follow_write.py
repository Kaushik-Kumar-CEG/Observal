# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Focused dormant write route tests; no production router registration or live DB."""

import json
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from api.deps import get_db
from api.routes import mobile_follow_write as routes
from services.mobile_follow_store import StoreFenceError

UID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class DB:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def scalar(self, statement, params):
        assert "FOR KEY SHARE" in str(statement)
        return params["subject"]


class FakeRequest(Request):
    def __init__(self, path, method, body=None):
        super().__init__(
            {
                "type": "http",
                "path": "/api/v1/mobile-follow-sync/v1/" + path,
                "method": method,
                "query_string": b"",
                "headers": [],
                "scheme": "https",
                "server": ("test", 443),
            }
        )
        self._body = json.dumps(body).encode() if body is not None else b""


P = SimpleNamespace(
    server_id=uuid.UUID(UID),
    project_id="default",
    user=SimpleNamespace(id=uuid.UUID(UID)),
    cohort="live",
    generation=7,
    device_id="phone",
)
OP = {"operation_id": UID, "subject_id": SID, "owner_generation": 7, "base_person_revision": 0, "action": "follow"}


@pytest.mark.asyncio
async def test_write_rechecks_auth_before_store(monkeypatch):
    async def deny(*args):
        raise HTTPException(401)

    async def forbidden(*args, **kwargs):
        raise AssertionError("store reached without authorization")

    monkeypatch.setattr(routes.auth, "authorize_follow_write", deny)
    monkeypatch.setattr(routes.store, "admit_operation", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes.operations(FakeRequest("operations", "POST", OP), "Bearer read", DB())
    assert err.value.detail == {"error": "unauthorized"}


@pytest.mark.asyncio
async def test_operation_historical_conflict_body_and_commit(monkeypatch):
    async def allow(*args):
        return P

    async def historical(*args, **kwargs):
        return 409, {
            "error": "person_conflict",
            "operation_id": UID,
            "owner_generation": 7,
            "revision": 3,
            "person_revision": 2,
            "current_following": True,
        }

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", historical)
    db = DB()
    result = await routes.operations(FakeRequest("operations", "POST", OP), "Bearer grant", db)
    assert result.status_code == 409
    assert json.loads(result.body) == (await historical())[1]
    assert db.commits == 2


@pytest.mark.asyncio
async def test_changed_operation_body_is_redacted(monkeypatch):
    async def allow(*args):
        return P

    async def changed(*args, **kwargs):
        raise StoreFenceError("operation_id_reused")

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", changed)
    db = DB()
    result = await routes.operations(FakeRequest("operations", "POST", OP), "Bearer grant", db)
    assert result.status_code == 409
    assert json.loads(result.body) == {"error": "operation_id_reused", "operation_id": UID, "owner_generation": 7}
    assert db.rollbacks == 1 and db.commits == 1


@pytest.mark.asyncio
async def test_subject_lock_precedes_second_write_authorization(monkeypatch):
    order = []

    class OrderedDB(DB):
        async def commit(self):
            order.append("commit")
            await super().commit()

        async def scalar(self, statement, params):
            order.append("subject")
            return await super().scalar(statement, params)

    async def allow(*args):
        order.append("auth")
        return P

    async def admitted(*args, **kwargs):
        order.append("admit")
        return 200, {"status": "applied"}

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", admitted)
    await routes.operations(FakeRequest("operations", "POST", OP), "Bearer grant", OrderedDB())
    assert order == ["auth", "commit", "subject", "auth", "admit", "commit"]


@pytest.mark.asyncio
async def test_stale_body_reports_current_generation_after_valid_grant(monkeypatch):
    async def allow(*args):
        return P

    async def conflict(*args, **kwargs):
        raise StoreFenceError("generation_conflict", owner_generation=7)

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", conflict)
    db = DB()
    result = await routes.operations(
        FakeRequest("operations", "POST", dict(OP, owner_generation=6)), "Bearer grant", db
    )
    assert (result.status_code, json.loads(result.body)) == (
        409,
        {"error": "generation_conflict", "operation_id": UID, "owner_generation": 7},
    )
    assert db.commits == 1 and db.rollbacks == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        dict(OP, owner_generation=True),
        dict(OP, base_person_revision=9007199254740992),
        dict(OP, action="read"),
        dict(OP, email="secret"),
    ],
)
async def test_invalid_operation_never_calls_store(monkeypatch, invalid):
    async def allow(*args):
        return P

    async def forbidden(*args, **kwargs):
        raise AssertionError("invalid input reached store")

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes.operations(FakeRequest("operations", "POST", invalid), "Bearer grant", DB())
    assert err.value.detail == {"error": "invalid_request"}


@pytest.mark.asyncio
async def test_withdrawal_requires_auth_not_confirmation_boolean(monkeypatch):
    async def deny(*args):
        raise HTTPException(401)

    async def forbidden(*args, **kwargs):
        raise AssertionError("privacy admission reached without auth")

    monkeypatch.setattr(routes, "_is_browser", lambda authorization: False)
    monkeypatch.setattr(routes.auth, "authorize_follow_write", deny)
    monkeypatch.setattr(routes.privacy, "admit_privacy_action", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes.withdraw(
            FakeRequest("consent/withdraw", "POST", {"confirm": True, "owner_generation": 7, "withdrawal_id": UID}),
            "Bearer read",
            DB(),
        )
    assert err.value.detail == {"error": "unauthorized"}


@pytest.mark.asyncio
async def test_pending_withdrawal_is_202_and_committed(monkeypatch):
    async def allow(*args):
        return P

    async def admit(*args, **kwargs):
        assert kwargs["body_digest"] == routes.privacy.withdrawal_body_digest(uuid.UUID(UID), 7)
        return {"action_id": UID, "owner_generation": 8, "status": "pending", "recovery_mode": "state_only"}

    monkeypatch.setattr(routes, "_is_browser", lambda authorization: False)
    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.privacy, "admit_privacy_action", admit)
    db = DB()
    result = await routes.withdraw(
        FakeRequest("consent/withdraw", "POST", {"confirm": True, "owner_generation": 7, "withdrawal_id": UID}),
        "Bearer grant",
        db,
    )
    assert result == {"withdrawal_id": UID, "owner_generation": 8, "state": "pending", "recovery_mode": "state_only"}
    assert next(r for r in routes.router.routes if r.path.endswith("/consent/withdraw")).status_code == 202
    assert db.commits == 1


@pytest.mark.parametrize("reason,expected", [("unknown", "unknown_removal"), ("expired", "unknown_removal")])
def test_lost_receipt_never_claims_completion(reason, expected):
    with pytest.raises(HTTPException) as err:
        routes._refusal(StoreFenceError(reason), kind="removal")
    assert err.value.status_code == 404 and err.value.detail == {"error": expected}


def test_isolated_asgi_wire_error_and_historical_pending(monkeypatch):
    app = FastAPI()
    app.include_router(routes.router)  # Only the isolated test app; never register in production.
    db = DB()
    app.dependency_overrides[get_db] = lambda: db

    async def deny(*args):
        raise HTTPException(401)

    monkeypatch.setattr(routes.auth, "authorize_follow_write", deny)
    with TestClient(app) as client:
        response = client.post("/api/v1/mobile-follow-sync/v1/operations", json=OP)
        assert (response.status_code, response.json()) == (401, {"error": "unauthorized"})
        response = client.post("/api/v1/mobile-follow-sync/v1/operations", content=b"{" + b"x" * 4096)
        assert (response.status_code, response.json()) == (413, {"error": "too_large"})

    async def allow(*args):
        return P

    async def changed(*args, **kwargs):
        raise StoreFenceError("operation_id_reused")

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.store, "admit_operation", changed)
    with TestClient(app) as client:
        response = client.post("/api/v1/mobile-follow-sync/v1/operations", json=OP)
        assert (response.status_code, response.json()) == (
            409,
            {"error": "operation_id_reused", "operation_id": UID, "owner_generation": 7},
        )


@pytest.mark.asyncio
async def test_remove_requires_fresh_follow_write_and_returns_pending_receipt(monkeypatch):
    async def allow(*args):
        return P

    async def admit(*args, **kwargs):
        assert kwargs["device_id"] == "phone"
        assert kwargs["nonce_digest"] == routes._nonce("n" * 32)
        assert kwargs["confirmed_authorized"] is True
        return {"action_id": UID, "owner_generation": 8, "status": "pending", "recovery_mode": "nonce_lookup_90d"}

    monkeypatch.setattr(routes.auth, "authorize_follow_write", allow)
    monkeypatch.setattr(routes.privacy, "admit_privacy_action", admit)
    db = DB()
    result = await routes.remove(
        FakeRequest("removals", "POST", {"nonce": "n" * 32, "owner_generation": 7, "confirm": True}), "Bearer grant", db
    )
    assert result == {
        "removal_id": UID,
        "owner_generation": 8,
        "state": "pending",
        "revision": 0,
        "recovery_mode": "nonce_lookup_90d",
    }
    assert db.commits == 1
    assert next(r for r in routes.router.routes if r.path.endswith("/removals")).status_code == 202


@pytest.mark.asyncio
async def test_nonce_lookup_requires_read_reproof(monkeypatch):
    async def deny(*args):
        raise HTTPException(401)

    async def forbidden(*args, **kwargs):
        raise AssertionError("nonce lookup reached without read authorization")

    monkeypatch.setattr(routes.auth, "authorize_follow_read", deny)
    monkeypatch.setattr(routes.privacy, "removal_by_nonce", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes.removal_lookup(
            FakeRequest("removals/lookup", "POST", {"nonce": "n" * 32, "original_owner_generation": 7}),
            "Bearer write",
            DB(),
        )
    assert err.value.detail == {"error": "unauthorized"}


@pytest.mark.asyncio
async def test_consent_requires_browser_even_with_true_boolean(monkeypatch):
    async def deny(*args, **kwargs):
        raise HTTPException(403)

    async def forbidden(*args, **kwargs):
        raise AssertionError("consent persisted without verified browser bearer")

    monkeypatch.setattr(routes, "_browser", deny)
    monkeypatch.setattr(routes.privacy, "accept_consent", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes.consent(
            FakeRequest("consent", "POST", {"consent": True, "owner_generation": 7, "consent_id": UID}),
            "Bearer mobile-read",
            DB(),
        )
    assert err.value.status_code == 403


@pytest.mark.asyncio
async def test_browser_consent_rejects_missing_origin_before_account_access(monkeypatch):
    monkeypatch.setattr(routes.settings, "get_sync", lambda name: "https://issuer.test")

    async def forbidden(*args, **kwargs):
        raise AssertionError("account reached before same-issuer browser proof")

    monkeypatch.setattr(routes.auth, "_account", forbidden)
    with pytest.raises(HTTPException) as err:
        await routes._browser(FakeRequest("consent", "POST"), "Bearer ordinary", DB(), consent=True)
    assert err.value.detail == {"error": "restricted"}


def test_exact_eight_unregistered_routes():
    assert {(next(iter(r.methods)), r.path.removeprefix(routes.router.prefix)) for r in routes.router.routes} == {
        ("POST", "/operations"),
        ("POST", "/consent"),
        ("POST", "/consent/withdraw"),
        ("GET", "/consent/withdrawals/{withdrawal_id}"),
        ("POST", "/removals/prepare"),
        ("POST", "/removals"),
        ("POST", "/removals/lookup"),
        ("GET", "/removals/{removal_id}"),
    }
