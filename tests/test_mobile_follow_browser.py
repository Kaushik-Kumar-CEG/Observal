# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant browser boundary regression tests; no live stack required."""

import sys
import types
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from starlette.requests import Request

import services
from services import mobile_follow_browser as browser


def request(headers, method="POST"):
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/api/v1/mobile-follow-sync/v1/write-approval",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "query_string": b"",
            "scheme": "https",
            "server": ("issuer.test", 443),
        }
    )


ORIGIN = "https://issuer.test"
HEADERS = {"origin": ORIGIN, "content-type": "application/json", "authorization": "Bearer browser-access"}


@pytest.mark.parametrize(
    "api,web",
    [
        ("", ORIGIN),
        (ORIGIN, ""),
        ("http://issuer.test", ORIGIN),
        (ORIGIN, "https://evil.test"),
        ("https://issuer.test.evil", ORIGIN),
        ("https://u:p@issuer.test", ORIGIN),
        ("https://issuer.test/path", ORIGIN),
        ("https://issuer.test:bad", ORIGIN),
    ],
)
def test_issuer_rejects_insecure_or_split_origins(api, web):
    with pytest.raises(HTTPException) as error:
        browser.issuer_origin(api, web)
    assert error.value.status_code == 503


def test_issuer_canonical_port_and_challenge_url():
    assert browser.issuer_origin("https://ISSUER.test:443/", ORIGIN) == ORIGIN
    assert browser.issuer_origin("https://issuer.test:8443", "https://ISSUER.test:8443/") == ORIGIN + ":8443"
    assert browser.verification_uri(ORIGIN, "a" * 32) == ORIGIN + "/follow/approve?code=" + "a" * 32
    with pytest.raises(HTTPException):
        browser.verification_uri(ORIGIN, "short")


@pytest.mark.parametrize(
    "headers",
    [
        {**HEADERS, "origin": "https://evil.test"},
        {**HEADERS, "origin": "null"},
        {k: v for k, v in HEADERS.items() if k != "origin"},
        {**HEADERS, "sec-fetch-site": "cross-site"},
        {**HEADERS, "sec-fetch-site": "same-site"},
        {**HEADERS, "content-type": "text/plain"},
        {**HEADERS, "authorization": "Bearer phone", "origin": "https://evil.test"},
        {k: v for k, v in HEADERS.items() if k != "authorization"},
    ],
)
def test_browser_boundary_fails_closed(headers):
    with pytest.raises(HTTPException) as error:
        browser.require_browser_request(request(headers), ORIGIN)
    assert error.value.status_code in (401, 403, 415)


def test_browser_boundary_allows_same_origin_json_bearer_only():
    browser.require_browser_request(request({**HEADERS, "sec-fetch-site": "same-origin"}), ORIGIN)
    with pytest.raises(HTTPException):
        browser.require_browser_request(request(HEADERS, method="GET"), ORIGIN)
    for duplicate in ("origin", "authorization"):
        forged = request(HEADERS)
        forged.scope["headers"].append((duplicate.encode(), HEADERS[duplicate].encode()))
        with pytest.raises(HTTPException) as error:
            browser.require_browser_request(forged, ORIGIN)
        assert error.value.status_code in (401, 403)


@pytest.mark.asyncio
async def test_callable_route_requires_browser_guard_before_approval(monkeypatch):
    from api.routes import mobile_follow_browser as routes

    async def authorize(*args):
        raise AssertionError("auth must not run for cross-origin request")

    auth = types.ModuleType("services.mobile_follow_auth")
    auth.authorize_browser_approval = authorize
    monkeypatch.setitem(sys.modules, "services.mobile_follow_auth", auth)
    monkeypatch.setattr(services, "mobile_follow_auth", auth)
    monkeypatch.setattr(routes.settings, "get_sync", lambda name: ORIGIN)
    with pytest.raises(HTTPException) as error:
        await routes.write_approval(
            request({**HEADERS, "origin": "https://evil.test"}),
            routes.ApprovalRequest(user_code="a" * 32, approve=True),
            "Bearer browser-access",
            object(),
        )
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_approval_route_commits_without_returning_code_or_grant(monkeypatch):
    from api.routes import mobile_follow_browser as routes

    auth = types.ModuleType("services.mobile_follow_auth")
    owner = object()
    calls = []

    async def authorize(request, authorization, db):
        assert authorization == "Bearer browser-access"
        calls.append("browser-auth")
        return owner

    async def approve(db, principal, code):
        assert principal is owner and code == "a" * 32
        calls.append("approve")

    class DB:
        async def commit(self):
            calls.append("commit")

    auth.authorize_browser_approval, auth.approve_challenge = authorize, approve
    monkeypatch.setitem(sys.modules, "services.mobile_follow_auth", auth)
    monkeypatch.setattr(services, "mobile_follow_auth", auth)
    monkeypatch.setattr(routes.settings, "get_sync", lambda name: ORIGIN)
    result = await routes.write_approval(
        request(HEADERS),
        routes.ApprovalRequest(user_code="a" * 32, approve=True),
        "Bearer browser-access",
        DB(),
    )
    assert result == {"state": "approved"}
    assert calls == ["browser-auth", "approve", "commit"]
    with pytest.raises(HTTPException) as error:
        await routes.write_approval(
            request(HEADERS),
            routes.ApprovalRequest(user_code="a" * 32, approve=False),
            "Bearer browser-access",
            DB(),
        )
    assert error.value.status_code == 400


def test_browser_wire_denials_are_strict_and_size_checked_before_json(monkeypatch):
    from api.deps import get_db
    from api.routes import mobile_follow_browser as routes

    auth = types.ModuleType("services.mobile_follow_auth")

    async def deny(*args):
        raise HTTPException(401, "Private auth detail")

    auth.authorize_browser_approval = deny
    auth.authorize_follow_read = deny
    monkeypatch.setitem(sys.modules, "services.mobile_follow_auth", auth)
    monkeypatch.setattr(services, "mobile_follow_auth", auth)
    monkeypatch.setattr(routes.settings, "get_sync", lambda name: ORIGIN)
    app = FastAPI()
    app.include_router(routes.router)  # Isolated: do not enable the production router.
    app.dependency_overrides[get_db] = lambda: object()
    path = "/api/v1/mobile-follow-sync/v1/"
    with TestClient(app) as client:
        for suffix in ("write-authorization", "write-approval", "write-grant"):
            response = client.post(path + suffix, content=b"{" + b"x" * 4096, headers=HEADERS)
            assert (response.status_code, response.json()) == (413, {"error": "too_large"})
        for data in (b"{", b"[]", b'{"user_code":123,"approve":true}', b'{"approve":true}'):
            response = client.post(path + "write-approval", content=data, headers=HEADERS)
            assert (response.status_code, response.json()) == (400, {"error": "invalid_request"})
        response = client.post(path + "write-approval", json={"user_code": "a" * 32, "approve": True}, headers=HEADERS)
        assert (response.status_code, response.json()) == (401, {"error": "unauthorized"})
        response = client.post(
            path + "write-approval",
            json={"user_code": "a" * 32, "approve": True},
            headers={**HEADERS, "origin": "https://evil.test"},
        )
        assert (response.status_code, response.json()) == (403, {"error": "restricted"})
        response = client.post(
            path + "write-approval", content=b"{}", headers={**HEADERS, "content-type": "text/plain"}
        )
        assert (response.status_code, response.json()) == (415, {"error": "invalid_request"})


@pytest.fixture
def grant_env(monkeypatch):
    owner, server = uuid.uuid4(), uuid.uuid4()
    approval = SimpleNamespace(
        status="approved", owner_generation=7, expires_at=datetime.now(UTC) + timedelta(minutes=5)
    )
    partition = SimpleNamespace(owner_generation=7, consent_state="available", removal_state="none")
    principal = SimpleNamespace(
        device_id="device",
        payload={"sub": str(owner)},
        user=SimpleNamespace(id=owner),
        server_id=server,
        cohort="cohort",
        generation=7,
    )
    auth = types.ModuleType("services.mobile_follow_auth")
    auth.PROJECT, auth.AUDIENCE, auth.SCOPE, auth.MAX_TOKEN_SECONDS = (
        "project",
        "follow-aud",
        "mobile:follow-write",
        300,
    )
    auth.MOBILE_CLIENT_ID = "observal-mobile"

    async def account(payload, db, *, device_id):
        assert device_id == "device" and payload is principal.payload
        return principal.user

    async def identity(db):
        return server

    async def cohort(db, user, server_id):
        return "cohort"

    async def locked_partition(db, user, server_id, value, *, exclusive):
        assert exclusive and db.commits == 1
        return partition

    auth._account, auth._identity, auth._cohort, auth._partition = account, identity, cohort, locked_partition
    monkeypatch.setitem(sys.modules, "services.mobile_follow_auth", auth)
    monkeypatch.setattr(services, "mobile_follow_auth", auth)
    model = types.ModuleType("models.mobile_follow_sync")

    class Base(DeclarativeBase):
        pass

    class Approval(Base):
        __tablename__ = "approvals"
        server_id: Mapped[str] = mapped_column(String)
        project_id: Mapped[str] = mapped_column(String)
        owner_id: Mapped[str] = mapped_column(String)
        cohort: Mapped[str] = mapped_column(String)
        device_id: Mapped[str] = mapped_column(String, primary_key=True)

    model.MobileFollowApproval = Approval
    monkeypatch.setitem(sys.modules, "models.mobile_follow_sync", model)

    events = []

    def sign(payload):
        assert events == ["read-commit", "delete", "flush", "consume-commit"]
        assert payload["sub"] == str(owner) and payload["owner_generation"] == 7
        events.append("mint")
        return "signed-token"

    monkeypatch.setattr("services.crypto.sign_token", sign)

    class DB:
        commits = 0

        async def commit(self):
            self.commits += 1
            events.append("read-commit" if self.commits == 1 else "consume-commit")

        async def scalar(self, stmt):
            return approval

        async def delete(self, row):
            assert row is approval
            events.append("delete")

        async def flush(self):
            events.append("flush")

    return DB(), principal, approval, events


@pytest.mark.asyncio
async def test_grant_consumed_durably_before_signing(grant_env):
    db, principal, _, events = grant_env
    token, ttl = await browser.consume_grant_before_mint(db, principal)
    assert (token, ttl) == ("signed-token", 300)
    assert events[-1] == "mint"


@pytest.mark.asyncio
async def test_no_token_on_expired_or_unapproved_challenge(grant_env):
    db, principal, approval, events = grant_env
    approval.status = "pending"
    with pytest.raises(HTTPException) as error:
        await browser.consume_grant_before_mint(db, principal)
    assert error.value.status_code == 401
    assert events == ["read-commit"]


@pytest.mark.asyncio
async def test_failed_durable_commit_never_mints(grant_env):
    db, principal, _, events = grant_env
    original_commit = db.commit

    async def fail_commit():
        if db.commits == 1:
            raise RuntimeError("database commit failed")
        await original_commit()

    db.commit = fail_commit
    with pytest.raises(RuntimeError, match="commit failed"):
        await browser.consume_grant_before_mint(db, principal)
    assert "mint" not in events
