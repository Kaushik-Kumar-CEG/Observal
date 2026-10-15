# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Phone credentials cannot become account-wide browser/CLI credentials."""

import asyncio
import inspect
import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from api import deps
from api.graphql import _resolve_user_context_from_request
from api.routes import auth, device_auth
from models.user import User, UserRole
from schemas.auth import DeviceAuthRequest, DeviceTokenRequest, RefreshRequest, RevokeRequest
from services.crypto import init_key_manager
from services.jwt_service import (
    MOBILE_AUDIENCE,
    MOBILE_CLIENT_ID,
    MOBILE_SCOPE,
    decode_access_token,
    decode_refresh_token,
)
from tests.test_device_auth import FakeRedis


class MobileTestRedis(FakeRedis):
    async def getdel(self, key):
        value = self._store.pop(key, None)
        self._ttls.pop(key, None)
        return value


@pytest.fixture
def identity(monkeypatch, tmp_path):
    init_key_manager(key_dir=str(tmp_path / "keys"), key_password=None)
    redis = MobileTestRedis()
    monkeypatch.setattr(device_auth.ds, "get_bool", AsyncMock(side_effect=lambda key: key == "mobile.auth_enabled"))
    for module in (deps, auth, device_auth):
        monkeypatch.setattr(module, "get_redis", lambda: redis)
    monkeypatch.setattr("services.redis.get_redis", lambda: redis)
    user = User(id=uuid.uuid4(), email="admin@example.test", username="admin", name="Admin", role=UserRole.admin)
    user.created_at = datetime.now(UTC)
    user.auth_provider = "local"
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: user))
    return SimpleNamespace(redis=redis, user=user, db=db)


@pytest.mark.asyncio
async def test_device_grant_creates_scope_preserving_read_only_phone_tokens(identity):
    request = SimpleNamespace(headers={"host": "localhost"})
    created = await inspect.unwrap(device_auth.device_authorize)(
        request, DeviceAuthRequest(client_id=MOBILE_CLIENT_ID), identity.db
    )
    assert created.verification_origins == ["http://localhost"]
    assert created.verification_uri.startswith("http://localhost/device")
    data = json.loads(await identity.redis.get(f"device_auth:{created.device_code}"))
    assert data["client_id"] == MOBILE_CLIENT_ID
    assert data["device_id"]
    data.update(status="approved", user_id=str(identity.user.id))
    await identity.redis.setex(f"device_auth:{created.device_code}", 600, json.dumps(data))
    grant = await inspect.unwrap(device_auth.device_token)(
        request,
        DeviceTokenRequest(device_code=created.device_code, grant_type=device_auth._DEVICE_GRANT_TYPE),
        identity.db,
    )
    assert grant.status_code == 200
    body = json.loads(grant.body)
    assert (body["token_type"], body["client_id"], body["audience"], body["scope"]) == (
        "bearer",
        MOBILE_CLIENT_ID,
        MOBILE_AUDIENCE,
        MOBILE_SCOPE,
    )
    access, refresh = body["access_token"], body["refresh_token"]
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(access)
    assert await deps._authenticate_via_jwt(access, identity.db) is None
    with pytest.raises(HTTPException) as exc:
        await deps.get_current_user(SimpleNamespace(), f"Bearer {access}", identity.db)
    assert exc.value.status_code == 401
    valid = decode_access_token(access, allow_mobile=True)
    assert (valid["aud"], valid["scope"], valid["client_id"]) == (MOBILE_AUDIENCE, MOBILE_SCOPE, MOBILE_CLIENT_ID)
    assert await deps._authenticate_via_jwt(access, identity.db, allow_mobile=True) is not None
    assert (await _resolve_user_context_from_request(SimpleNamespace(headers={"authorization": f"Bearer {access}"})))[
        "user_id"
    ] is None
    mobile_request = SimpleNamespace(url=SimpleNamespace(path="/api/v1/auth/mobile/logout"), state=SimpleNamespace())
    assert (await deps.get_mobile_user(mobile_request, f"Bearer {access}", identity.db)).id == identity.user.id
    proof_request = SimpleNamespace(
        headers={"authorization": f"Bearer {access}"},
        url=SimpleNamespace(path="/api/v1/auth/mobile/credential"),
        state=SimpleNamespace(),
    )
    proven = await deps.get_mobile_user(proof_request, f"Bearer {access}", identity.db)
    proof = await inspect.unwrap(auth.mobile_credential)(proof_request, proven)
    assert (proof.subject_id, proof.device_id, proof.audience, proof.scope) == (
        identity.user.id,
        data["device_id"],
        MOBILE_AUDIENCE,
        MOBILE_SCOPE,
    )
    first = await inspect.unwrap(auth.refresh_token)(request, RefreshRequest(refresh_token=refresh), identity.db)
    second = await inspect.unwrap(auth.refresh_token)(
        request, RefreshRequest(refresh_token=first.refresh_token), identity.db
    )
    for pair in (first, second):
        assert (pair.token_type, pair.client_id, pair.audience, pair.scope) == (
            "bearer",
            MOBILE_CLIENT_ID,
            MOBILE_AUDIENCE,
            MOBILE_SCOPE,
        )
        a = decode_access_token(pair.access_token, allow_mobile=True)
        r = decode_refresh_token(pair.refresh_token)
        assert (a["device_id"], a["scope"], a["aud"]) == (data["device_id"], MOBILE_SCOPE, MOBILE_AUDIENCE)
        assert (r["device_id"], r["scope"], r["aud"]) == (data["device_id"], MOBILE_SCOPE, MOBILE_AUDIENCE)
    desktop_access, desktop_refresh, _ = await auth._issue_tokens(identity.user)
    logout_request = SimpleNamespace(headers={"authorization": f"Bearer {second.access_token}"})
    await inspect.unwrap(auth.mobile_logout)(
        logout_request, RevokeRequest(refresh_token=second.refresh_token), identity.user
    )
    assert await deps._authenticate_via_jwt(second.access_token, identity.db, allow_mobile=True) is None
    assert await deps._authenticate_via_jwt(desktop_access, identity.db) is not None
    desktop_rotated = await inspect.unwrap(auth.refresh_token)(
        request, RefreshRequest(refresh_token=desktop_refresh), identity.db
    )
    assert decode_access_token(desktop_rotated.access_token)["sub"] == str(identity.user.id)
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(auth.refresh_token)(
            request, RefreshRequest(refresh_token=second.refresh_token), identity.db
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_mobile_sso_verification_origin_is_browser_initial_only(identity, monkeypatch):
    monkeypatch.setattr(
        device_auth.ds,
        "get_sync",
        lambda key, default=None: "https://browser.example.test" if key == "deployment.frontend_url" else default,
    )
    grant = await inspect.unwrap(device_auth.device_authorize)(
        SimpleNamespace(headers={"host": "untrusted.example"}),
        DeviceAuthRequest(client_id=MOBILE_CLIENT_ID, sso=True),
        identity.db,
    )
    assert grant.verification_origins == ["https://browser.example.test"]
    assert grant.verification_uri.startswith("https://browser.example.test/")
    assert "untrusted.example" not in grant.verification_uri
    monkeypatch.setattr(
        device_auth.ds,
        "get_sync",
        lambda key, default=None: (
            "https://attacker.example.test/redirect" if key == "deployment.frontend_url" else default
        ),
    )
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_authorize)(
            SimpleNamespace(headers={"host": "untrusted.example"}),
            DeviceAuthRequest(client_id=MOBILE_CLIENT_ID),
            identity.db,
        )
    assert exc.value.status_code == 503
    monkeypatch.setattr(device_auth.ds, "get_sync", lambda _key, default=None: default)
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_authorize)(
            SimpleNamespace(
                headers={
                    "host": "api.example.test",
                    "x-forwarded-proto": "https",
                    "x-forwarded-host": "attacker.example.test",
                }
            ),
            DeviceAuthRequest(client_id=MOBILE_CLIENT_ID),
            identity.db,
        )
    assert exc.value.status_code == 503  # No configured public origin: ignore client-supplied Host.


@pytest.mark.asyncio
async def test_explicit_isolated_loopback_https_origin_never_uses_spoofed_forwarded_host(identity, monkeypatch):
    monkeypatch.setattr(
        device_auth.ds,
        "get_sync",
        lambda key, default=None: "https://localhost:18443" if key == "deployment.frontend_url" else "",
    )
    request = SimpleNamespace(
        headers={"host": "attacker.test", "x-forwarded-host": "attacker.test", "x-forwarded-proto": "http"}
    )
    grant = await inspect.unwrap(device_auth.device_authorize)(
        request, DeviceAuthRequest(client_id=MOBILE_CLIENT_ID), identity.db
    )
    assert grant.verification_origins == ["https://localhost:18443"]
    assert grant.verification_uri.startswith("https://localhost:18443/device")
    monkeypatch.setattr(
        device_auth.ds,
        "get_sync",
        lambda key, default=None: "https://localhost:18443/redirect" if key == "deployment.frontend_url" else "",
    )
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_authorize)(
            request, DeviceAuthRequest(client_id=MOBILE_CLIENT_ID), identity.db
        )
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_mobile_refresh_is_atomically_single_use_under_concurrent_requests(identity):
    _, refresh, _ = await auth._issue_tokens(identity.user, client_id=MOBILE_CLIENT_ID, device_id="race-phone")
    request = SimpleNamespace(headers={})
    outcomes = await asyncio.gather(
        *(
            inspect.unwrap(auth.refresh_token)(request, RefreshRequest(refresh_token=refresh), identity.db)
            for _ in range(2)
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, HTTPException) and result.status_code == 401 for result in outcomes) == 1
    assert sum(not isinstance(result, BaseException) for result in outcomes) == 1
    winner = next(result for result in outcomes if not isinstance(result, BaseException))
    assert winner.client_id == MOBILE_CLIENT_ID and winner.scope == MOBILE_SCOPE


@pytest.mark.asyncio
async def test_mobile_bearer_denied_by_legacy_telemetry_and_admin_routes(identity):
    from api.routes.admin import users as _users
    from api.routes.admin._router import router as admin_router
    from api.routes.layer_snapshot import router as snapshot_router
    from api.routes.sessions import router as sessions_router

    app = FastAPI()
    for router in (snapshot_router, sessions_router, admin_router):
        app.include_router(router)
    # Other tests can reload the shared admin router module during collection,
    # leaving an older router instance empty. Bind the real endpoint on this
    # isolated test app if that happens; 404 is not an auth-denial assertion.
    if not any(route.path == "/api/v1/admin/users" for route in app.routes):
        app.add_api_route("/api/v1/admin/users", _users.list_users, methods=["GET"])
    app.dependency_overrides[deps.get_db] = lambda: identity.db
    phone, _, _ = await auth._issue_tokens(identity.user, client_id=MOBILE_CLIENT_ID, device_id="phone-test")
    headers = {"Authorization": f"Bearer {phone}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for path in (
            "/api/v1/layer-snapshots/1234567890abcdef",
            "/api/v1/sessions",
            "/api/v1/admin/users",
        ):
            response = await client.get(path, headers=headers)
            assert response.status_code == 401, (path, response.status_code)


@pytest.mark.asyncio
async def test_mobile_credential_proof_requires_server_verified_mobile_bearer(identity, monkeypatch):
    monkeypatch.setattr(auth.limiter, "enabled", False)
    app = FastAPI()
    app.include_router(auth.router)
    app.dependency_overrides[deps.get_db] = lambda: identity.db
    phone, _, _ = await auth._issue_tokens(identity.user, client_id=MOBILE_CLIENT_ID, device_id="phone-proof")
    desktop, _, _ = await auth._issue_tokens(identity.user)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        proof = await client.get("/api/v1/auth/mobile/credential", headers={"Authorization": f"Bearer {phone}"})
        other = await client.get("/api/v1/auth/mobile/credential", headers={"Authorization": f"Bearer {desktop}"})
        missing = await client.get("/api/v1/auth/mobile/credential")
    assert proof.status_code == 200
    assert proof.json() == {
        "token_type": "bearer",
        "client_id": MOBILE_CLIENT_ID,
        "audience": MOBILE_AUDIENCE,
        "scope": MOBILE_SCOPE,
        "subject_id": str(identity.user.id),
        "device_id": "phone-proof",
    }
    assert other.status_code == 403 and missing.status_code == 401


@pytest.mark.asyncio
async def test_mobile_dependency_cannot_be_reused_on_an_unrelated_endpoint(identity):
    phone, _, _ = await auth._issue_tokens(identity.user, client_id=MOBILE_CLIENT_ID, device_id="phone-test")
    request = SimpleNamespace(url=SimpleNamespace(path="/api/v1/admin/users"), state=SimpleNamespace())
    with pytest.raises(HTTPException) as exc:
        await deps.get_mobile_user(request, f"Bearer {phone}", identity.db)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_mobile_signin_is_closed_until_explicit_rollout(identity, monkeypatch):
    monkeypatch.setattr(device_auth.ds, "get_bool", AsyncMock(return_value=False))
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_authorize)(
            SimpleNamespace(headers={}), DeviceAuthRequest(client_id=MOBILE_CLIENT_ID), identity.db
        )
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_disable_rollout_burns_approved_phone_grant_and_blocks_active_reads(identity, monkeypatch):
    request = SimpleNamespace(headers={"host": "localhost"})
    created = await inspect.unwrap(device_auth.device_authorize)(
        request, DeviceAuthRequest(client_id=MOBILE_CLIENT_ID), identity.db
    )
    data = json.loads(await identity.redis.get(f"device_auth:{created.device_code}"))
    data.update(status="approved", user_id=str(identity.user.id))
    await identity.redis.setex(f"device_auth:{created.device_code}", 600, json.dumps(data))
    phone_access, phone_refresh, _ = await auth._issue_tokens(
        identity.user, client_id=MOBILE_CLIENT_ID, device_id="phone-before-disable"
    )
    monkeypatch.setattr(device_auth.ds, "get_bool", AsyncMock(return_value=False))
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_token)(
            request,
            DeviceTokenRequest(device_code=created.device_code, grant_type=device_auth._DEVICE_GRANT_TYPE),
            identity.db,
        )
    assert exc.value.status_code == 503
    assert await identity.redis.get(f"device_auth:{created.device_code}") is None
    mobile_request = SimpleNamespace(
        url=SimpleNamespace(path="/api/v1/mobile-activity/v1/capabilities"), state=SimpleNamespace()
    )
    with pytest.raises(HTTPException) as exc:
        await deps.get_mobile_user(mobile_request, f"Bearer {phone_access}", identity.db)
    assert exc.value.status_code == 503
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(auth.refresh_token)(request, RefreshRequest(refresh_token=phone_refresh), identity.db)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_unknown_device_client_never_receives_a_grant(identity):
    with pytest.raises(HTTPException) as exc:
        await inspect.unwrap(device_auth.device_authorize)(
            SimpleNamespace(headers={}), DeviceAuthRequest(client_id="forged-unrestricted"), identity.db
        )
    assert exc.value.status_code == 400
