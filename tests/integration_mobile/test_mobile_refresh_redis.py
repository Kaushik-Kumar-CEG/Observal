# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real Redis 7 mobile refresh concurrency; loopback disposable store only."""

import asyncio
import inspect
import os
import time
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from redis.asyncio import Redis

from api.routes import auth
from models.user import User, UserRole
from schemas.auth import RefreshRequest
from services.crypto import init_key_manager
from services.jwt_service import MOBILE_CLIENT_ID, decode_access_token, decode_refresh_token
from services.mobile_refresh import rotate_mobile_refresh

pytestmark = pytest.mark.skipif(
    os.getenv("MOBILE_REFRESH_REDIS_SCRATCH") != "1", reason="disposable loopback Redis only"
)


@pytest.mark.asyncio
async def test_atomic_single_successor_fixed_family_and_revocation_across_clients(monkeypatch, tmp_path):
    from services import mobile_read_control

    url = os.environ["MOBILE_REFRESH_REDIS_URL"]
    assert url == "redis://127.0.0.1:16408/15"
    init_key_manager(key_dir=str(tmp_path / "jwt"), key_password=None)
    clients = [Redis.from_url(url, decode_responses=True) for _ in range(2)]
    user = User(id=uuid.uuid4(), email="mobile-refresh@example.invalid", username="refresh_local", role=UserRole.user)
    user.auth_provider = "local"
    db = MagicMock()
    db.execute = AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: user))
    monkeypatch.setattr(mobile_read_control, "mobile_issue_allowed", AsyncMock(return_value=True))
    monkeypatch.setattr(auth, "get_redis", lambda: clients[0])
    keys: set[str] = set()
    try:
        _access, old, _ = await auth._issue_tokens(user, client_id=MOBILE_CLIENT_ID, device_id="test-device")
        chosen = iter(clients)
        monkeypatch.setattr(auth, "get_redis", lambda: next(chosen))
        predecessor = decode_refresh_token(old)
        old_key = f"refresh_jti:{predecessor['jti']}"
        keys.add(old_key)
        # Two separate Redis clients stand in for two API workers. Both
        # requests carry the same original JWT but only one may commit.
        outcomes = await asyncio.gather(
            *(
                inspect.unwrap(auth.refresh_token)(SimpleNamespace(headers={}), RefreshRequest(refresh_token=old), db)
                for _ in clients
            ),
            return_exceptions=True,
        )
        winners = [item for item in outcomes if not isinstance(item, BaseException)]
        losers = [item for item in outcomes if isinstance(item, HTTPException) and item.status_code == 401]
        assert len(winners) == len(losers) == 1
        winner = winners[0]
        next_payload = decode_refresh_token(winner.refresh_token)
        assert next_payload["exp"] == predecessor["exp"]
        assert next_payload["sub"] == predecessor["sub"]
        assert next_payload["device_id"] == predecessor["device_id"]
        assert (await clients[0].get(old_key)) is None
        successor_key = f"refresh_jti:{next_payload['jti']}"
        keys.add(successor_key)
        assert await clients[0].get(successor_key) == str(user.id)
        assert 0 < await clients[0].ttl(successor_key) <= predecessor["exp"] - int(time.time()) + 1
        assert decode_access_token(winner.access_token, allow_mobile=True)["exp"] <= predecessor["exp"]
        # A reply lost after atomic commit cannot replay the old JTI or mint a
        # second successor. A surviving successor remains bounded by day 30.
        assert (
            await rotate_mobile_refresh(
                clients[1],
                user_id=str(user.id),
                device_id="test-device",
                previous_jti=predecessor["jti"],
                successor_jti=str(uuid.uuid4()),
                issued_us=predecessor["iat_us"],
                ttl=42,
            )
            == 0
        )
        # A terminal account revoke denies the still-unconsumed successor.
        revoked_key = f"revoked_user:{user.id}"
        keys.add(revoked_key)
        await clients[0].set(revoked_key, str(int(datetime.now(UTC).timestamp() * 1_000_000) + 1))
        monkeypatch.setattr(auth, "get_redis", lambda: clients[1])
        with pytest.raises(HTTPException) as revoked:
            await inspect.unwrap(auth.refresh_token)(
                SimpleNamespace(headers={}), RefreshRequest(refresh_token=winner.refresh_token), db
            )
        assert revoked.value.status_code == 401
        assert await clients[0].get(successor_key) == str(user.id)  # deny does not mint/consume
        # Device marker denies a fresh unconsumed token as well.
        await clients[0].delete(revoked_key)
        device_key = "revoked_mobile_device:test-device"
        keys.add(device_key)
        await clients[0].set(device_key, "1")
        with pytest.raises(HTTPException) as device_denied:
            await inspect.unwrap(auth.refresh_token)(
                SimpleNamespace(headers={}), RefreshRequest(refresh_token=winner.refresh_token), db
            )
        assert device_denied.value.status_code == 401
        assert await clients[0].get(successor_key) == str(user.id)
    finally:
        if keys:
            await clients[0].delete(*keys)
        for client in clients:
            await client.aclose()
