# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Normal browser proof is separate from sign-in and phone write authorization."""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from redis.exceptions import RedisError

from services import mobile_follow_browser_action as proof


class SharedRedis:
    def __init__(self):
        self.data = {}

    async def set(self, key, value, *, ex, nx):
        assert nx and ex <= 120
        if key in self.data:
            return None
        self.data[key] = value
        return True

    async def eval(self, script, numkeys, key, expected):
        assert numkeys == 1
        if self.data.get(key) != expected:
            return 0
        del self.data[key]
        return 1


@pytest.fixture
def principal():
    return SimpleNamespace(user=SimpleNamespace(id=uuid.uuid4()), payload={"jti": str(uuid.uuid4())})


@pytest.mark.asyncio
async def test_action_account_jti_replay_and_cross_process(monkeypatch, principal):
    redis = SharedRedis()
    monkeypatch.setattr(proof, "get_redis", lambda: redis)
    nonce = await proof.mint(principal, "consent", "website-jwt")
    for p, action in (
        (principal, "write-approval"),
        (SimpleNamespace(user=SimpleNamespace(id=uuid.uuid4()), payload=principal.payload), "consent"),
        (SimpleNamespace(user=principal.user, payload={"jti": str(uuid.uuid4())}), "consent"),
    ):
        with pytest.raises(HTTPException) as denied:
            await proof.consume(p, action, nonce, "website-jwt")
        assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as wrong_jwt:
        await proof.consume(principal, "consent", nonce, "other-signed-jwt-same-jti")
    assert wrong_jwt.value.status_code == 403
    results = await asyncio.gather(
        proof.consume(principal, "consent", nonce, "website-jwt"),
        proof.consume(principal, "consent", nonce, "website-jwt"),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, HTTPException) and result.status_code == 403 for result in results) == 1


@pytest.mark.asyncio
async def test_redis_loss_fails_closed(monkeypatch, principal):
    class Lost:
        async def set(self, *args, **kwargs):
            raise RedisError("offline")

        async def eval(self, *args, **kwargs):
            raise RedisError("offline")

    monkeypatch.setattr(proof, "get_redis", Lost)
    with pytest.raises(HTTPException) as denied:
        await proof.mint(principal, "consent", "website-jwt")
    assert denied.value.status_code == 503
    with pytest.raises(HTTPException) as denied:
        await proof.consume(principal, "consent", "x" * 43, "website-jwt")
    assert denied.value.status_code == 503


@pytest.mark.asyncio
async def test_missing_nonce_and_invalid_action_are_closed(principal):
    with pytest.raises(HTTPException) as denied:
        await proof.consume(principal, "consent", None, "website-jwt")
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as denied:
        await proof.mint(principal, "operations", "website-jwt")
    assert denied.value.status_code == 403
