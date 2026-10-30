# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""One-use, action-specific browser intent; never a sign-in or account consent."""

import hashlib
import secrets
import uuid

from fastapi import HTTPException
from redis.exceptions import RedisError

from services.redis import get_redis

TTL = 120
ACTIONS = frozenset({"consent", "write-approval"})
_CONSUME = """
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"""


def _binding(principal, action: str, token: str) -> str:
    if action not in ACTIONS:
        raise HTTPException(403, "Invalid browser action")
    try:
        owner = str(uuid.UUID(str(principal.user.id)))
        jti = str(uuid.UUID(principal.payload["jti"]))
    except (KeyError, ValueError, TypeError):
        raise HTTPException(401, "Invalid browser credential") from None
    if not isinstance(token, str) or not token:
        raise HTTPException(401, "Invalid browser credential")
    return hashlib.sha256(f"{owner}:{jti}:{action}:{token}".encode()).hexdigest()


def action_header(request) -> str:
    values = request.headers.getlist("X-Observal-Browser-Action")
    if len(values) != 1:
        raise HTTPException(403, "Browser action proof required")
    return values[0]


def _key(nonce: str) -> str:
    if (
        not isinstance(nonce, str)
        or len(nonce) != 43
        or not nonce.isascii()
        or not all(c.isalnum() or c in "-_" for c in nonce)
    ):
        raise HTTPException(403, "Browser action proof required")
    return "follow:browser-action:" + hashlib.sha256(nonce.encode()).hexdigest()


async def mint(principal, action: str, token: str) -> str:
    binding = _binding(principal, action, token)
    try:
        redis = get_redis()
        for _ in range(3):
            nonce = secrets.token_urlsafe(32)
            if await redis.set(_key(nonce), binding, ex=TTL, nx=True):
                return nonce
    except RedisError as exc:
        raise HTTPException(503, "Browser action store unavailable") from exc
    raise HTTPException(503, "Browser action store unavailable")


async def consume(principal, action: str, nonce: str | None, token: str) -> None:
    key = _key(nonce)
    binding = _binding(principal, action, token)
    try:
        # Redis evaluates GET+DEL atomically on its primary; no API-local state.
        if await get_redis().eval(_CONSUME, 1, key, binding) != 1:
            raise HTTPException(403, "Browser action proof required")
    except RedisError as exc:
        raise HTTPException(503, "Browser action store unavailable") from exc
