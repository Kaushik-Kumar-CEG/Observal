# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Independent one-use browser intent for phone sign-in (never Following consent)."""

import hashlib
import secrets
from urllib.parse import urlsplit

import jwt
from fastapi import HTTPException, Request
from redis.exceptions import RedisError

import services.dynamic_settings as ds
from services.jwt_service import decode_access_token
from services.redis import get_redis

TTL = 120
_CONSUME = """
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"""
_LIMIT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
return n
"""


def browser_token(request: Request, user) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1 or not values[0].startswith("Bearer "):
        raise HTTPException(401, "Browser credential required")
    token = values[0][7:].strip()
    try:
        payload = decode_access_token(token)
        if payload.get("sub") != str(user.id) or not payload.get("jti") or payload.get("client_id") is not None:
            raise HTTPException(401, "Browser credential required")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "Browser credential required") from exc
    return token


async def browser_origin() -> str:
    """Only an explicit HTTPS origin shared by web and API can sign in a phone."""

    def parse(value: str | None) -> str:
        try:
            url = urlsplit(value or "")
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username is not None
                or url.password is not None
                or url.path not in ("", "/")
                or url.query
                or url.fragment
            ):
                raise ValueError("invalid origin")
            host = url.hostname.lower()
            return f"https://{host if ':' not in host else f'[{host}]'}{f':{url.port}' if url.port not in (None, 443) else ''}"
        except (ValueError, TypeError):
            raise HTTPException(503, "Device verification origin unavailable") from None

    api = parse(await ds.get("deployment.public_url"))
    web = parse(await ds.get("deployment.frontend_url"))
    if api != web:
        raise HTTPException(503, "Device verification origin unavailable")
    return api


def require_post(request: Request, origin: str, user) -> str:
    if len(request.headers.getlist("origin")) != 1 or request.headers.get("origin") != origin:
        raise HTTPException(403, "Invalid browser origin")
    if request.headers.get("sec-fetch-site") not in (None, "same-origin"):
        raise HTTPException(403, "Invalid browser origin")
    if request.headers.get("content-type", "").lower().split(";", 1)[0].strip() != "application/json":
        raise HTTPException(415, "JSON required")
    return browser_token(request, user)


def require_preview(request: Request, origin: str, user) -> None:
    origins = request.headers.getlist("origin")
    site = request.headers.get("sec-fetch-site")
    if (origins and (len(origins) != 1 or origins[0] != origin)) or (not origins and site != "same-origin"):
        raise HTTPException(403, "Invalid browser origin")
    if site not in (None, "same-origin"):
        raise HTTPException(403, "Invalid browser origin")
    browser_token(request, user)


async def limit_preview(user) -> None:
    try:
        key = "device:preview-rate:" + hashlib.sha256(str(user.id).encode()).hexdigest()
        if await get_redis().eval(_LIMIT, 1, key) > 5:
            raise HTTPException(429, "Too many code lookups")
    except RedisError as exc:
        raise HTTPException(503, "Device verification unavailable") from exc


def _key(nonce: str | None) -> str:
    if not nonce or len(nonce) != 43 or not nonce.isascii() or not all(c.isalnum() or c in "-_" for c in nonce):
        raise HTTPException(403, "Device browser action required")
    return "device:browser-action:" + hashlib.sha256(nonce.encode()).hexdigest()


def _binding(user, code: str, token: str) -> str:
    return hashlib.sha256(f"phone-sign-in:{user.id}:{code}:{token}".encode()).hexdigest()


async def mint(user, code: str, token: str) -> str:
    try:
        redis = get_redis()
        for _ in range(3):
            nonce = secrets.token_urlsafe(32)
            if await redis.set(_key(nonce), _binding(user, code, token), ex=TTL, nx=True):
                return nonce
    except RedisError as exc:
        raise HTTPException(503, "Device verification unavailable") from exc
    raise HTTPException(503, "Device verification unavailable")


async def consume(request: Request, user, code: str, token: str) -> None:
    values = request.headers.getlist("x-observal-browser-action")
    if len(values) != 1:
        raise HTTPException(403, "Device browser action required")
    key = _key(values[0])
    try:
        if await get_redis().eval(_CONSUME, 1, key, _binding(user, code, token)) != 1:
            raise HTTPException(403, "Device browser action required")
    except RedisError as exc:
        raise HTTPException(503, "Device verification unavailable") from exc
