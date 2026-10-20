# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""JWT token generation and validation for unified browser/CLI auth.

Tokens are signed with the configured asymmetric key via the key manager in
services.crypto. The corresponding public keys are published at
/.well-known/jwks.json so external consumers can verify tokens without
sharing a secret.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from loguru import logger as optic

import services.dynamic_settings as ds
from models.user import UserRole

MOBILE_CLIENT_ID = "observal-mobile"
MOBILE_AUDIENCE = "observal-mobile-activity-v1"
MOBILE_SCOPE = "mobile:read"


def create_access_token(
    user_id: uuid.UUID,
    role: UserRole,
    expires_in_minutes: int | None = None,
    groups: list[str] | None = None,
    client_id: str | None = None,
    device_id: str | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, int]:
    """Create a short-lived asymmetrically signed access token.

    Returns (encoded_token, expires_in_seconds).
    """
    optic.trace("creating access token for user {}", user_id)
    from services.crypto import sign_token

    now = datetime.now(UTC)
    expires_delta = timedelta(minutes=expires_in_minutes or ds.get_sync_int("jwt.access_token_expire_minutes", 60))
    if client_id == MOBILE_CLIENT_ID:
        # Android's accepted mobile grant allows at most 24 hours. Do not
        # inherit an operator's longer desktop/CLI JWT setting or lengthen the
        # signed original refresh-family deadline. Desktop lifetimes are separate.
        expires_delta = min(expires_delta, timedelta(hours=24))
    if expires_at is not None:
        expires_delta = min(expires_delta, expires_at - now)
        if expires_delta.total_seconds() < 1:
            raise ValueError("Mobile refresh family has expired")
    expires_in = int(expires_delta.total_seconds())
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "type": "access",
        "groups": groups or [],
        "jti": str(uuid.uuid4()),
        "iat": now,
        # iat has 1s resolution; revocation compares in microseconds (services/token_revocation.py).
        "iat_us": int(now.timestamp()) * 1_000_000 + now.microsecond,
        "exp": now + expires_delta,
    }
    if client_id is not None:
        if client_id != MOBILE_CLIENT_ID:
            raise ValueError("Unknown token client")
        if not device_id:
            raise ValueError("Mobile device grant required")
        payload.update(client_id=MOBILE_CLIENT_ID, aud=MOBILE_AUDIENCE, scope=MOBILE_SCOPE, device_id=device_id)
    token = sign_token(payload)
    return token, expires_in


def create_refresh_token(
    user_id: uuid.UUID,
    role: UserRole,
    groups: list[str] | None = None,
    client_id: str | None = None,
    device_id: str | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, str]:
    """Create a long-lived asymmetrically signed refresh token.

    Returns (encoded_token, jti).
    The jti is returned separately so it can be stored for revocation.
    """
    from services.crypto import sign_token

    now = datetime.now(UTC)
    jti = str(uuid.uuid4())
    if client_id == MOBILE_CLIENT_ID and expires_at is None:
        expires_at = now + timedelta(days=min(ds.get_sync_int("jwt.refresh_token_expire_days", 30), 30))
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "type": "refresh",
        "groups": groups or [],
        "jti": jti,
        "iat": now,
        "iat_us": int(now.timestamp()) * 1_000_000 + now.microsecond,
        "exp": expires_at
        if expires_at is not None
        else now + timedelta(days=ds.get_sync_int("jwt.refresh_token_expire_days", 30)),
    }
    if client_id is not None:
        if client_id != MOBILE_CLIENT_ID:
            raise ValueError("Unknown token client")
        if not device_id:
            raise ValueError("Mobile device grant required")
        payload.update(client_id=MOBILE_CLIENT_ID, aud=MOBILE_AUDIENCE, scope=MOBILE_SCOPE, device_id=device_id)
    token = sign_token(payload)
    return token, jti


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token using the configured public key set.

    Raises jwt.InvalidTokenError (or subclass) on failure.
    """
    from services.crypto import verify_token

    return verify_token(token)


def _validate_mobile_claims(payload: dict, *, allow_mobile: bool) -> None:
    client_id = payload.get("client_id")
    if client_id is None:
        if "aud" in payload or "scope" in payload:
            raise jwt.InvalidTokenError("Unknown token audience or scope")
        return
    if (
        client_id != MOBILE_CLIENT_ID
        or payload.get("aud") != MOBILE_AUDIENCE
        or payload.get("scope") != MOBILE_SCOPE
        or not isinstance(payload.get("device_id"), str)
        or not payload["device_id"]
        or not allow_mobile
    ):
        raise jwt.InvalidTokenError("Token is not authorized for this client")


def decode_access_token(token: str, *, allow_mobile: bool = False) -> dict:
    """Decode a browser/CLI access token; reject phone tokens by default."""
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Token is not an access token")
    _validate_mobile_claims(payload, allow_mobile=allow_mobile)
    return payload


def decode_refresh_token(token: str) -> dict:
    """Decode a refresh token and verify its type claim."""
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise jwt.InvalidTokenError("Token is not a refresh token")
    _validate_mobile_claims(payload, allow_mobile=True)
    return payload
