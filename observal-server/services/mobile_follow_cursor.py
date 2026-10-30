# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Purpose-bound signed follow read positions; the PostgreSQL lease is authoritative."""

import re
import uuid
from datetime import UTC, datetime

import jwt

from services.crypto import sign_token, verify_token

CURSOR_PATTERN = re.compile(r"[A-Za-z0-9_.~-]{1,1300}\Z")


def _micros(value: datetime) -> int:
    elapsed = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds


class InvalidCursor(ValueError):  # noqa: N818
    pass


class GenerationConflict(InvalidCursor):
    pass


def issue(
    *,
    purpose: str,
    server_id: uuid.UUID,
    project_id: str,
    owner_id: uuid.UUID,
    device_id: str,
    cohort: str,
    generation: int,
    lease_id: uuid.UUID,
    last_row: int,
    expires_at: datetime,
) -> str:
    if purpose not in ("snapshot", "export", "changes") or last_row not in range(0, 1001, 100):
        raise InvalidCursor
    deadline_us = _micros(expires_at)
    token = sign_token(
        {
            "type": "mobile-follow-read-cursor-v1",
            "purpose": purpose,
            "server_id": str(server_id),
            "project_id": project_id,
            "owner_id": str(owner_id),
            "device_id": device_id,
            "cohort": cohort,
            "generation": generation,
            "lease_id": str(lease_id),
            "last_row": last_row,
            # JWT's integer exp is a ceiling; the microsecond deadline below is
            # authoritative, so a lease never ends early or lasts beyond 900s.
            "exp": (deadline_us + 999_999) // 1_000_000,
            "expires_at_us": deadline_us,
        }
    )
    if not CURSOR_PATTERN.fullmatch(token):
        raise InvalidCursor
    return token


def verify(
    token: str,
    *,
    purpose: str,
    server_id: uuid.UUID,
    project_id: str,
    owner_id: uuid.UUID,
    device_id: str,
    cohort: str,
    generation: int,
    now: datetime | None = None,
) -> tuple[uuid.UUID, int]:
    if not isinstance(token, str) or not CURSOR_PATTERN.fullmatch(token) or token.count(".") != 2:
        raise InvalidCursor
    try:
        # Explicit clock comparison permits deterministic boundary tests and prevents
        # a JWT library's default clock/leeway from extending the fixed lease.
        payload = verify_token(token)
        expected = {
            "type": "mobile-follow-read-cursor-v1",
            "purpose": purpose,
            "server_id": str(server_id),
            "project_id": project_id,
            "owner_id": str(owner_id),
            "device_id": device_id,
            "cohort": cohort,
        }
        if any(type(payload.get(k)) is not type(v) or payload.get(k) != v for k, v in expected.items()):
            raise InvalidCursor
        expiry = payload.get("exp")
        exact = payload.get("expires_at_us")
        position = payload.get("last_row")
        signed_generation = payload.get("generation")
        if (
            type(expiry) is not int
            or type(exact) is not int
            or expiry != (exact + 999_999) // 1_000_000
            or exact <= _micros(now or datetime.now(UTC))
            or type(position) is not int
            or position not in range(0, 1001, 100)
            or type(signed_generation) is not int
            or signed_generation < 1
        ):
            raise InvalidCursor
        lease = uuid.UUID(payload["lease_id"])
        if str(lease) != payload["lease_id"]:
            raise InvalidCursor
        if signed_generation != generation:
            raise GenerationConflict
        return lease, position
    except GenerationConflict:
        raise
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError) as exc:
        raise InvalidCursor from exc
