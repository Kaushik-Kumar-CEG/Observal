# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Isolated follow-sync credentials and one-use browser approval.

Not wired to the router. Callers must use the dedicated dependencies below, never
get_mobile_user/get_current_user for follow-sync writes. Keep the DB transaction
open through the protected read/write; commit only after the operation finishes.
"""

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, Header, HTTPException, Request
from redis.exceptions import RedisError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from models.mobile_follow_sync import MobileFollowApproval, MobileFollowPartition
from models.user import User
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.crypto import sign_token, verify_token
from services.jwt_service import MOBILE_AUDIENCE, MOBILE_CLIENT_ID, MOBILE_SCOPE, decode_access_token
from services.mobile_read_control import active_mobile_cohort
from services.redis import get_redis
from services.token_revocation import get_revocation_marker, is_revoked, token_issued_us

AUDIENCE = "observal-mobile-follow-sync-v1"
SCOPE = "mobile:follow-write"
MAX_TOKEN_SECONDS = 300
CHALLENGE_SECONDS = 600
PROJECT = str(DEFAULT_PROJECT_ID)
ROOT = "/api/v1/mobile-follow-sync/v1/"


def wire_cohort(cohort: str) -> str:
    """Keep distinct synthetic storage partitions; expose only agreed public cohort enum."""
    if cohort in ("synthetic-author", "synthetic-user"):
        return "synthetic"
    if cohort == "live":
        return "live"
    _deny(403, "Follow cohort unavailable")


READ_PATHS = frozenset(
    {
        ("GET", "availability"),
        ("GET", "snapshot"),
        ("GET", "changes"),
        ("GET", "export"),
        ("GET", "consent/state"),
        ("POST", "write-authorization"),
        ("POST", "write-grant"),
        ("POST", "removals/lookup"),
    }
)
READ_STATUS = re.compile(r"(?:operations|removals|consent/withdrawals)/[0-9a-fA-F-]{36}\Z")
WRITE_PATHS = frozenset(
    {
        ("POST", "operations"),
        ("POST", "removals/prepare"),
        ("POST", "removals"),
        ("POST", "consent/withdraw"),
    }
)


@dataclass(frozen=True)
class FollowPrincipal:
    user: User
    device_id: str | None
    server_id: uuid.UUID
    project_id: str
    cohort: str
    generation: int
    payload: dict


def _deny(status: int = 401, detail: str = "Invalid follow credential") -> None:
    raise HTTPException(status_code=status, detail=detail)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer ") or not authorization[7:].strip():
        _deny()
    return authorization[7:].strip()


def _uuid(value) -> uuid.UUID:
    if not isinstance(value, str):
        _deny()
    try:
        result = uuid.UUID(value)
    except ValueError:
        _deny()
    if str(result) != value:
        _deny()
    return result


def _route(request: Request, allowed: frozenset[tuple[str, str]]) -> None:
    path = request.url.path
    suffix = path[len(ROOT) :] if path.startswith(ROOT) else ""
    if (request.method, suffix) in allowed:
        return
    if allowed is READ_PATHS and request.method == "GET" and READ_STATUS.fullmatch(suffix):
        try:
            if str(uuid.UUID(suffix.rsplit("/", 1)[1])) == suffix.rsplit("/", 1)[1]:
                return
        except ValueError:
            pass
    _deny(403, "Follow credential not accepted on this route")


async def _identity(db: AsyncSession) -> uuid.UUID:
    server = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
    if server is None:
        _deny(503, "Follow service unavailable")
    return server if isinstance(server, uuid.UUID) else _uuid(str(server))


async def _account(payload: dict, db: AsyncSession, *, device_id: str | None) -> User:
    uid = _uuid(payload.get("sub"))
    jti = _uuid(payload.get("jti"))
    try:
        issued = token_issued_us(payload)
    except (TypeError, ValueError, OverflowError):
        _deny()
    if not isinstance(issued, int) or isinstance(issued, bool):
        _deny()
    try:
        redis = get_redis()
        marker = await get_revocation_marker(redis, uid)
        if (
            is_revoked(marker, issued)
            or await redis.get(f"revoked_jti:{jti}")
            or (device_id is not None and await redis.get(f"revoked_mobile_device:{device_id}"))
        ):
            _deny()
    except RedisError:
        _deny(503, "Authorization temporarily unavailable")
    user = await db.scalar(select(User).where(User.id == uid))
    if user is None or user.auth_provider == "deactivated":
        _deny()
    return user


async def _partition(
    db: AsyncSession, user: User, server: uuid.UUID, cohort: str, *, exclusive: bool = False, create: bool = False
) -> MobileFollowPartition:
    if create:
        # The cohort barrier has already been checked. Serialize first admission
        # against concurrent owner admission/deletion before inserting the default-
        # closed consent_required partition; never create from a write credential.
        owner = await db.scalar(select(User.id).where(User.id == user.id).with_for_update())
        if owner is None:
            _deny()
        await db.execute(
            text(
                "INSERT INTO mobile_follow_partitions (server_id, project_id, owner_id, cohort) "
                "VALUES (:server, :project, :owner, :cohort) ON CONFLICT DO NOTHING"
            ),
            {"server": server, "project": PROJECT, "owner": user.id, "cohort": cohort},
        )
    row = await db.scalar(
        select(MobileFollowPartition)
        .where(
            MobileFollowPartition.server_id == server,
            MobileFollowPartition.project_id == PROJECT,
            MobileFollowPartition.owner_id == user.id,
            MobileFollowPartition.cohort == cohort,
        )
        .with_for_update(read=not exclusive)
    )
    if row is None:
        _deny(403, "Follow state unavailable")
    return row


async def _cohort(db: AsyncSession, user: User, server: uuid.UUID) -> str:
    cohort = await active_mobile_cohort(db, user, server_id=str(server))
    if cohort is None:
        _deny(403, "Follow cohort unavailable")
    return cohort


async def authorize_follow_read(
    request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
) -> FollowPrincipal:
    """Explicitly allowlisted sync reads, challenge and grant; never a write bearer."""
    _route(request, READ_PATHS)
    try:
        payload = decode_access_token(_bearer(authorization), allow_mobile=True)
    except jwt.InvalidTokenError:
        _deny()
    device = payload.get("device_id")
    if (
        payload.get("client_id") != MOBILE_CLIENT_ID
        or payload.get("aud") != MOBILE_AUDIENCE
        or payload.get("scope") != MOBILE_SCOPE
        or not isinstance(device, str)
        or not 0 < len(device) <= 128
    ):
        _deny()
    user = await _account(payload, db, device_id=device)
    server = await _identity(db)
    cohort = await _cohort(db, user, server)  # default-closed project read barrier
    row = await _partition(db, user, server, cohort)
    request.state.audit_user = user
    return FollowPrincipal(user, device, server, PROJECT, cohort, row.owner_generation, payload)


async def authorize_follow_write(
    request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
) -> FollowPrincipal:
    """Only explicit follow write routes. Recheck authoritative generation every call."""
    _route(request, WRITE_PATHS)
    try:
        payload = verify_token(_bearer(authorization))
    except jwt.InvalidTokenError:
        _deny()
    now = int(datetime.now(UTC).timestamp())
    device = payload.get("device_id")
    generation = payload.get("owner_generation")
    if (
        payload.get("type") != "follow-write"
        or payload.get("aud") != AUDIENCE
        or payload.get("scope") != SCOPE
        or payload.get("client_id") != MOBILE_CLIENT_ID
        or not isinstance(device, str)
        or not 0 < len(device) <= 128
        or type(generation) is not int
        or generation < 1
        or type(payload.get("iat")) is not int
        or type(payload.get("exp")) is not int
        or type(payload.get("iat_us")) is not int
        or not payload["iat"] * 1_000_000 <= payload["iat_us"] < (payload["iat"] + 1) * 1_000_000
        or payload["exp"] - payload["iat"] > MAX_TOKEN_SECONDS
        or payload["iat"] > now
        or payload["exp"] <= now
        or payload.get("project_id") != PROJECT
    ):
        _deny()
    server = _uuid(payload.get("server_id"))
    user = await _account(payload, db, device_id=device)
    actual_server = await _identity(db)
    if actual_server != server:
        _deny()
    cohort = await _cohort(db, user, server)
    if cohort != payload.get("cohort"):
        _deny()
    # Acquire the exclusive owner lock BEFORE store admission; upgrading a
    # shared lock under two concurrent writers deadlocks instead of returning
    # the agreed conditional conflict.
    row = await _partition(db, user, server, cohort, exclusive=True)
    if row.owner_generation != generation or row.consent_state != "available" or row.removal_state != "none":
        _deny()
    request.state.audit_user = user
    return FollowPrincipal(user, device, server, PROJECT, cohort, generation, payload)


async def authorize_browser_approval(
    request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
) -> FollowPrincipal:
    """Only a same-issuer ordinary account bearer, never a phone or write JWT."""
    _route(request, frozenset({("POST", "write-approval")}))
    try:
        payload = decode_access_token(_bearer(authorization))
    except jwt.InvalidTokenError:
        _deny()
    # iat alone can be fresh after a silent refresh. Require a signed proof
    # minted only by direct password authentication; refresh never copies it.
    now_us = int(datetime.now(UTC).timestamp() * 1_000_000)
    try:
        issued_us = token_issued_us(payload)
    except (TypeError, ValueError, OverflowError):
        _deny()
    verified_us = payload.get("browser_verified_at_us")
    if (
        type(verified_us) is not int
        or type(issued_us) is not int
        or verified_us != issued_us
        or not 0 <= now_us - verified_us <= 300_000_000
    ):
        _deny(403, "Recent browser verification required")
    user = await _account(payload, db, device_id=None)
    server = await _identity(db)
    cohort = await _cohort(db, user, server)
    row = await _partition(db, user, server, cohort)
    request.state.audit_user = user
    return FollowPrincipal(user, None, server, PROJECT, cohort, row.owner_generation, payload)


def _key(p: FollowPrincipal) -> dict:
    return dict(server_id=p.server_id, project_id=p.project_id, owner_id=p.user.id, cohort=p.cohort)


async def create_challenge(db: AsyncSession, principal: FollowPrincipal) -> str:
    """Return code ONLY to the requesting phone. One active challenge per device."""
    if principal.device_id is None:
        _deny()
    row = await _partition(db, principal.user, principal.server_id, principal.cohort)
    if row.owner_generation != principal.generation or row.consent_state != "available" or row.removal_state != "none":
        _deny()
    code = secrets.token_urlsafe(24)
    now = datetime.now(UTC)
    key = _key(principal)
    old = await db.scalar(
        select(MobileFollowApproval)
        .where(
            *[getattr(MobileFollowApproval, k) == v for k, v in key.items()],
            MobileFollowApproval.device_id == principal.device_id,
        )
        .with_for_update()
    )
    if old is not None:
        await db.delete(old)
        await db.flush()
    db.add(
        MobileFollowApproval(
            **key,
            device_id=principal.device_id,
            challenge_digest=hashlib.sha256(code.encode()).digest(),
            owner_generation=row.owner_generation,
            status="pending",
            issued_at=now,
            expires_at=now + timedelta(seconds=CHALLENGE_SECONDS),
        )
    )
    await db.flush()
    return code


async def approve_challenge(db: AsyncSession, principal: FollowPrincipal, code: str) -> None:
    """Browser supplies the independently entered code; no code/token in response."""
    if not isinstance(code, str) or not 20 <= len(code) <= 64 or not code.isascii():
        _deny(400, "Invalid challenge")
    key = _key(principal)
    digest = hashlib.sha256(code.encode()).digest()
    row = await db.scalar(
        select(MobileFollowApproval)
        .where(
            *[getattr(MobileFollowApproval, k) == v for k, v in key.items()],
            MobileFollowApproval.challenge_digest == digest,
        )
        .with_for_update()
    )
    if row is None or not hmac.compare_digest(row.challenge_digest, digest) or row.status != "pending":
        _deny()
    partition = await _partition(db, principal.user, principal.server_id, principal.cohort)
    if row.owner_generation != partition.owner_generation or principal.generation != partition.owner_generation:
        _deny(409, "generation_conflict")
    if (
        partition.consent_state != "available"
        or partition.removal_state != "none"
        or row.expires_at <= datetime.now(UTC)
    ):
        _deny()
    row.status = "approved"
    row.approved_at = datetime.now(UTC)
    await db.flush()


async def create_write_grant(db: AsyncSession, principal: FollowPrincipal) -> tuple[str, int]:
    """Consume the approved row under lock; caller commits before sending JWT."""
    if principal.device_id is None:
        _deny()
    row = await _partition(db, principal.user, principal.server_id, principal.cohort)
    key = _key(principal)
    approval = await db.scalar(
        select(MobileFollowApproval)
        .where(
            *[getattr(MobileFollowApproval, k) == v for k, v in key.items()],
            MobileFollowApproval.device_id == principal.device_id,
        )
        .with_for_update()
    )
    if (
        row.owner_generation != principal.generation
        or row.consent_state != "available"
        or row.removal_state != "none"
        or approval is None
        or approval.status != "approved"
        or approval.owner_generation != row.owner_generation
        or approval.expires_at <= datetime.now(UTC)
    ):
        _deny()
    now = datetime.now(UTC)
    issued = int(now.timestamp())
    payload = dict(
        sub=str(principal.user.id),
        jti=str(uuid.uuid4()),
        type="follow-write",
        client_id=MOBILE_CLIENT_ID,
        aud=AUDIENCE,
        scope=SCOPE,
        device_id=principal.device_id,
        server_id=str(principal.server_id),
        project_id=principal.project_id,
        cohort=principal.cohort,
        owner_generation=row.owner_generation,
        iat=issued,
        iat_us=issued * 1_000_000 + now.microsecond,
        exp=issued + MAX_TOKEN_SECONDS,
    )
    token = sign_token(payload)
    await db.delete(approval)
    await db.flush()
    return token, MAX_TOKEN_SECONDS
