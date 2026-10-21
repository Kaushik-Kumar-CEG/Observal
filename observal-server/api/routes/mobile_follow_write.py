# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant 1.0.5 follow mutations. Never register before the complete gated flow is approved."""

import hashlib
import json
import secrets
import uuid

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import services.dynamic_settings as settings
from api.deps import get_db
from models.mobile_follow_sync import SAFE
from services import mobile_follow_auth as auth
from services import mobile_follow_privacy as privacy
from services import mobile_follow_store as store
from services.jwt_service import decode_access_token
from services.mobile_follow_browser import enforce_post_limit, issuer_origin, require_browser_request


class StrictErrorRoute(APIRoute):
    """Do not let FastAPI wrap frozen Error bodies in a `detail` envelope."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def strict_handler(request):
            try:
                if request.method == "POST":
                    await enforce_post_limit(request)
                return await handler(request)
            except HTTPException as exc:
                if isinstance(exc.detail, dict) and exc.detail.get("error") in {
                    "invalid_request",
                    "too_large",
                    "unauthorized",
                    "restricted",
                    "generation_conflict",
                    "consent_already_available",
                    "consent_capacity_reached",
                    "revision_exhausted",
                    "unknown_removal",
                    "unknown_withdrawal",
                    "unavailable",
                }:
                    return JSONResponse(status_code=exc.status_code, content=exc.detail)
                return JSONResponse(status_code=503, content={"error": "unavailable"})

        return strict_handler


router = APIRouter(prefix="/api/v1/mobile-follow-sync/v1", tags=["mobile-follow-sync"], route_class=StrictErrorRoute)


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Generation(Body):
    owner_generation: int = Field(strict=True, ge=1, le=SAFE)

    @field_validator("owner_generation")
    @classmethod
    def integer_not_boolean(cls, value):
        if type(value) is not int:
            raise ValueError("integer required")
        return value


class Operation(Generation):
    operation_id: uuid.UUID
    subject_id: uuid.UUID
    base_person_revision: int = Field(strict=True, ge=0, le=SAFE)
    action: str

    @field_validator("action")
    @classmethod
    def action_allowed(cls, value):
        if value not in ("follow", "unfollow"):
            raise ValueError("invalid action")
        return value

    @field_validator("base_person_revision")
    @classmethod
    def base_not_boolean(cls, value):
        if type(value) is not int:
            raise ValueError("integer required")
        return value


class Consent(Generation):
    consent: StrictBool
    consent_id: uuid.UUID


class Withdrawal(Generation):
    confirm: StrictBool
    withdrawal_id: uuid.UUID


class Removal(Generation):
    nonce: str = Field(min_length=24, max_length=256)
    confirm: StrictBool


class Lookup(Body):
    nonce: str = Field(min_length=24, max_length=256)
    original_owner_generation: int = Field(strict=True, ge=1, le=SAFE)

    @field_validator("original_owner_generation")
    @classmethod
    def integer_not_boolean(cls, value):
        if type(value) is not int:
            raise ValueError("integer required")
        return value


def _error(status: int, code: str):
    raise HTTPException(status_code=status, detail={"error": code})


async def _body(request: Request, model):
    try:
        return model.model_validate(await request.json())
    except (ValueError, ValidationError, UnicodeDecodeError):
        _error(400, "invalid_request")


def _id(value: str, kind: str) -> uuid.UUID:
    try:
        result = uuid.UUID(value)
        if str(result) == value:
            return result
    except ValueError:
        pass
    _error(404, "unknown_withdrawal" if kind == "withdrawal" else "unknown_removal")


def _key(p):
    return store.Partition(p.server_id, p.project_id, p.user.id, p.cohort)


def _digest(body) -> bytes:
    return hashlib.sha256(
        json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).digest()


def _nonce(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def _refusal(exc: store.StoreFenceError, *, kind: str, operation_id: uuid.UUID | None = None, generation: int = 1):
    reason = exc.reason
    if kind == "operation":
        if reason == "generation_conflict" and exc.owner_generation is not None:
            generation = exc.owner_generation
        if reason in {
            "generation_conflict",
            "subject_erased",
            "operation_id_reused",
            "capacity_reached",
            "history_capacity_reached",
            "revision_exhausted",
        }:
            return JSONResponse(
                status_code=409,
                content={"error": reason, "operation_id": str(operation_id), "owner_generation": generation},
            )
        if reason == "subject_unavailable":
            _error(403, "restricted")
    if reason in {"unknown", "expired"}:
        _error(404, {"removal": "unknown_removal", "withdrawal": "unknown_withdrawal"}.get(kind, "unknown_operation"))
    if reason in {"invalid_request", "invalid_nonce"}:
        _error(
            400 if reason == "invalid_request" else 409,
            "invalid_request" if reason == "invalid_request" else "generation_conflict",
        )
    if reason in {"generation_conflict", "consent_already_available", "consent_capacity_reached", "revision_exhausted"}:
        _error(409, reason)
    if reason in {"restricted", "subject_erased"}:
        _error(403, "restricted")
    _error(503, "unavailable")


async def _write(request, authorization, db):
    try:
        return await auth.authorize_follow_write(request, authorization, db)
    except HTTPException as exc:
        _error(
            503 if exc.status_code == 503 else 401 if exc.status_code == 401 else 403,
            "unavailable" if exc.status_code == 503 else "unauthorized" if exc.status_code == 401 else "restricted",
        )


async def _read_locked(request, authorization, db):
    # A shared auth partition lock must not be upgraded to exclusive under two readers.
    try:
        p = await auth.authorize_follow_read(request, authorization, db)
        await db.commit()
        user = await auth._account(p.payload, db, device_id=p.device_id)
        server = await auth._identity(db)
        if user.id != p.user.id or server != p.server_id or await auth._cohort(db, user, server) != p.cohort:
            _error(401, "unauthorized")
        await auth._partition(db, user, server, p.cohort, exclusive=True)
        return p
    except HTTPException as exc:
        _error(
            503 if exc.status_code == 503 else 401 if exc.status_code == 401 else 403,
            "unavailable" if exc.status_code == 503 else "unauthorized" if exc.status_code == 401 else "restricted",
        )


async def _browser(request, authorization, db, *, consent=False):
    allowed = (
        frozenset({("POST", "consent")})
        if consent
        else frozenset(
            {
                ("POST", "consent/withdraw"),
                ("GET", "consent/withdrawals/" + request.path_params.get("withdrawal_id", "")),
            }
        )
    )
    try:
        auth._route(request, allowed)
        if request.method == "POST":
            origin = issuer_origin(
                settings.get_sync("deployment.public_url"), settings.get_sync("deployment.frontend_url")
            )
            require_browser_request(request, origin)
        payload = decode_access_token(auth._bearer(authorization))
        user = await auth._account(payload, db, device_id=None)
        server = await auth._identity(db)
        cohort = await auth._cohort(db, user, server)
        key = store.Partition(server, auth.PROJECT, user.id, cohort)
        await store.locked_partition(db, key, create=consent)
        request.state.audit_user = user
        return key
    except jwt.InvalidTokenError:
        _error(401, "unauthorized")
    except store.StoreFenceError as exc:
        _refusal(exc, kind="consent" if consent else "withdrawal")
    except HTTPException as exc:
        _error(
            503 if exc.status_code == 503 else 401 if exc.status_code == 401 else 403,
            "unavailable" if exc.status_code == 503 else "unauthorized" if exc.status_code == 401 else "restricted",
        )


def _is_browser(authorization):
    # Not a trust decision: merely select a verification path. Both paths validate.
    try:
        decode_access_token(auth._bearer(authorization))
        return True
    except (jwt.InvalidTokenError, HTTPException):
        return False


def _receipt(result, kind):
    return {
        f"{kind}_id": result["action_id"],
        "state": result["status"],
        "owner_generation": result["owner_generation"],
        **({"revision": 0} if kind == "removal" else {}),
        "recovery_mode": result["recovery_mode"],
    }


@router.post("/operations")
async def operations(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    p = await _write(request, authorization, db)
    body = await _body(request, Operation)
    # Write authorization locks the owner. Release it before taking the subject
    # lock: the users DELETE trigger takes subject then owner. Re-authorize under
    # the held subject lock so no stale grant can write after a privacy fence.
    await db.commit()
    try:
        await db.scalar(text("SELECT id FROM users WHERE id=:subject FOR KEY SHARE"), {"subject": body.subject_id})
        p = await _write(request, authorization, db)
        status, result = await store.admit_operation(
            db,
            _key(p),
            operation_id=body.operation_id,
            subject_id=body.subject_id,
            owner_generation=body.owner_generation,
            base_person_revision=body.base_person_revision,
            action=body.action,
            body_digest=_digest(body),
        )
        await db.commit()
        return JSONResponse(status_code=status, content=result)
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="operation", operation_id=body.operation_id, generation=body.owner_generation)


@router.post("/consent")
async def consent(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    key = await _browser(request, authorization, db, consent=True)
    body = await _body(request, Consent)
    if body.consent is not True:
        _error(400, "invalid_request")
    try:
        result = await privacy.accept_consent(
            db,
            key,
            consent_id=body.consent_id,
            owner_generation=body.owner_generation,
            body_digest=_digest(body),
            browser_owner_approved=True,
        )
        await db.commit()
        return {"state": result["status"], "owner_generation": result["owner_generation"]}
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="consent")


@router.post("/consent/withdraw", status_code=202)
async def withdraw(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    if _is_browser(authorization):
        key = await _browser(request, authorization, db)
    else:
        key = _key(await _write(request, authorization, db))
    body = await _body(request, Withdrawal)
    if body.confirm is not True:
        _error(400, "invalid_request")
    try:
        result = await privacy.admit_privacy_action(
            db,
            key,
            kind="withdrawal",
            action_id=body.withdrawal_id,
            owner_generation=body.owner_generation,
            confirmed_authorized=True,
            body_digest=privacy.withdrawal_body_digest(body.withdrawal_id, body.owner_generation),
        )
        await db.commit()
        return _receipt(result, "withdrawal")
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="withdrawal")


@router.get("/consent/withdrawals/{withdrawal_id}")
async def withdrawal_status(
    withdrawal_id: str, request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
):
    if _is_browser(authorization):
        key = await _browser(request, authorization, db)
    else:
        key = _key(await _read_locked(request, authorization, db))
    try:
        result = await privacy.privacy_status(db, key, _id(withdrawal_id, "withdrawal"), kind="withdrawal")
        await db.commit()
        return _receipt(result, "withdrawal")
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="withdrawal")


@router.post("/removals/prepare")
async def prepare(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    p = await _write(request, authorization, db)
    nonce = secrets.token_urlsafe(32)
    key = _key(p)
    try:
        await store.locked_partition(db, key)
        await db.execute(
            text(f"""INSERT INTO mobile_follow_nonces ({store.COLS},device_id,nonce_digest,owner_generation,issued_at,expires_at)
            VALUES ({store.VALUES},:device,:digest,:gen,statement_timestamp(),statement_timestamp()+interval '120 seconds')
            ON CONFLICT ({store.COLS},device_id) DO UPDATE SET nonce_digest=EXCLUDED.nonce_digest,
            owner_generation=EXCLUDED.owner_generation,issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at"""),
            {**key.params(), "device": p.device_id, "digest": _nonce(nonce), "gen": p.generation},
        )
        await db.commit()
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="removal")
    return {
        "nonce": nonce,
        "expires_in": 120,
        "server_id": str(p.server_id),
        "project_id": p.project_id,
        "viewer_id": str(p.user.id),
        "cohort": auth.wire_cohort(p.cohort),
        "owner_generation": p.generation,
    }


@router.post("/removals", status_code=202)
async def remove(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    p = await _write(request, authorization, db)
    body = await _body(request, Removal)
    if body.confirm is not True:
        _error(400, "invalid_request")
    try:
        result = await privacy.admit_privacy_action(
            db,
            _key(p),
            kind="removal",
            action_id=uuid.uuid4(),
            owner_generation=body.owner_generation,
            confirmed_authorized=True,
            device_id=p.device_id,
            nonce_digest=_nonce(body.nonce),
        )
        await db.commit()
        return _receipt(result, "removal")
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="removal")


@router.post("/removals/lookup")
async def removal_lookup(
    request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
):
    p = await _read_locked(request, authorization, db)
    body = await _body(request, Lookup)
    try:
        result = await privacy.removal_by_nonce(
            db,
            _key(p),
            device_id=p.device_id,
            nonce_digest=_nonce(body.nonce),
            original_generation=body.original_owner_generation,
        )
        await db.commit()
        return _receipt(result, "removal")
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="removal")


@router.get("/removals/{removal_id}")
async def removal_status(
    removal_id: str, request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
):
    p = await _read_locked(request, authorization, db)
    try:
        result = await privacy.privacy_status(db, _key(p), _id(removal_id, "removal"), kind="removal")
        await db.commit()
        return _receipt(result, "removal")
    except store.StoreFenceError as exc:
        await db.rollback()
        return _refusal(exc, kind="removal")
