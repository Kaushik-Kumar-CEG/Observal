# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant follow-sync 1.0.5 reads. Intentionally NOT registered on the API."""

import re
import uuid

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from services import mobile_follow_auth as auth
from services import mobile_follow_cursor as cursor
from services.jwt_service import MOBILE_AUDIENCE, MOBILE_CLIENT_ID, MOBILE_SCOPE, decode_access_token
from services.mobile_follow_store import (
    KEY as STORE_KEY,
)
from services.mobile_follow_store import (
    Partition,
    StoreFenceError,
    admit_lease,
    lease_page,
    operation_status,
)


class ReadRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def strict_errors(request: Request):
            try:
                return await handler(request)
            except HTTPException as exc:
                if exc.status_code in (401, 403, 503):
                    return error(
                        {401: "unauthorized", 403: "restricted", 503: "unavailable"}[exc.status_code],
                        exc.status_code,
                        retry=exc.status_code == 503,
                    )
                raise

        return strict_errors


router = APIRouter(prefix="/api/v1/mobile-follow-sync/v1", tags=["mobile-follow-sync"], route_class=ReadRoute)
SAFE = 9007199254740991
CANONICAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def error(code: str, status: int, *, retry: bool = False) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers={"Retry-After": "1"} if retry else None)


def number(value: str | None, *, default: int | None = None, positive: bool = False) -> int:
    if value is None:
        if default is None:
            raise ValueError("missing")
        return default
    if not CANONICAL.fullmatch(value) or len(value) > 16:
        raise ValueError("noncanonical")
    result = int(value)
    if result > SAFE or (positive and not result):
        raise ValueError("out of range")
    return result


async def principal_for(request: Request, authorization: str | None, db: AsyncSession, *, browser: bool = False):
    """Authenticate before an EXCLUSIVE partition lock; never upgrade a shared lock."""
    auth._route(request, auth.READ_PATHS)
    try:
        payload = decode_access_token(auth._bearer(authorization), allow_mobile=not browser)
    except jwt.InvalidTokenError:
        auth._deny()
    device = payload.get("device_id")
    if browser:
        if payload.get("client_id") == MOBILE_CLIENT_ID or device is not None:
            auth._deny()
        device = None
    elif (
        payload.get("client_id") != MOBILE_CLIENT_ID
        or payload.get("aud") != MOBILE_AUDIENCE
        or payload.get("scope") != MOBILE_SCOPE
        or not isinstance(device, str)
        or not 0 < len(device) <= 128
    ):
        auth._deny()
    user = await auth._account(payload, db, device_id=device)
    server = await auth._identity(db)
    cohort = await auth._cohort(db, user, server)
    row = await auth._partition(
        db,
        user,
        server,
        cohort,
        exclusive=True,
        create=request.url.path.endswith(("/availability", "/consent/state")),
    )
    request.state.audit_user = user
    return auth.FollowPrincipal(user, device, server, auth.PROJECT, cohort, row.owner_generation, payload), row


def key_for(p: auth.FollowPrincipal) -> Partition:
    return Partition(p.server_id, p.project_id, p.user.id, p.cohort)


def state(row) -> str:
    if row.removal_state != "none" or row.consent_state == "withdrawal_pending":
        return "withdrawal_pending"
    return row.consent_state


def _available(row) -> bool:
    return row.consent_state == "available" and row.removal_state == "none"


@router.get("/availability")
async def availability(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    p, row = await principal_for(request, authorization, db)
    await db.commit()
    return dict(
        version="1.0.5",
        state=state(row),
        server_id=str(p.server_id),
        project_id=p.project_id,
        viewer_id=str(p.user.id),
        cohort=auth.wire_cohort(p.cohort),
        owner_generation=row.owner_generation,
        current_revision=row.current_revision,
        max_page_size=100,
        max_distinct_subjects=1000,
        max_read_leases=4,
        max_pinned_logical_bytes=2097152,
        max_retained_history_logical_bytes=16777216,
        max_normal_edits_90d=10000,
        max_protected_unfollows_90d=1000,
        read_lease_seconds=900,
        offline_horizon_days=30,
    )


@router.get("/consent/state")
async def consent_state(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    _, row = await principal_for(request, authorization, db, browser=True)
    visible = state(row)
    if visible not in ("available", "disabled", "consent_required", "withdrawal_pending"):
        return error("restricted", 403)
    await db.commit()
    return {"state": visible, "owner_generation": row.owner_generation}


def _store_error(reason: str) -> JSONResponse:
    if reason == "restricted":
        return error("restricted", 403)
    if reason in ("snapshot_required", "generation_conflict"):
        return error(reason, 409)
    if reason == "invalid_request":
        return error(reason, 400)
    return error("unavailable", 503, retry=True)


async def _page(request: Request, authorization: str | None, db: AsyncSession, purpose: str):
    p, row = await principal_for(request, authorization, db)
    q = request.query_params
    try:
        if len(q.getlist("limit")) > 1 or len(q.getlist("cursor")) > 1:
            raise ValueError
        limit = number(q.get("limit"), default=100)
        if limit != 100:
            raise ValueError
        after = generation = None
        if purpose == "changes":
            if len(q.getlist("after_revision")) != 1 or len(q.getlist("owner_generation")) != 1:
                raise ValueError
            after = number(q.get("after_revision"))
            generation = number(q.get("owner_generation"), positive=True)
            if q.get("min_revision") is not None:
                raise ValueError
        else:
            if (
                len(q.getlist("min_revision")) > 1
                or q.get("after_revision") is not None
                or q.get("owner_generation") is not None
            ):
                raise ValueError
            minimum = number(q.get("min_revision"), default=0)
        if q.get("cursor") is not None:
            lease_id, position = cursor.verify(
                q["cursor"],
                purpose=purpose,
                server_id=p.server_id,
                project_id=p.project_id,
                owner_id=p.user.id,
                device_id=p.device_id,
                cohort=p.cohort,
                generation=row.owner_generation,
            )
            if not _available(row):
                return error("restricted", 403)
            if purpose == "changes":
                bound_after = await db.scalar(
                    text(
                        f"SELECT after_revision FROM mobile_follow_leases WHERE {STORE_KEY} AND lease_id=:lease AND kind='changes'"
                    ),
                    {**key_for(p).params(), "lease": lease_id},
                )
                if bound_after is None or bound_after != after or generation != row.owner_generation:
                    return error("snapshot_required", 409)
        else:
            # Generation mismatch is authoritative even during a pending
            # removal; a prior checkpoint cannot be mistaken for permission.
            if purpose == "changes" and generation != row.owner_generation:
                return error("generation_conflict", 409)
            if not _available(row):
                return error("restricted", 403)
            position = 0
            if purpose != "changes" and (
                row.current_revision < minimum or await _stale_image(db, key_for(p), minimum, row.owner_generation)
            ):
                return error("unavailable", 503, retry=True)
            lease_id = await admit_lease(
                db,
                key_for(p),
                kind="changes" if purpose == "changes" else "image",
                device_id=p.device_id if purpose == "changes" else None,
                after_revision=after,
                min_revision=0 if purpose == "changes" else minimum,
            )
        # The store owns a fixed PostgreSQL lease and one-shot per-keyset throttle.
        page = await lease_page(
            db,
            key_for(p),
            lease_id,
            kind="changes" if purpose == "changes" else "image",
            last_row=position,
            device_id=p.device_id if purpose == "changes" else None,
            throttle=True,
        )
    except cursor.GenerationConflict:
        return error("generation_conflict", 409)
    except (ValueError, cursor.InvalidCursor):
        return error("invalid_request", 400)
    except StoreFenceError as exc:
        if exc.reason != "rate_limited":
            return _store_error(exc.reason)
        # Persist both the initial lease and throttle before returning a retry capability.
        # Retrieve its fixed expiry while the exclusive owner lock is still held.
        expiry = await _lease_expiry(db, key_for(p), lease_id)
        if expiry is None:
            return error("unavailable", 503, retry=True)
        retry_cursor = cursor.issue(
            purpose=purpose,
            server_id=p.server_id,
            project_id=p.project_id,
            owner_id=p.user.id,
            device_id=p.device_id,
            cohort=p.cohort,
            generation=row.owner_generation,
            lease_id=lease_id,
            last_row=position,
            expires_at=expiry,
        )
        await db.commit()
        return JSONResponse(
            {"error": "rate_limited", "read_lease_id": str(lease_id), "retry_cursor": retry_cursor},
            status_code=429,
            headers={"Retry-After": "1"},
        )
    next_cursor = None
    if not page["complete"]:
        expiry = await _lease_expiry(db, key_for(p), lease_id)
        if expiry is None:
            return error("unavailable", 503, retry=True)
        next_cursor = cursor.issue(
            purpose=purpose,
            server_id=p.server_id,
            project_id=p.project_id,
            owner_id=p.user.id,
            device_id=p.device_id,
            cohort=p.cohort,
            generation=page["owner_generation"],
            lease_id=lease_id,
            last_row=page["last_row"],
            expires_at=expiry,
        )
    result = dict(
        owner_generation=page["owner_generation"],
        revision=page["revision"],
        read_lease_id=str(lease_id),
        erasure_floor=page["erasure_floor"],
        next_cursor=next_cursor,
        complete=page["complete"],
    )
    if purpose == "changes":
        result["changes"] = [
            dict(
                subject_id=str(item["subject_id"]),
                action="follow" if item["following"] else "unfollow",
                person_revision=item["person_revision"],
                revision=item["revision"],
                change_ordinal=item["ordinal"],
            )
            for item in page["items"]
        ]
    else:
        result.update(
            server_id=str(p.server_id),
            project_id=p.project_id,
            viewer_id=str(p.user.id),
            cohort=auth.wire_cohort(p.cohort),
        )
        result["items"] = [
            dict(subject_id=str(item["subject_id"]), person_revision=item["person_revision"]) for item in page["items"]
        ]
    await db.commit()
    return result


async def _stale_image(db: AsyncSession, key: Partition, minimum: int, generation: int) -> bool:
    if not minimum:
        return False
    # Do not take another image slot when an existing shared image is too old.
    return bool(
        await db.scalar(
            text(
                f"SELECT EXISTS (SELECT 1 FROM mobile_follow_leases WHERE {STORE_KEY} "
                "AND kind='image' AND owner_generation=:generation AND pinned_revision<:minimum "
                "AND expires_at>clock_timestamp())"
            ),
            {**key.params(), "generation": generation, "minimum": minimum},
        )
    )


async def _lease_expiry(db: AsyncSession, key: Partition, lease_id: uuid.UUID):
    return await db.scalar(
        text(f"SELECT expires_at FROM mobile_follow_leases WHERE {STORE_KEY} AND lease_id=:lease"),
        {**key.params(), "lease": lease_id},
    )


@router.get("/snapshot")
async def snapshot(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    return await _page(request, authorization, db, "snapshot")


@router.get("/export")
async def export(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    return await _page(request, authorization, db, "export")


@router.get("/changes")
async def changes(request: Request, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)):
    return await _page(request, authorization, db, "changes")


@router.get("/operations/{operation_id}")
async def operation(
    request: Request, operation_id: str, authorization: str | None = Header(None), db: AsyncSession = Depends(get_db)
):
    p, _ = await principal_for(request, authorization, db)
    try:
        parsed = uuid.UUID(operation_id)
        if str(parsed) != operation_id:
            raise ValueError
        outcome = await operation_status(db, key_for(p), parsed)
    except ValueError:
        return error("invalid_request", 400)
    except StoreFenceError as exc:
        return error(
            "dedup_expired" if exc.reason == "expired" else "unknown_operation", 410 if exc.reason == "expired" else 404
        )
    await db.commit()
    return outcome
