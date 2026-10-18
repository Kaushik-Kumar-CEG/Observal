# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Super-admin-only, deny-first operator control of the disposable phone cohort.

An image deploy never enables reads. Opening and closing take the same
transaction-scoped exclusive project lock as retention and all phone readers.
The workflow never sets the live trace qualification or trace_headlines switch.
"""

from uuid import UUID, uuid4

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

import services.dynamic_settings as ds
from api.deps import get_db, require_role
from models.enterprise_config import EnterpriseConfig
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.redis import get_redis
from services.security_events import EventType, SecurityEvent, Severity, emit_security_event
from services.token_revocation import revoke_user_tokens

from ._router import router

_ACK = "isolated-disposable-synthetic-only-v1"
_KEYS = (
    "mobile.auth_enabled",
    "mobile.synthetic_test_enabled",
    "mobile.synthetic_test_server_id",
    "mobile.synthetic_test_viewer_id",
    "mobile.synthetic_test_self_user_viewer_id",
    "mobile.synthetic_test_ack",
    "mobile.trace_qualification_server_id",
    "mobile.trace_qualification_ack",
    "trace_headlines",
)


class MobileTestSetup(BaseModel):
    server_id: UUID
    author_viewer_id: UUID
    user_viewer_id: UUID
    acknowledgement: str


class MobileTestStatus(BaseModel):
    blocked: bool
    generation: int
    server_id: UUID | None
    author_viewer_id: UUID | None
    user_viewer_id: UUID | None
    configured: bool
    trace_headlines: bool
    revocation_pending: bool = False


async def _lock(db: AsyncSession) -> None:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": "mobile-read:" + str(DEFAULT_PROJECT_ID)},
    )


async def _settings(db: AsyncSession) -> dict[str, str]:
    rows = await db.execute(select(EnterpriseConfig.key, EnterpriseConfig.value).where(EnterpriseConfig.key.in_(_KEYS)))
    values = {key: value for key, value in rows.all()}
    return {key: values.get(key, ds.DEFAULTS.get(key, "")) for key in _KEYS}


async def _status(db: AsyncSession) -> MobileTestStatus:
    values = await _settings(db)
    row = (
        await db.execute(
            text("SELECT blocked,generation FROM mobile_read_controls WHERE project_id=:project"),
            {"project": str(DEFAULT_PROJECT_ID)},
        )
    ).one_or_none()
    latest_action = await db.scalar(
        text(
            "SELECT action FROM mobile_operator_audit WHERE project_id=:project "
            "ORDER BY created_at DESC,id DESC LIMIT 1"
        ),
        {"project": str(DEFAULT_PROJECT_ID)},
    )

    def ident(key: str) -> UUID | None:
        try:
            return UUID(values[key])
        except (ValueError, TypeError):
            return None

    return MobileTestStatus(
        blocked=bool(row.blocked) if row else True,
        generation=row.generation if row else 0,
        server_id=ident("mobile.synthetic_test_server_id"),
        author_viewer_id=ident("mobile.synthetic_test_viewer_id"),
        user_viewer_id=ident("mobile.synthetic_test_self_user_viewer_id"),
        configured=values["mobile.synthetic_test_enabled"] == "true"
        and values["mobile.auth_enabled"] == "true"
        and values["mobile.synthetic_test_ack"] == _ACK,
        trace_headlines=values["trace_headlines"] == "true",
        revocation_pending=latest_action == "revoking",
    )


async def _write(db: AsyncSession, values: dict[str, str]) -> None:
    for key, value in values.items():
        if ds.is_externally_managed(key):
            raise HTTPException(409, "Mobile setting is externally managed")
        await db.execute(
            text(
                "INSERT INTO enterprise_config(id,key,value,updated_at) VALUES (:id,:key,:value,now()) "
                "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()"
            ),
            {"id": uuid4(), "key": key, "value": value},
        )


async def _record_transition(
    db: AsyncSession, actor: User, action: str, cohort: MobileTestStatus, generation: int
) -> None:
    # Commit with the setting/barrier mutation. A ClickHouse security event is
    # additionally emitted after commit but must not be the only audit sink.
    await db.execute(
        text(
            "INSERT INTO mobile_operator_audit(project_id,actor_id,action,generation,server_id,"
            "author_viewer_id,user_viewer_id) VALUES "
            "(:project,:actor,:action,:generation,:server,:author,:user)"
        ),
        {
            "project": str(DEFAULT_PROJECT_ID),
            "actor": actor.id,
            "action": action,
            "generation": generation,
            "server": cohort.server_id,
            "author": cohort.author_viewer_id,
            "user": cohort.user_viewer_id,
        },
    )


async def _refresh(values: dict[str, str]) -> None:
    for key in values:
        await ds.invalidate(key)
    await ds.refresh_sync_cache()


async def _audit(actor: User, action: str) -> None:
    await emit_security_event(
        SecurityEvent(
            event_type=EventType.SETTING_CHANGED,
            severity=Severity.WARNING if action != "revoke" else Severity.CRITICAL,
            outcome="success",
            actor_id=str(actor.id),
            actor_email=actor.email,
            actor_role=actor.role.value,
            target_id="mobile-test-cohort",
            target_type="mobile_test_setup",
            detail=f"Mobile test cohort {action}",
        )
    )


@router.get("/mobile-test/status", response_model=MobileTestStatus)
async def mobile_test_status(
    db: AsyncSession = Depends(get_db), actor: User = Depends(require_role(UserRole.super_admin))
):
    del actor
    await _lock(db)
    return await _status(db)


@router.post("/mobile-test/setup", response_model=MobileTestStatus)
async def mobile_test_setup(
    req: MobileTestSetup,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role(UserRole.super_admin)),
):
    if req.acknowledgement != _ACK or req.author_viewer_id == req.user_viewer_id:
        raise HTTPException(422, "Explicit disposable cohort acknowledgement and two distinct viewers required")
    await _lock(db)
    current = await _status(db)
    if not current.blocked or current.trace_headlines or current.revocation_pending or not current.generation:
        raise HTTPException(409, "A migrated, closed read barrier and disabled live qualification are required")
    server_id = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
    if str(server_id) != str(req.server_id):
        raise HTTPException(409, "This is not the selected mobile server")
    values = await _settings(db)
    if values["mobile.trace_qualification_server_id"] or values["mobile.trace_qualification_ack"]:
        raise HTTPException(409, "Live qualification must be absent")
    users = await db.scalars(
        select(User).where(User.id.in_((req.author_viewer_id, req.user_viewer_id)), User.auth_provider != "deactivated")
    )
    principals = {user.id: user for user in users.all()}
    if len(principals) != 2 or principals[req.author_viewer_id].role != UserRole.super_admin:
        raise HTTPException(422, "Two active test viewers required; Author must be super-admin")
    # Reserved DNS TLDs are explicit disposable-account markers. An operator
    # acknowledgement alone must not unlock a real registered person's data.
    if any(
        "@" not in user.email or not user.email.rsplit("@", 1)[1].lower().endswith((".test", ".invalid"))
        for user in principals.values()
    ):
        raise HTTPException(422, "Both viewers must use reserved .test or .invalid email domains")
    changes = {
        "mobile.auth_enabled": "true",
        "mobile.synthetic_test_enabled": "true",
        "mobile.synthetic_test_server_id": str(req.server_id),
        "mobile.synthetic_test_viewer_id": str(req.author_viewer_id),
        "mobile.synthetic_test_self_user_viewer_id": str(req.user_viewer_id),
        "mobile.synthetic_test_ack": _ACK,
        "trace_headlines": "false",
    }
    await _write(db, changes)
    await _record_transition(
        db,
        actor,
        "setup",
        MobileTestStatus(
            blocked=True,
            generation=current.generation,
            server_id=req.server_id,
            author_viewer_id=req.author_viewer_id,
            user_viewer_id=req.user_viewer_id,
            configured=True,
            trace_headlines=False,
        ),
        current.generation,
    )
    await db.commit()
    await _refresh(changes)
    await _audit(actor, "setup (closed)")
    return await _status(db)


@router.post("/mobile-test/open", response_model=MobileTestStatus)
async def mobile_test_open(
    req: MobileTestSetup,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role(UserRole.super_admin)),
):
    if req.acknowledgement != _ACK:
        raise HTTPException(422, "Explicit disposable cohort acknowledgement required")
    await _lock(db)
    status = await _status(db)
    values = await _settings(db)
    identity = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
    if (
        not status.blocked
        or status.revocation_pending
        or not status.configured
        or status.trace_headlines
        or values["mobile.trace_qualification_server_id"]
        or values["mobile.trace_qualification_ack"]
        or str(identity) != str(req.server_id)
        or status.server_id != req.server_id
        or status.author_viewer_id != req.author_viewer_id
        or status.user_viewer_id != req.user_viewer_id
        or req.author_viewer_id == req.user_viewer_id
    ):
        raise HTTPException(409, "Closed, matching, live-disabled test setup required")
    changed = await db.execute(
        text(
            "UPDATE mobile_read_controls SET blocked=false,generation=generation+1,updated_at=now() "
            "WHERE project_id=:project AND blocked=true RETURNING generation"
        ),
        {"project": str(DEFAULT_PROJECT_ID)},
    )
    generation = changed.scalar_one_or_none()
    if generation is None:
        raise HTTPException(409, "Missing or already opened read barrier")
    await _record_transition(db, actor, "open", status, generation)
    await db.commit()
    await _audit(actor, "opened")
    return await _status(db)


@router.post("/mobile-test/revoke", response_model=MobileTestStatus)
async def mobile_test_revoke(
    db: AsyncSession = Depends(get_db), actor: User = Depends(require_role(UserRole.super_admin))
):
    # Commit deny BEFORE touching any setting or key: a failed second phase
    # still leaves every named phone read behind the closed barrier.
    await _lock(db)
    prior = await _status(db)
    changed = await db.execute(
        text(
            "INSERT INTO mobile_read_controls(project_id,blocked,generation) VALUES (:project,true,1) "
            "ON CONFLICT (project_id) DO UPDATE SET blocked=true,generation=mobile_read_controls.generation+1,"
            "updated_at=now() RETURNING generation"
        ),
        {"project": str(DEFAULT_PROJECT_ID)},
    )
    # Disallow minting in the same committed transaction as the first deny.
    # In-flight device redemption/refresh holds the shared project lock, so
    # all tokens minted earlier are covered by the later Redis marker.
    disable = {"mobile.auth_enabled": "false", "mobile.synthetic_test_enabled": "false", "trace_headlines": "false"}
    await _write(db, disable)
    await _record_transition(db, actor, "revoking", prior, changed.scalar_one())
    await db.commit()
    await _refresh(disable)
    await _audit(actor, "denied")
    # These are explicitly disposable principals. Revoke both desktop and
    # mobile grants so an old scoped token cannot regain access after a later
    # setup with the same IDs. Redis auth is fail-closed if revocation fails.
    for viewer_id in (prior.author_viewer_id, prior.user_viewer_id):
        if viewer_id is not None:
            await revoke_user_tokens(get_redis(), viewer_id)
    # The first commit drops the transaction lock. Another operator could run
    # setup+open before settings are cleared; take it again and close the gate
    # in the SAME transaction as clearing the cohort.
    await _lock(db)
    changes = {
        "mobile.auth_enabled": "false",
        "mobile.synthetic_test_enabled": "false",
        "mobile.synthetic_test_server_id": "",
        "mobile.synthetic_test_viewer_id": "",
        "mobile.synthetic_test_self_user_viewer_id": "",
        "mobile.synthetic_test_ack": "",
        "mobile.trace_qualification_server_id": "",
        "mobile.trace_qualification_ack": "",
        "trace_headlines": "false",
    }
    await _write(db, changes)
    final = await db.execute(
        text(
            "UPDATE mobile_read_controls SET blocked=true,generation=generation+1,updated_at=now() "
            "WHERE project_id=:project RETURNING generation"
        ),
        {"project": str(DEFAULT_PROJECT_ID)},
    )
    await _record_transition(db, actor, "revoke", prior, final.scalar_one())
    await db.commit()
    await _refresh(changes)
    await _audit(actor, "revoke")
    return await _status(db)
