# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
# SPDX-FileCopyrightText: 2026 Lokesh <lokeshselvam7025@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Session JSONL ingest endpoint."""

import asyncio
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from loguru import logger as optic
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db, require_role
from api.ratelimit import limiter
from database import async_session
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID

MAX_SHORT_STRING_LENGTH = 512
MAX_TEXT_LENGTH = 1_048_576

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])
# Waiting on a PostgreSQL project advisory lock consumes a pooled connection.
# Bound same-process Pi ingress to leave pool headroom for auth, denial,
# high-water writes, ordinary API requests and the projection worker.
_MOBILE_INGEST_SLOTS = asyncio.Semaphore(4)

MAX_SESSION_LINES = 1000
MAX_SESSION_TOTAL_LINES = 10_000_000


MAX_CAPABILITIES_PER_PUSH = 200
_CAPABILITY_KINDS = {"agent", "mcp", "skill", "hook", "prompt", "sandbox", "external"}
# delegated: the session handed a task to this agent (ADR 0002)
_CAPABILITY_MODES = {"context", "next-session", "delegated"}
_CAPABILITY_CONFIDENCE = {"exact", "window", "loose"}


class CapabilityUsed(BaseModel):
    """One discovery resource the CLI recorded as used in this session (from the capability lock)."""

    identifier: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    kind: str = Field(..., max_length=32)
    component_id: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    native_ref: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    version: str | None = Field(None, max_length=64)
    digest: str | None = Field(None, max_length=96)
    mode: str = Field("context", max_length=32)
    source: str = Field("unknown", max_length=32)
    used_at: str = Field(..., max_length=64)
    confidence: str = Field("window", max_length=16)

    @field_validator("kind")
    @classmethod
    def kind_is_known(cls, value: str) -> str:
        if value not in _CAPABILITY_KINDS:
            raise ValueError(f"unknown capability kind: {value}")
        return value

    @field_validator("mode")
    @classmethod
    def mode_is_known(cls, value: str) -> str:
        if value not in _CAPABILITY_MODES:
            raise ValueError(f"unknown capability mode: {value}")
        return value

    @field_validator("confidence")
    @classmethod
    def confidence_is_known(cls, value: str) -> str:
        if value not in _CAPABILITY_CONFIDENCE:
            raise ValueError(f"unknown capability confidence: {value}")
        return value

    @model_validator(mode="after")
    def has_some_identity(self):
        if not (self.identifier or self.component_id or self.native_ref):
            raise ValueError("a capability needs an identifier, component_id or native_ref")
        return self


class SessionIngestRequest(BaseModel):
    session_id: str = Field(..., max_length=MAX_SHORT_STRING_LENGTH)
    harness: str = Field("claude-code", max_length=MAX_SHORT_STRING_LENGTH)
    agent_id: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    agent_version: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    layer_hash: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    lines: list[str] = Field(..., max_length=MAX_SESSION_LINES)  # Raw JSONL lines
    start_offset: int = Field(0, ge=0)
    end_byte_offsets: list[int] | None = Field(None, max_length=MAX_SESSION_LINES)
    hook_event: str = Field("UserPromptSubmit", max_length=MAX_SHORT_STRING_LENGTH)
    # Sent on Stop for integrity check
    final: bool = False
    total_line_count: int | None = Field(None, ge=0, le=MAX_SESSION_TOTAL_LINES)
    total_offset: int | None = Field(None, ge=0)
    session_hash: str | None = Field(None, max_length=128)
    hashed_line_count: int | None = Field(None, ge=0, le=MAX_SESSION_TOTAL_LINES)
    # Kiro-specific: total credits consumed this session
    total_credits: float | None = Field(None, ge=0)
    # Claude Code subagent attribution: set when this session is a subagent
    parent_session_id: str | None = Field(None, max_length=MAX_SHORT_STRING_LENGTH)
    # Optional upgraded Pi identity; legacy senders remain unqualified.
    run_incarnation: UUID | None = None
    run_header_hash: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")
    # Only emitted by an upgraded Pi session_start handler, never inferred from JSONL.
    run_origin: Literal["pi_session_start_root_v1"] | None = None
    # Claimed only by an upgraded Pi sender after reading its parent's
    # immutable on-disk header and saved incarnation, never inferred by ID.
    parent_run_incarnation: UUID | None = None
    parent_header_hash: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")
    # Discovery resources the CLI's capability lock attributes to this session
    capabilities_used: list[CapabilityUsed] | None = Field(None, max_length=MAX_CAPABILITIES_PER_PUSH)

    @field_validator("lines")
    @classmethod
    def lines_are_bounded(cls, value: list[str]) -> list[str]:
        for line in value:
            if len(line) > MAX_TEXT_LENGTH:
                raise ValueError(f"session lines must be at most {MAX_TEXT_LENGTH} characters")
        return value

    @model_validator(mode="after")
    def byte_offsets_match_lines(self):
        if self.end_byte_offsets is not None:
            if len(self.end_byte_offsets) != len(self.lines):
                raise ValueError("end_byte_offsets must contain one value per source line")
            if any(offset < 0 for offset in self.end_byte_offsets):
                raise ValueError("end_byte_offsets cannot contain negative values")
            if self.end_byte_offsets != sorted(self.end_byte_offsets):
                raise ValueError("end_byte_offsets must be ordered")
        if self.session_hash is not None and self.hashed_line_count is None:
            raise ValueError("hashed_line_count is required with session_hash")
        if (
            self.hashed_line_count is not None
            and self.total_line_count is not None
            and self.hashed_line_count > self.total_line_count
        ):
            raise ValueError("hashed_line_count cannot exceed total_line_count")
        return self


class SessionIngestResponse(BaseModel):
    ingested: int
    skipped: int
    errors: int
    acknowledged_line: int
    acknowledged_offset: int
    integrity_ok: bool | None = None  # Only set when final=True
    server_hash: str | None = None
    repair_from_line: int | None = None


class SessionCheckpointResponse(BaseModel):
    session_id: str
    harness: str
    acknowledged_line: int
    acknowledged_offset: int


@router.post("/session", response_model=SessionIngestResponse)
@limiter.limit("60/minute")
async def ingest_session(
    req: SessionIngestRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.user)),
    auth_db: AsyncSession = Depends(get_db),
):
    """Ingest raw JSONL transcript lines from an harness session.

    Called by the session_push hook on each UserPromptSubmit and Stop event.
    Lines are stored as-is and classified server-side.
    """
    optic.trace("user_id={}", current_user.id)
    user_id = str(current_user.id)
    project_id = DEFAULT_PROJECT_ID
    if req.harness == "pi":
        # get_db is the cached JWT-auth dependency. Its read-only transaction
        # must release the pool connection BEFORE the bounded semaphore AND
        # BEFORE run admission (which itself awaits ClickHouse with PG held).
        # expire_on_commit=False preserves the authenticated User fields.
        await auth_db.commit()
        async with _MOBILE_INGEST_SLOTS:
            await _admit_run_if_claimed(req, current_user, project_id)
            if len(req.session_id) <= 256 and (req.lines or req.final):
                return await _ingest_pi_with_gate(req, current_user, user_id, project_id)
            return await _ingest_session_after_admit(req, current_user, user_id, project_id)
    await _admit_run_if_claimed(req, current_user, project_id)
    return await _ingest_session_after_admit(req, current_user, user_id, project_id)


async def _admit_run_if_claimed(req: SessionIngestRequest, current_user: User, project_id: str) -> None:
    if (
        req.harness == "pi"
        or req.run_incarnation is not None
        or req.run_header_hash is not None
        or req.run_origin
        or req.parent_run_incarnation is not None
        or req.parent_header_hash is not None
    ):
        from services.mobile_run_identity import admit_pi_run

        await admit_pi_run(
            project=str(project_id),
            user=current_user.id,
            session=req.session_id,
            harness=req.harness,
            start_offset=req.start_offset,
            lines=req.lines,
            run_incarnation=req.run_incarnation,
            run_header_hash=req.run_header_hash,
            run_origin=req.run_origin,
            parent_session_id=req.parent_session_id,
            parent_run_incarnation=req.parent_run_incarnation,
            parent_header_hash=req.parent_header_hash,
        )


async def _ingest_pi_with_gate(req: SessionIngestRequest, current_user: User, user_id: str, project_id: str):
    # Keep one physical PG connection's session-level exclusive project lock
    # THROUGH CH insertion, finalization and PG work-item commit. A separate
    # deny transaction commits first while the session lock blocks stale
    # readers and projectors; a transaction lock would release too early.
    async with async_session() as gate_db:
        await gate_db.execute(text("SELECT pg_advisory_lock(hashtextextended('mobile-read:default',0))"))
        try:
            async with async_session() as deny_db:
                await deny_db.execute(
                    text(
                        "UPDATE mobile_session_publications SET status='pending_source',source_policy_epoch=0,"
                        "updated_at=now() WHERE project_id=:project AND user_id=:user AND harness='pi' "
                        "AND session_id=:session AND (status!='pending_source' OR source_policy_epoch!=0)"
                    ),
                    {"project": str(project_id), "user": current_user.id, "session": req.session_id},
                )
                await deny_db.commit()
            return await _ingest_session_after_admit(req, current_user, user_id, project_id)
        finally:
            await gate_db.execute(text("SELECT pg_advisory_unlock(hashtextextended('mobile-read:default',0))"))
            await gate_db.commit()


async def _ingest_session_after_admit(req: SessionIngestRequest, current_user: User, user_id: str, project_id: str):
    from services.session_ingest import (
        SessionRecordConflictError,
        advance_session_checkpoint,
        check_session_integrity,
        ingest_session_lines,
    )

    optic.debug(
        "ingest request: session={}, harness={}, lines={}, offset={}, final={}",
        req.session_id,
        req.harness,
        len(req.lines),
        req.start_offset,
        req.final,
    )

    try:
        result = await ingest_session_lines(
            session_id=req.session_id,
            project_id=project_id,
            user_id=user_id,
            agent_id=req.agent_id,
            agent_version=req.agent_version,
            layer_hash=req.layer_hash,
            harness=req.harness,
            lines=req.lines,
            start_offset=req.start_offset,
            end_byte_offsets=req.end_byte_offsets,
            total_credits=req.total_credits,
            parent_session_id=req.parent_session_id,
        )
    except SessionRecordConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"message": "session source changed at an acknowledged line", "offsets": exc.offsets},
        )

    acknowledged_line, acknowledged_offset = await advance_session_checkpoint(
        req.session_id,
        project_id,
        user_id,
        req.harness,
    )
    if req.harness == "pi" and len(req.session_id) <= 256 and acknowledged_line >= 0:
        # PG persists the server-acknowledged maximum independently of CH
        # source retention and CH integrity-repair checkpoint rewinds. A lost
        # terminal record may leave a contiguous surviving prefix; it cannot
        # be mistaken for a tool-free full session after a short TTL interval.
        async with async_session() as highwater_db:
            await highwater_db.execute(
                text(
                    "INSERT INTO mobile_source_line_highwater(project_id,user_id,harness,session_id,max_line) "
                    "VALUES (:project,:user,'pi',:session,:line) "
                    "ON CONFLICT (project_id,user_id,harness,session_id) "
                    "DO UPDATE SET max_line=GREATEST(mobile_source_line_highwater.max_line,EXCLUDED.max_line)"
                ),
                {
                    "project": str(project_id),
                    "user": current_user.id,
                    "session": req.session_id,
                    "line": acknowledged_line,
                },
            )
            await highwater_db.commit()

    if req.capabilities_used:
        from services.clickhouse import insert_session_capabilities

        await insert_session_capabilities(
            session_id=req.session_id,
            project_id=project_id,
            user_id=user_id,
            harness=req.harness,
            uses=[c.model_dump() for c in req.capabilities_used],
        )

    integrity = None
    integrity_ok = None
    if req.final and req.total_line_count is not None:
        integrity = await check_session_integrity(
            session_id=req.session_id,
            project_id=project_id,
            user_id=user_id,
            harness=req.harness,
            expected_line_count=req.total_line_count,
            expected_offset=req.total_offset or 0,
            acknowledged_line=acknowledged_line,
            acknowledged_offset=acknowledged_offset,
            expected_hash=req.session_hash,
            hashed_line_count=req.hashed_line_count,
        )
        integrity_ok = integrity.ok
        if integrity.repair_from_line is not None:
            from services.clickhouse import insert_session_checkpoint

            acknowledged_line = integrity.repair_from_line - 1
            acknowledged_offset = integrity.repair_offset
            await insert_session_checkpoint(
                req.session_id,
                project_id,
                user_id,
                req.harness,
                acknowledged_line,
                acknowledged_offset,
            )
        if not integrity_ok:
            optic.warning(
                "session integrity check failed: session={}, expected={}, actual offset={}",
                req.session_id,
                req.total_line_count,
                req.total_offset,
            )

    if (
        req.harness == "pi"
        and len(req.session_id) <= 256
        and req.final
        and integrity is not None
        and integrity.ok
        and req.total_line_count is not None
        and req.total_line_count > 0
        and req.hashed_line_count == req.total_line_count
        and req.session_hash is not None
        and integrity.server_hash == req.session_hash
    ):
        # A contiguous checkpoint is not the sender's complete transcript:
        # persist finality only after the server rehashes every source line.
        # Later appends advance the independent high-water and hide old facts
        # until a new final receipt and projection attest the full transcript.
        async with async_session() as final_db:
            await final_db.execute(
                text(
                    "INSERT INTO mobile_source_final_receipts"
                    "(project_id,user_id,harness,session_id,final_line,source_hash) "
                    "VALUES (:project,:user,'pi',:session,:line,:hash) "
                    "ON CONFLICT (project_id,user_id,harness,session_id) DO UPDATE SET "
                    "final_line=EXCLUDED.final_line,source_hash=EXCLUDED.source_hash "
                    "WHERE EXCLUDED.final_line>=mobile_source_final_receipts.final_line"
                ),
                {
                    "project": str(project_id),
                    "user": current_user.id,
                    "session": req.session_id,
                    "line": req.total_line_count - 1,
                    "hash": req.session_hash,
                },
            )
            await final_db.commit()

    # Durable projection request is committed after the ClickHouse checkpoint.
    # A transient Postgres failure makes the client retry the idempotent push;
    # never acknowledge new Pi evidence without a replayable work item.
    if req.harness == "pi" and len(req.session_id) <= 256 and (req.lines or req.final):
        async with async_session() as db:
            await db.execute(
                text(
                    "INSERT INTO mobile_projection_queue(project_id,user_id,harness,session_id) "
                    "VALUES (:project,:user,'pi',:session) "
                    "ON CONFLICT (project_id,user_id,harness,session_id) DO UPDATE "
                    "SET requested_at=now(),attempts=0"
                ),
                {"project": project_id, "user": current_user.id, "session": req.session_id},
            )
            await db.commit()

    # Notify WebSocket subscribers so the frontend gets instant turn updates.
    # Publish to both a session-specific channel (for detail viewers, O(1) fan-out)
    # and the global channel (for list viewers with debounced refresh).
    # Fire-and-forget so a Redis blip never blocks the HTTP response to the CLI.
    if result.ingested > 0:
        import asyncio

        from services.redis import publish

        _payload = {
            "session_id": req.session_id,
            "event_name": "session_push",
        }
        asyncio.create_task(publish(f"sessions:{req.session_id}:updated", _payload))  # noqa: RUF006
        asyncio.create_task(publish("sessions:updated", _payload))  # noqa: RUF006

    optic.info(
        "session ingested: session={}, ingested={}, skipped={}, errors={}",
        req.session_id,
        result.ingested,
        result.skipped,
        result.errors,
    )

    return SessionIngestResponse(
        ingested=result.ingested,
        skipped=result.skipped,
        errors=result.errors,
        acknowledged_line=acknowledged_line,
        acknowledged_offset=acknowledged_offset,
        integrity_ok=integrity_ok,
        server_hash=integrity.server_hash if req.final and req.total_line_count is not None else None,
        repair_from_line=integrity.repair_from_line if req.final and req.total_line_count is not None else None,
    )


@router.get("/session/checkpoint", response_model=SessionCheckpointResponse)
async def get_session_checkpoint(
    session_id: str = Query(..., max_length=MAX_SHORT_STRING_LENGTH),
    harness: str = Query(..., max_length=MAX_SHORT_STRING_LENGTH),
    current_user: User = Depends(require_role(UserRole.user)),
):
    """Return the caller's durable contiguous checkpoint for one session source."""
    from services.clickhouse import query_session_checkpoint

    project_id = DEFAULT_PROJECT_ID
    acknowledged_line, acknowledged_offset = await query_session_checkpoint(
        session_id,
        project_id,
        str(current_user.id),
        harness,
    )
    return SessionCheckpointResponse(
        session_id=session_id,
        harness=harness,
        acknowledged_line=acknowledged_line,
        acknowledged_offset=acknowledged_offset,
    )
