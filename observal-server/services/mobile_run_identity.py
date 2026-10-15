# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Prospective Pi run admission: bind one scoped session ID to one source incarnation.

This is an identity/reuse fence, NOT proof that a parentless run is interactive.
A Pi session_start lifecycle claim can prospectively qualify a source-backed
root, but is still client-originated, not independent launcher attestation.
Legacy senders cannot retroactively acquire incarnation identity.
"""

import hashlib
import json
import uuid
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import text

from database import async_session


async def admit_pi_run(
    *,
    project: str,
    user: uuid.UUID,
    session: str,
    harness: str,
    start_offset: int,
    lines: list[str],
    run_incarnation: uuid.UUID | None,
    run_header_hash: str | None,
    run_origin: str | None = None,
) -> None:
    if harness != "pi":
        raise HTTPException(409, "Pi run identity required")
    if not session or len(session) > 256:
        # Existing long IDs remain legacy-only; never upgrade them.
        if run_incarnation is None and run_header_hash is None and run_origin is None:
            return
        raise HTTPException(409, "Unverifiable run identity")
    params = {"project": project, "user": user, "harness": harness, "session": session}
    async with async_session() as db:
        # Serialize competing claims before any ClickHouse write. A conflicting
        # incarnation never gets an opportunity to overwrite old source lines.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": json.dumps([project, str(user), harness, session])},
        )
        existing = (
            await db.execute(
                text(
                    "SELECT run_incarnation,header_hash,origin_witness FROM mobile_run_instances "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session "
                    "FOR UPDATE"
                ),
                params,
            )
        ).first()
        if existing is not None:
            if (
                existing.run_incarnation != run_incarnation
                or existing.header_hash != run_header_hash
                or existing.origin_witness != run_origin
                or (start_offset == 0 and lines and hashlib.sha256(lines[0].encode()).hexdigest() != run_header_hash)
            ):
                raise HTTPException(409, "Scoped session identity conflict")
        elif run_incarnation is None and run_header_hash is None and run_origin is None:
            return  # Legacy evidence remains unqualified but cannot replace a claimed run.
        elif run_incarnation is None or run_header_hash is None or len(run_header_hash) != 64:
            raise HTTPException(409, "Unverifiable run identity")
        elif start_offset != 0 or not lines:
            # A partial legacy source cannot be upgraded by claiming a nonce.
            raise HTTPException(409, "Run header is required before resumed upload")
        else:
            from services.clickhouse.client import _query

            prior = await _query(
                "SELECT 1 FROM session_events FINAL WHERE project_id={project:String} "
                "AND user_id={user:String} AND harness='pi' AND session_id={session:String} "
                "AND is_source_record=1 AND line_offset=0 LIMIT 1 FORMAT JSON",
                {"param_project": project, "param_user": str(user), "param_session": session},
            )
            prior.raise_for_status()
            if prior.json().get("data"):
                raise HTTPException(409, "Existing legacy source cannot acquire run identity")
            raw = lines[0]
            if hashlib.sha256(raw.encode()).hexdigest() != run_header_hash:
                raise HTTPException(409, "Run header mismatch")
            try:
                parsed = json.loads(raw)
                stamp = parsed.get("timestamp") if isinstance(parsed, dict) else None
                when = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else None
            except (ValueError, TypeError):
                when = None
                parsed = None
            if (
                not isinstance(parsed, dict)
                or parsed.get("type") != "session"
                or parsed.get("id") != session
                or when is None
                or when.tzinfo is None
                or (
                    run_origin is not None and (run_origin != "pi_session_start_root_v1" or parsed.get("parentSession"))
                )
            ):
                raise HTTPException(409, "Run header identity mismatch")
            await db.execute(
                text(
                    "INSERT INTO mobile_run_instances(project_id,user_id,harness,session_id,run_incarnation,header_hash,origin_witness) "
                    "VALUES (:project,:user,:harness,:session,:run,:header,:origin)"
                ),
                {**params, "run": run_incarnation, "header": run_header_hash, "origin": run_origin},
            )
        await db.commit()
