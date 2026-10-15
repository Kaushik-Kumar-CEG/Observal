# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bounded, retryable Pi-MCP source projection; never serves a zero cohort.

A complete scoped source and uploader-bound v2 manifest are prerequisites. This
worker publishes only matched positive client-reported call facts, not an
attestation of execution or complete server coverage. All failures stay null.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from database import async_session
from services.clickhouse.client import _query
from services.session_parsers.pi_invocations import PiInvocationExtractor

_MAX_LINES = 10000
_MAX_BYTES = 16 * 1024 * 1024
_PARAMS = (
    "project_id={project:String} AND user_id={user:String} AND harness={harness:String} AND session_id={session:String}"
)


def _revision(rows: list[dict], *, retained_suffix: bool = False) -> str | None:
    first = rows[0].get("line_offset") if rows else None
    if (
        not rows
        or len(rows) > _MAX_LINES
        or not isinstance(first, int)
        or first < 0
        or (first != 0 and not retained_suffix)
        or [r.get("line_offset") for r in rows] != list(range(first, first + len(rows)))
    ):
        return None
    if any(not r.get("line_hash") or r.get("raw_line_truncated") or not r.get("raw_line") for r in rows):
        return None
    return hashlib.sha256(
        json.dumps([[r["line_offset"], r["line_hash"]] for r in rows], separators=(",", ":")).encode()
    ).hexdigest()


def _matched(
    extracted, rows: list[dict], mappings: dict[str, dict[str, uuid.UUID]], *, verified_root: uuid.UUID | None = None
) -> tuple[list[dict], bool]:
    """Only result-linked calls with a unique server alias and valid time qualify."""
    valid = []
    partial = bool(extracted.malformed_source_records)
    now = datetime.now(UTC)
    by_offset = {r["line_offset"]: r for r in rows}
    # A parent-free source or a preceding prompt does not attest root origin.
    # Only a separately verified incarnation/lineage witness may count reach.
    for call in extracted.invocations:
        source = by_offset.get(call.source_line_offset)
        alias = call.mcp_server
        stamp = call.event_time
        candidates = mappings.get(source.get("layer_hash") or "", {}) if source else {}
        if (
            not source
            or not alias
            or alias not in candidates
            or stamp is None
            or not datetime(1971, 1, 1, tzinfo=UTC) <= stamp <= now + timedelta(minutes=5)
            or len(call.source_block_key) > 270
        ):
            partial = True
            continue
        root = (
            source["session_id"]
            if verified_root is not None
            and rows[0]["line_offset"] == 0
            and not any(r.get("parent_session_id") for r in rows)
            else None
        )
        valid.append(
            {
                "source_line_offset": call.source_line_offset,
                "block_key": call.source_block_key,
                "component_id": candidates[alias],
                "layer_hash": source["layer_hash"],
                "alias": alias,
                "root_session_id": root,
                "root_run_incarnation": verified_root if root is not None else None,
                "event_time": stamp,
                "result_state": call.result_state,
            }
        )
        if root is None or call.result_state == "unknown":
            partial = True
    return valid, partial


async def _rows(project: str, user: str, harness: str, session: str) -> list[dict] | None:
    params = {"param_project": project, "param_user": user, "param_harness": harness, "param_session": session}
    shape = await _query(
        f"SELECT count() AS n, sum(length(raw_line)) AS bytes FROM session_events FINAL WHERE {_PARAMS} "
        "AND is_source_record=1 FORMAT JSON",
        params,
    )
    shape.raise_for_status()
    result = shape.json().get("data", [{}])[0]
    if int(result.get("n") or 0) > _MAX_LINES or int(result.get("bytes") or 0) > _MAX_BYTES:
        return None
    response = await _query(
        f"SELECT project_id,user_id,harness,session_id,line_offset,line_hash,raw_line,raw_line_truncated,"
        f"layer_hash,parent_session_id,is_source_record,event_type,timestamp FROM session_events FINAL WHERE {_PARAMS} "
        f"AND is_source_record=1 ORDER BY line_offset LIMIT {_MAX_LINES + 1} FORMAT JSON",
        params,
    )
    response.raise_for_status()
    return response.json().get("data", [])


async def project_pi_session(ctx: dict, project: str, user: str, harness: str, session: str) -> dict:
    del ctx
    # Worker is fed only server-derived uploader identity, never client-declared
    # user IDs. Backfill accepts the same fully scoped key.
    if harness != "pi" or not session or len(session) > 256:
        return {"status": "unsupported"}
    owner = uuid.UUID(user)
    rows = await _rows(project, user, harness, session)
    revision = _revision(rows or [], retained_suffix=True)
    first_source_offset = rows[0]["line_offset"] if revision is not None else 0
    scope = {"project": project, "user": owner, "harness": harness, "session": session}
    async with async_session() as db:
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": json.dumps([project, user, harness, session])},
        )
        status = "pending_source"
        valid: list[dict] = []
        run = (
            await db.execute(
                text(
                    "SELECT run_incarnation,header_hash,root_verified FROM mobile_run_instances "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session FOR UPDATE"
                ),
                scope,
            )
        ).first()
        run_incarnation = None
        if run and revision is not None and first_source_offset == 0 and rows:
            try:
                header = json.loads(rows[0]["raw_line"])
            except (ValueError, TypeError, KeyError):
                header = None
            if (
                isinstance(header, dict)
                and header.get("type") == "session"
                and header.get("id") == session
                and hashlib.sha256(rows[0]["raw_line"].encode()).hexdigest() == run.header_hash
            ):
                run_incarnation = run.run_incarnation
        if revision is not None:
            hashes = {r.get("layer_hash") for r in rows}
            if all(isinstance(digest, str) and digest.startswith("v2_") for digest in hashes):
                results = (
                    await db.execute(
                        text(
                            "SELECT l.layer_hash,l.expected_components,c.alias,c.component_id "
                            "FROM mobile_verified_layers l LEFT JOIN mobile_layer_components c "
                            "ON c.project_id=l.project_id AND c.user_id=l.user_id AND c.harness=l.harness "
                            "AND c.layer_hash=l.layer_hash "
                            "WHERE l.project_id=:project AND l.user_id=:user AND l.harness=:harness "
                            "AND l.layer_hash = ANY(:hashes)"
                        ),
                        {"project": project, "user": owner, "harness": harness, "hashes": list(hashes)},
                    )
                ).all()
                mapping: dict[str, dict[str, uuid.UUID]] = {}
                expected: dict[str, int] = {}
                for digest, count, alias, component in results:
                    expected[digest] = count
                    if alias is not None:
                        mapping.setdefault(digest, {})[alias] = component
                if all(len(mapping.get(digest, {})) == expected.get(digest, -1) for digest in hashes):
                    extraction = PiInvocationExtractor().extract(rows)
                    valid, partial = _matched(
                        extraction,
                        rows,
                        mapping,
                        verified_root=run_incarnation if run_incarnation and run.root_verified else None,
                    )
                    status = "partial" if partial or first_source_offset else "complete"
                else:
                    status = "pending_mapping"
            else:
                status = "legacy_layer"
        current = (
            await db.execute(
                text(
                    "SELECT source_revision,status,first_source_offset FROM mobile_session_publications "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                scope,
            )
        ).first()
        if current and (current.source_revision, current.status, current.first_source_offset) == (
            revision or "unknown",
            status,
            first_source_offset,
        ):
            # Backfill and retention replay unchanged sources frequently. Do not
            # invalidate a subject's pagination because an unrelated scan ran.
            count = await db.scalar(
                text(
                    "SELECT count(*) FROM mobile_evidence_events WHERE project_id=:project AND user_id=:user "
                    "AND harness=:harness AND session_id=:session"
                ),
                scope,
            )
            await db.rollback()
            return {"status": status, "matched": count or 0}
        old_components = (
            (
                await db.execute(
                    text(
                        "SELECT DISTINCT component_id FROM mobile_evidence_events WHERE project_id=:project "
                        "AND user_id=:user AND harness=:harness AND session_id=:session"
                    ),
                    scope,
                )
            )
            .scalars()
            .all()
        )
        # A source repair, deletion or mapping invalidation revokes the old
        # generation instead of leaving formerly attributed events readable.
        await db.execute(
            text(
                "DELETE FROM mobile_evidence_events WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        for fact in valid:
            await db.execute(
                text(
                    "INSERT INTO mobile_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                    "block_key,layer_hash,alias,component_id,root_session_id,run_incarnation,root_run_incarnation,"
                    "event_time,result_state) "
                    "VALUES (:project,:user,:harness,:session,:source_line_offset,:block_key,:layer_hash,:alias,"
                    ":component_id,:root_session_id,:run_incarnation,:root_run_incarnation,:event_time,:result_state)"
                ),
                {**scope, **fact, "run_incarnation": run_incarnation},
            )
        await db.execute(
            text(
                "INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,source_revision,status,first_source_offset) "
                "VALUES (:project,:user,:harness,:session,:revision,:status,:first_source_offset) "
                "ON CONFLICT (project_id,user_id,harness,session_id) DO UPDATE "
                "SET source_revision=EXCLUDED.source_revision,status=EXCLUDED.status,"
                "first_source_offset=EXCLUDED.first_source_offset,updated_at=now()"
            ),
            {**scope, "revision": revision or "unknown", "status": status, "first_source_offset": first_source_offset},
        )
        changed_components = set(old_components) | {fact["component_id"] for fact in valid}
        subjects = {(owner, "user")}
        if changed_components:
            authors = (
                (
                    await db.execute(
                        text(
                            "SELECT DISTINCT original_author_id FROM mobile_listing_provenance "
                            "WHERE kind='mcp' AND listing_id=ANY(:ids)"
                        ),
                        {"ids": list(changed_components)},
                    )
                )
                .scalars()
                .all()
            )
            subjects.update((author, "author") for author in authors)
        for subject, subject_scope in subjects:
            await db.execute(
                text(
                    "INSERT INTO mobile_scope_epochs(project_id,subject_id,scope,epoch) "
                    "VALUES (:project,:subject,:scope,1) ON CONFLICT (project_id,subject_id,scope) "
                    "DO UPDATE SET epoch=mobile_scope_epochs.epoch+1"
                ),
                {"project": project, "subject": subject, "scope": subject_scope},
            )
        if run is not None:
            await db.execute(
                text(
                    "UPDATE mobile_run_instances SET source_status=:status "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                {**scope, "status": status if run_incarnation else "pending"},
            )
        # ClickHouse and Postgres have no shared transaction. Recheck source
        # after publication preparation; a racing append/repair retries instead
        # of committing an already-stale generation.
        fresh = await _rows(project, user, harness, session)
        if _revision(fresh or [], retained_suffix=True) != revision:
            await db.rollback()
            raise RuntimeError("Mobile source changed during evidence publication")
        await db.commit()
    return {"status": status, "matched": len(valid)}


async def scan_retained_mobile_sources(ctx: dict) -> dict:
    """Keyset-scan retained Pi v2 senders for missed uploads or source repairs.

    Old/legacy hashes are never inferred or upgraded. A complete sweep rewinds
    to pick up sessions before the cursor in the next bounded pass. The queue
    and publication generations make all retries idempotent.
    """
    del ctx
    async with async_session() as db:
        cursor = (
            await db.execute(
                text(
                    "SELECT project_id,user_id,session_id FROM mobile_backfill_cursor "
                    "WHERE singleton=true FOR UPDATE SKIP LOCKED"
                )
            )
        ).first()
        if cursor is None:
            return {"status": "busy"}
        result = await _query(
            "SELECT project_id,user_id,session_id,groupUniqArray(101)(layer_hash) AS hashes "
            "FROM session_events FINAL WHERE harness='pi' AND is_source_record=1 "
            "AND startsWith(layer_hash,'v2_') AND timestamp>=now()-INTERVAL 90 DAY "
            "AND (project_id,user_id,session_id)>({project:String},{user:String},{session:String}) "
            "GROUP BY project_id,user_id,session_id ORDER BY project_id,user_id,session_id LIMIT 51 "
            "SETTINGS max_execution_time=5 FORMAT JSON",
            {"param_project": cursor.project_id, "param_user": cursor.user_id, "param_session": cursor.session_id},
        )
        result.raise_for_status()
        candidates = result.json().get("data", [])
        queued = 0
        for candidate in candidates[:50]:
            try:
                owner = uuid.UUID(candidate["user_id"])
            except (ValueError, TypeError, KeyError):
                continue
            hashes = candidate.get("hashes") or []
            if len(hashes) > 100:
                continue
            eligible = await db.scalar(
                text(
                    "SELECT 1 FROM mobile_verified_layers l JOIN users u ON u.id=l.user_id "
                    "WHERE l.project_id=:project AND l.user_id=:user AND l.harness='pi' "
                    "AND l.layer_hash=ANY(:hashes) AND u.auth_provider!='deactivated' LIMIT 1"
                ),
                {"project": candidate["project_id"], "user": owner, "hashes": hashes},
            )
            if not eligible:
                continue
            await db.execute(
                text(
                    "INSERT INTO mobile_projection_queue(project_id,user_id,harness,session_id) "
                    "VALUES (:project,:user,'pi',:session) ON CONFLICT "
                    "(project_id,user_id,harness,session_id) DO UPDATE SET requested_at=now()"
                ),
                {"project": candidate["project_id"], "user": owner, "session": candidate["session_id"]},
            )
            queued += 1
        if len(candidates) > 50:
            last = candidates[49]
            values = {"project": last["project_id"], "user": last["user_id"], "session": last["session_id"]}
        else:
            values = {"project": "", "user": "", "session": ""}
        await db.execute(
            text(
                "UPDATE mobile_backfill_cursor SET project_id=:project,user_id=:user,session_id=:session "
                "WHERE singleton=true"
            ),
            values,
        )
        await db.commit()
    return {"status": "scanned", "candidates": len(candidates), "queued": queued}


async def run_mobile_retention_sweep(ctx: dict) -> dict:
    """Revoke materialized evidence after ClickHouse TTL, admin purge or repair.

    Reads already revalidate their source on each request. This bounded sweep
    also removes old PostgreSQL facts that would otherwise outlive source
    retention. User deletion cascades are handled directly by the schema.
    """
    del ctx
    async with async_session() as db:
        candidates = (
            await db.execute(
                text(
                    "SELECT project_id,user_id,harness,session_id FROM mobile_session_publications "
                    "WHERE status IN ('complete','partial') AND updated_at<now()-INTERVAL '1 day' "
                    "ORDER BY updated_at,project_id,user_id,session_id LIMIT 50"
                )
            )
        ).all()
    checked = 0
    revoked = 0
    for project, user, harness, session in candidates:
        try:
            result = await project_pi_session({}, project, str(user), harness, session)
        except Exception:
            from loguru import logger as optic

            optic.exception("mobile retained evidence cleanup failed")
            return {"checked": checked, "revoked": revoked, "failed": True}
        checked += 1
        if result["status"] not in ("complete", "partial"):
            revoked += 1
    return {"checked": checked, "revoked": revoked, "failed": False}


async def run_mobile_projection_queue(ctx: dict) -> dict:
    """Drain a small durable queue; failed jobs stay available for later retry."""
    del ctx
    attempted = 0
    completed = 0
    async with async_session() as db:
        pending = (
            await db.execute(
                text(
                    "SELECT project_id,user_id,harness,session_id,requested_at "
                    "FROM mobile_projection_queue ORDER BY requested_at LIMIT 50 FOR UPDATE SKIP LOCKED"
                )
            )
        ).all()
        for project, user, harness, session, requested_at in pending:
            attempted += 1
            try:
                result = await project_pi_session({}, project, str(user), harness, session)
                # Pending mapping/source is not a completed projection; retain
                # the key for new snapshots and source repairs.
                if result["status"] in ("complete", "partial", "legacy_layer", "unsupported"):
                    await db.execute(
                        text(
                            "DELETE FROM mobile_projection_queue WHERE project_id=:project AND user_id=:user "
                            "AND harness=:harness AND session_id=:session AND requested_at<=:requested"
                        ),
                        {
                            "project": project,
                            "user": user,
                            "harness": harness,
                            "session": session,
                            "requested": requested_at,
                        },
                    )
                    completed += 1
                else:
                    await db.execute(
                        text(
                            "UPDATE mobile_projection_queue SET attempts=attempts+1 "
                            "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                        ),
                        {"project": project, "user": user, "harness": harness, "session": session},
                    )
            except Exception:
                # Fixed logger text only: no transcript or secrets in worker logs.
                from loguru import logger as optic

                optic.exception("mobile evidence projection failed for scoped session")
                await db.rollback()
                return {"attempted": attempted, "completed": completed, "failed": True}
        await db.commit()
    return {"attempted": attempted, "completed": completed, "failed": False}
