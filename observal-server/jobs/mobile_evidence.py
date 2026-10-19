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

import services.dynamic_settings as ds
from database import async_session
from services.clickhouse.client import _query
from services.mobile_pi_hook_receipts import extract_hook_receipts
from services.mobile_pi_skill_loads import extract_skill_loads
from services.session_parsers.pi_invocations import PiInvocationExtractor

_MAX_LINES = 10000
_MAX_BYTES = 16 * 1024 * 1024
_PARAMS = (
    "project_id={project:String} AND user_id={user:String} AND harness={harness:String} AND session_id={session:String}"
)


def _source_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or not 1971 <= parsed.year < 2100:
        return None
    return parsed.astimezone(UTC)


def _zero_activities(rows: list[dict]) -> list[tuple[int, datetime, str]] | None:
    """Only tool-free, timestamped Pi records justify a partial zero cohort."""
    activity: list[tuple[int, datetime, str]] = []
    for row in rows:
        try:
            record = json.loads(row["raw_line"])
        except (ValueError, TypeError, KeyError):
            return None
        if not isinstance(record, dict):
            return None
        if record.get("type") != "message":
            if record.get("type") not in {
                "session",
                "label",
                "session_info",
                "model_change",
                "thinking_level_change",
                "compaction",
                "branch_summary",
            }:
                return None
            continue
        if not isinstance(row.get("layer_hash"), str) or not row["layer_hash"].startswith("v2_"):
            return None
        message = record.get("message")
        if not isinstance(message, dict):
            return None
        when = _source_time(record.get("timestamp"))
        if when is None or when > datetime.now(UTC) + timedelta(minutes=5):
            return None
        if message.get("role") not in ("user", "assistant"):
            return None
        if message.get("role") == "assistant":
            content = message.get("content")
            if not isinstance(content, list) or any(
                isinstance(part, dict) and part.get("type") == "toolCall" for part in content
            ):
                return None  # A silent/unknown tool might have called a component.
        if row.get("event_type") in ("user_prompt", "assistant_text", "thinking"):
            activity.append((row["line_offset"], when, row["layer_hash"]))
    return activity or None


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


def _policy_source_complete(
    rows: list[dict],
    revision: str | None,
    previous_revision: str | None,
    previous_highest: int | None,
    highwater: int | None,
    policy_since: datetime | None,
    final_line: int | None = None,
    final_hash: str | None = None,
) -> bool:
    """No surviving prefix may masquerade as the complete original session.

    Original pre-067 records have a published full digest; new sessions need
    both the ingest-side monotonic max line and a post-verification header.
    This does not infer a zero from an unknown or vanished source.
    """
    if not rows or revision is None or rows[0].get("line_offset") != 0 or policy_since is None:
        return False
    last = rows[-1].get("line_offset")
    if (
        not isinstance(last, int)
        or (highwater is not None and last != highwater)
        or (previous_highest is not None and last < previous_highest)
    ):
        return False
    # An old publication digest proves only which prefix the old worker saw,
    # not that the uploader ever sent the terminal record. Both old and new
    # sessions need a freshly server-verified full-file final receipt.
    if highwater is None or final_line != last or not final_hash:
        return False
    fingerprint = hashlib.sha256()
    for row in rows:
        # The server finalization manifest hashes SHA-256 of original JSONL,
        # not the xxh128 line_hash used for the projection revision.
        if not isinstance(row.get("source_sha256"), str) or len(row["source_sha256"]) != 64:
            return False
        fingerprint.update(row["source_sha256"].encode())
        fingerprint.update(b"\n")
    if fingerprint.hexdigest() != final_hash:
        return False
    if previous_revision == revision:
        return True  # exact historical bytes, now independently finalized
    try:
        ch_ingested = datetime.fromisoformat(str(rows[0]["ingested_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError):
        return False
    first_ingested = ch_ingested.replace(tzinfo=UTC) if ch_ingested.tzinfo is None else ch_ingested.astimezone(UTC)
    return first_ingested >= policy_since


def _source_retained_until(rows: list[dict], revision: str | None, *, retention_days: int = 30) -> datetime | None:
    """Earliest actual UTC whole-row TTL or one-day-buffered raw-line TTL.

    Whole rows expire at toDate(timestamp) + N days (midnight UTC), not at
    timestamp + N days. A later TTL increase never revives a missing source:
    every policy transition quarantines old publications until reprojected.
    """
    if revision is None or not rows or rows[0].get("line_offset") != 0:
        return None
    try:
        times = []
        for row in rows:
            value = row["timestamp"]
            if not isinstance(value, str):
                return None
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
            if not 1971 <= stamp.year < 2100:
                return None
            times.append(stamp)
        if not times or retention_days < 0:
            return None
        earliest = min(times)
        raw_cutoff = earliest + timedelta(days=29)
        if retention_days == 0:  # Whole-row TTL disabled; raw_line still expires at 30 days.
            return raw_cutoff
        midnight_cutoff = earliest.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=retention_days)
        return min(raw_cutoff, midnight_cutoff)
    except (KeyError, TypeError, ValueError):
        return None


def _matched_hook_receipts(
    receipts,
    rows: list[dict],
    mappings: dict[str, dict[str, tuple[uuid.UUID, str]]],
    *,
    revision: str,
    run_incarnation: uuid.UUID | None,
    root: uuid.UUID | None,
    root_session_id: str | None,
    root_start: datetime | None,
) -> tuple[list[dict], bool]:
    facts, partial = [], False
    by_offset = {row["line_offset"]: row for row in rows}
    now = datetime.now(UTC)
    for receipt in receipts:
        source = by_offset.get(receipt.offset)
        pin = mappings.get(source["layer_hash"], {}).get(receipt.binding_sha256) if source else None
        if (
            pin is None
            or pin[1] != receipt.event
            or receipt.layer_hash != source["layer_hash"]
            or root is None
            or run_incarnation is None
            or root_start is None
            or receipt.event_time < root_start
            or receipt.event_time > now + timedelta(minutes=5)
            or rows[0]["line_offset"] != 0
        ):
            partial = True
            continue
        facts.append(
            {
                "source_line_offset": receipt.offset,
                "block_key": receipt.block_key,
                "layer_hash": source["layer_hash"],
                "binding_sha256": receipt.binding_sha256,
                "component_id": pin[0],
                "source_revision": revision,
                "run_incarnation": run_incarnation,
                "root_session_id": root_session_id,
                "root_run_incarnation": root,
                "event_time": receipt.event_time,
                "outcome": receipt.outcome,
            }
        )
    return facts, partial


def _matched_skill_loads(
    loads,
    rows: list[dict],
    mappings: dict[str, dict[tuple[str, str], tuple[uuid.UUID, str, str]]],
    *,
    revision: str,
    run_incarnation: uuid.UUID | None,
    root: uuid.UUID | None,
    root_session_id: str | None,
    root_start: datetime | None,
) -> tuple[list[dict], bool]:
    """Only admit a pinned successful read from this exact verified incarnation."""
    facts = []
    partial = False
    by_offset = {r["line_offset"]: r for r in rows}
    now = datetime.now(UTC)
    for load in loads:
        source = by_offset.get(load.offset)
        pin = mappings.get(source["layer_hash"], {}).get((load.scope, load.alias)) if source else None
        if (
            pin is None
            or load.layer_hash != source["layer_hash"]
            or pin[1] != load.location_sha256
            or pin[2] != load.content_sha256
            or root is None
            or run_incarnation is None
            or root_start is None
            or load.event_time < root_start
            or load.event_time > now + timedelta(minutes=5)
            or rows[0]["line_offset"] != 0
        ):
            partial = True
            continue
        facts.append(
            {
                "source_line_offset": load.offset,
                "block_key": load.block_key,
                "layer_hash": source["layer_hash"],
                "scope": load.scope,
                "alias": load.alias,
                "component_id": pin[0],
                "source_revision": revision,
                "run_incarnation": run_incarnation,
                "root_session_id": root_session_id,
                "root_run_incarnation": root,
                "event_time": load.event_time,
            }
        )
    return facts, partial


def _matched(
    extracted,
    rows: list[dict],
    mappings: dict[str, dict[str, uuid.UUID]],
    *,
    verified_root: uuid.UUID | None = None,
    allow_child: bool = False,
    root_start: datetime | None = None,
    root_session_id: str | None = None,
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
            or (root_start is not None and stamp < root_start)
        ):
            partial = True
            continue
        root = (
            (root_session_id or source["session_id"])
            if verified_root is not None
            and rows[0]["line_offset"] == 0
            and (allow_child or not any(r.get("parent_session_id") for r in rows))
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
        f"SELECT project_id,user_id,harness,session_id,line_offset,line_hash,source_sha256,raw_line,raw_line_truncated,"
        f"layer_hash,parent_session_id,is_source_record,event_type,timestamp,ingested_at "
        f"FROM session_events FINAL WHERE {_PARAMS} "
        f"AND is_source_record=1 ORDER BY line_offset LIMIT {_MAX_LINES + 1} FORMAT JSON",
        params,
    )
    response.raise_for_status()
    return response.json().get("data", [])


async def _qualified_lineage(db, scope: dict, run, child_start: datetime) -> tuple[str, uuid.UUID, datetime] | None:
    """At most eight exact same-actor parent incarnations, ending in a current root."""
    seen = {scope["session"]}
    parent_id, nonce, fingerprint = run.parent_session_id, run.parent_run_incarnation, run.parent_header_hash
    if not parent_id or nonce is None or not fingerprint:
        return None
    for _ in range(8):
        if parent_id in seen:
            return None
        seen.add(parent_id)
        parent = (
            await db.execute(
                text(
                    "SELECT session_id,run_incarnation,header_hash,parent_session_id,parent_run_incarnation,"
                    "parent_header_hash,origin_witness,root_verified,source_status,started_at "
                    "FROM mobile_run_instances WHERE project_id=:project AND user_id=:user AND harness='pi' "
                    "AND session_id=:parent FOR UPDATE"
                ),
                {**scope, "parent": parent_id},
            )
        ).first()
        if (
            parent is None
            or parent.run_incarnation != nonce
            or parent.header_hash != fingerprint
            or parent.started_at is None
            or parent.started_at > child_start
            or parent.source_status not in ("complete", "partial")
        ):
            return None
        child_start = parent.started_at
        if parent.parent_session_id is None:
            if parent.root_verified and parent.origin_witness == "pi_session_start_root_v1":
                return parent.session_id, parent.run_incarnation, parent.started_at
            return None
        parent_id, nonce, fingerprint = (
            parent.parent_session_id,
            parent.parent_run_incarnation,
            parent.parent_header_hash,
        )
    return None


async def project_pi_session(ctx: dict, project: str, user: str, harness: str, session: str) -> dict:
    del ctx
    # Worker is fed only server-derived uploader identity, never client-declared
    # user IDs. Backfill accepts the same fully scoped key.
    if harness != "pi" or not session or len(session) > 256:
        return {"status": "unsupported"}
    owner = uuid.UUID(user)
    scope = {"project": project, "user": owner, "harness": harness, "session": session}
    async with async_session() as db:
        # The project shared lock covers both ClickHouse reads and the final
        # PostgreSQL publication commit. A TTL transition takes the exclusive
        # lock before applying ClickHouse changes; retries cannot publish a
        # stale epoch after an operator closes the barrier.
        await db.execute(
            text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0))"), {"key": "mobile-read:" + project}
        )
        policy = (
            await db.execute(
                text(
                    "SELECT source_policy_epoch,source_policy_ready,source_policy_since "
                    "FROM mobile_read_controls WHERE project_id=:project"
                ),
                {"project": project},
            )
        ).one_or_none()
        if policy is None or not policy.source_policy_ready or policy.source_policy_since is None:
            raise RuntimeError("Mobile source policy not verified; retry projection after TTL application")
        configured = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='data.retention_days'"))
        try:
            days = int(configured) if configured is not None else 90
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Invalid mobile source retention") from exc
        if not 0 <= days <= 36500:
            raise RuntimeError("Verifiable mobile source retention required")
        rows = await _rows(project, user, harness, session)
        revision = _revision(rows or [], retained_suffix=True)
        retained_until = _source_retained_until(rows or [], revision, retention_days=days)
        observed_revision, observed_floor = revision, retained_until
        first_source_offset = rows[0]["line_offset"] if revision is not None else 0
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": json.dumps([project, user, harness, session])},
        )
        original = (
            await db.execute(
                text(
                    "SELECT source_revision,source_highest_line FROM mobile_session_publications "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                scope,
            )
        ).one_or_none()
        highest = await db.scalar(
            text(
                "SELECT max_line FROM mobile_source_line_highwater WHERE project_id=:project "
                "AND user_id=:user AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        final = (
            await db.execute(
                text(
                    "SELECT final_line,source_hash FROM mobile_source_final_receipts "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                scope,
            )
        ).one_or_none()
        if revision is not None and not _policy_source_complete(
            rows or [],
            revision,
            original.source_revision if original else None,
            original.source_highest_line if original else None,
            highest,
            policy.source_policy_since,
            final.final_line if final else None,
            final.source_hash if final else None,
        ):
            revision = None
            retained_until = None
            first_source_offset = 0
        status = "pending_source"
        valid: list[dict] = []
        valid_skills: list[dict] = []
        valid_hooks: list[dict] = []
        skill_mapping: dict[str, dict[tuple[str, str], tuple[uuid.UUID, str, str]]] = {}
        hook_mapping: dict[str, dict[str, tuple[uuid.UUID, str]]] = {}
        run = (
            await db.execute(
                text(
                    "SELECT run_incarnation,header_hash,root_verified,origin_witness,parent_session_id,"
                    "parent_run_incarnation,parent_header_hash,started_at FROM mobile_run_instances "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session FOR UPDATE"
                ),
                scope,
            )
        ).first()
        run_incarnation = None
        root_witnessed = False
        resolved_root: uuid.UUID | None = None
        resolved_root_id: str | None = None
        lineage_start: datetime | None = None
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
                root_witnessed = (
                    run.origin_witness == "pi_session_start_root_v1"
                    and not header.get("parentSession")
                    and not any(row.get("parent_session_id") for row in rows)
                    and _source_time(header.get("timestamp")) is not None
                    and run.parent_session_id is None
                )
                if root_witnessed:
                    resolved_root = run.run_incarnation
                    resolved_root_id = session
                    lineage_start = _source_time(header.get("timestamp"))
                elif run.parent_session_id is not None and _source_time(header.get("timestamp")) is not None:
                    lineage = await _qualified_lineage(db, scope, run, _source_time(header["timestamp"]))
                    if (
                        lineage is not None
                        and header.get("parentSession")
                        and all(row.get("parent_session_id") == run.parent_session_id for row in rows)
                    ):
                        resolved_root_id, resolved_root, _root_started = lineage
                        lineage_start = _source_time(header["timestamp"])  # Calls cannot predate this child.
        if revision is not None:
            hashes = {r.get("layer_hash") for r in rows}
            if all(isinstance(digest, str) and digest.startswith(("v2_", "v3_")) for digest in hashes):
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
                skill_results = (
                    await db.execute(
                        text(
                            "SELECT l.layer_hash,l.expected_skills,s.scope,s.alias,s.component_id,s.location_sha256,s.content_sha256 "
                            "FROM mobile_verified_layers l LEFT JOIN mobile_skill_layer_components s "
                            "ON s.project_id=l.project_id AND s.user_id=l.user_id AND s.harness=l.harness "
                            "AND s.layer_hash=l.layer_hash WHERE l.project_id=:project AND l.user_id=:user "
                            "AND l.harness=:harness AND l.layer_hash=ANY(:hashes)"
                        ),
                        {"project": project, "user": owner, "harness": harness, "hashes": list(hashes)},
                    )
                ).all()
                expected_skills: dict[str, int] = {}
                for digest, count, pin_scope, alias, component, location, content_sha256 in skill_results:
                    expected_skills[digest] = count
                    if alias is not None:
                        skill_mapping.setdefault(digest, {})[(pin_scope, alias)] = (component, location, content_sha256)
                hook_results = (
                    await db.execute(
                        text(
                            "SELECT l.layer_hash,l.expected_hooks,h.binding_sha256,h.component_id,h.event "
                            "FROM mobile_verified_layers l LEFT JOIN mobile_hook_layer_components h "
                            "ON h.project_id=l.project_id AND h.user_id=l.user_id AND h.harness=l.harness "
                            "AND h.layer_hash=l.layer_hash WHERE l.project_id=:project AND l.user_id=:user "
                            "AND l.harness=:harness AND l.layer_hash=ANY(:hashes)"
                        ),
                        {"project": project, "user": owner, "harness": harness, "hashes": list(hashes)},
                    )
                ).all()
                expected_hooks: dict[str, int] = {}
                for digest, count, binding, component, event in hook_results:
                    expected_hooks[digest] = count
                    if binding is not None:
                        hook_mapping.setdefault(digest, {})[binding] = (component, event)
                if all(
                    len(hook_mapping.get(digest, {})) == expected_hooks.get(digest, -1)
                    and len(mapping.get(digest, {})) == expected.get(digest, -1)
                    and len(skill_mapping.get(digest, {})) == expected_skills.get(digest, -1)
                    for digest in hashes
                ):
                    extraction = PiInvocationExtractor().extract(rows)
                    valid, partial = _matched(
                        extraction,
                        rows,
                        mapping,
                        verified_root=resolved_root,
                        allow_child=resolved_root is not None and not root_witnessed,
                        root_start=lineage_start,
                        root_session_id=resolved_root_id,
                    )
                    loads, malformed_skills = extract_skill_loads(rows)
                    valid_skills, unqualified_skills = _matched_skill_loads(
                        loads,
                        rows,
                        skill_mapping,
                        revision=revision,
                        run_incarnation=run_incarnation,
                        root=resolved_root,
                        root_session_id=resolved_root_id,
                        root_start=lineage_start,
                    )
                    receipts, malformed_hooks = extract_hook_receipts(rows)
                    valid_hooks, unqualified_hooks = _matched_hook_receipts(
                        receipts,
                        rows,
                        hook_mapping,
                        revision=revision,
                        run_incarnation=run_incarnation,
                        root=resolved_root,
                        root_session_id=resolved_root_id,
                        root_start=lineage_start,
                    )
                    status = (
                        "partial"
                        if (
                            partial
                            or malformed_skills
                            or unqualified_skills
                            or malformed_hooks
                            or unqualified_hooks
                            or first_source_offset
                        )
                        else "complete"
                    )
                else:
                    status = "pending_mapping"
            else:
                status = "legacy_layer"
        current = (
            await db.execute(
                text(
                    "SELECT source_revision,status,first_source_offset,source_retained_until,source_policy_epoch,source_highest_line "
                    "FROM mobile_session_publications "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                scope,
            )
        ).first()
        zero_times = (
            _zero_activities(rows)
            if rows and root_witnessed and status == "complete" and not valid and any(mapping.values())
            else None
        )
        if current and (
            current.source_revision,
            current.status,
            current.first_source_offset,
            current.source_retained_until,
            current.source_policy_epoch,
            current.source_highest_line,
        ) == (
            revision or "unknown",
            status,
            first_source_offset,
            retained_until,
            policy.source_policy_epoch,
            rows[-1]["line_offset"] if revision is not None and rows else current.source_highest_line,
        ):
            # Newly upgraded zero-cohort projection may be missing even when
            # positive facts/publication were previously idempotent.
            zero_exists = (
                await db.scalar(
                    text(
                        "SELECT 1 FROM mobile_eligible_event_times WHERE project_id=:project AND user_id=:user "
                        "AND harness=:harness AND session_id=:session LIMIT 1"
                    ),
                    scope,
                )
                if zero_times
                else True
            )
            stale_roots = await db.scalar(
                text(
                    "SELECT count(*) FROM mobile_evidence_events WHERE project_id=:project AND user_id=:user "
                    "AND harness=:harness AND session_id=:session "
                    "AND root_run_incarnation IS DISTINCT FROM :resolved_root"
                ),
                {**scope, "resolved_root": resolved_root},
            )
            existing_skills = await db.scalar(
                text(
                    "SELECT count(*) FROM mobile_skill_evidence_events WHERE project_id=:project AND user_id=:user "
                    "AND harness=:harness AND session_id=:session AND source_revision=:revision "
                    "AND root_run_incarnation=:resolved_root"
                ),
                {**scope, "revision": revision, "resolved_root": resolved_root},
            )
            existing_hooks = await db.scalar(
                text(
                    "SELECT count(*) FROM mobile_hook_evidence_events WHERE project_id=:project AND user_id=:user "
                    "AND harness=:harness AND session_id=:session AND source_revision=:revision "
                    "AND root_run_incarnation=:resolved_root"
                ),
                {**scope, "revision": revision, "resolved_root": resolved_root},
            )
            if (
                zero_exists
                and not stale_roots
                and existing_hooks == len(valid_hooks)
                and existing_skills == len(valid_skills)
                and bool(run.root_verified if run else False) == bool(resolved_root)
            ):
                count = await db.scalar(
                    text(
                        "SELECT count(*) FROM mobile_evidence_events WHERE project_id=:project AND user_id=:user "
                        "AND harness=:harness AND session_id=:session"
                    ),
                    scope,
                )
                await db.rollback()
                return {"status": status, "matched": (count or 0) + existing_skills + existing_hooks}
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
        old_skills = (
            (
                await db.execute(
                    text(
                        "SELECT DISTINCT component_id FROM mobile_skill_evidence_events WHERE project_id=:project "
                        "AND user_id=:user AND harness=:harness AND session_id=:session"
                    ),
                    scope,
                )
            )
            .scalars()
            .all()
        )
        old_hooks = (
            (
                await db.execute(
                    text(
                        "SELECT DISTINCT component_id FROM mobile_hook_evidence_events WHERE project_id=:project "
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
                "DELETE FROM mobile_hook_evidence_events WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        await db.execute(
            text(
                "DELETE FROM mobile_skill_evidence_events WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        await db.execute(
            text(
                "DELETE FROM mobile_evidence_events WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        await db.execute(
            text(
                "DELETE FROM mobile_eligible_event_times WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND session_id=:session"
            ),
            scope,
        )
        if zero_times:
            for offset, event_time, digest in zero_times:
                await db.execute(
                    text(
                        "INSERT INTO mobile_eligible_event_times(project_id,user_id,harness,session_id,"
                        "source_line_offset,root_run_incarnation,source_revision,event_time,layer_hash) "
                        "VALUES (:project,:user,:harness,:session,:offset,:run,:revision,:time,:digest)"
                    ),
                    {
                        **scope,
                        "offset": offset,
                        "run": run_incarnation,
                        "revision": revision,
                        "time": event_time,
                        "digest": digest,
                    },
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
        for fact in valid_skills:
            await db.execute(
                text(
                    "INSERT INTO mobile_skill_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                    "block_key,layer_hash,scope,alias,component_id,source_revision,run_incarnation,"
                    "root_session_id,root_run_incarnation,event_time,result_state) "
                    "VALUES (:project,:user,:harness,:session,:source_line_offset,:block_key,:layer_hash,:scope,"
                    ":alias,:component_id,:source_revision,:run_incarnation,:root_session_id,"
                    ":root_run_incarnation,:event_time,'success')"
                ),
                {**scope, **fact},
            )
        for fact in valid_hooks:
            await db.execute(
                text(
                    "INSERT INTO mobile_hook_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                    "block_key,layer_hash,binding_sha256,component_id,source_revision,run_incarnation,root_session_id,"
                    "root_run_incarnation,event_time,outcome) VALUES (:project,:user,:harness,:session,:source_line_offset,"
                    ":block_key,:layer_hash,:binding_sha256,:component_id,:source_revision,:run_incarnation,"
                    ":root_session_id,:root_run_incarnation,:event_time,:outcome)"
                ),
                {**scope, **fact},
            )
        await db.execute(
            text(
                "INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,source_revision,status,"
                "first_source_offset,source_retained_until,source_policy_epoch,source_highest_line) "
                "VALUES (:project,:user,:harness,:session,:revision,:status,:first_source_offset,:retained_until,"
                ":policy_epoch,:highest_line) "
                "ON CONFLICT (project_id,user_id,harness,session_id) DO UPDATE "
                "SET source_revision=EXCLUDED.source_revision,status=EXCLUDED.status,"
                "first_source_offset=EXCLUDED.first_source_offset,"
                "source_retained_until=EXCLUDED.source_retained_until,source_policy_epoch=EXCLUDED.source_policy_epoch,"
                "source_highest_line=GREATEST(mobile_session_publications.source_highest_line,EXCLUDED.source_highest_line),"
                "updated_at=now()"
            ),
            {
                **scope,
                "revision": revision or "unknown",
                "status": status,
                "first_source_offset": first_source_offset,
                "retained_until": retained_until,
                "policy_epoch": policy.source_policy_epoch,
                "highest_line": rows[-1]["line_offset"] if revision is not None and rows else None,
            },
        )
        changed_components = set(old_components) | {fact["component_id"] for fact in valid}
        changed_skills = set(old_skills) | {fact["component_id"] for fact in valid_skills}
        changed_hooks = set(old_hooks) | {fact["component_id"] for fact in valid_hooks}
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
        if changed_skills:
            skill_authors = (
                (
                    await db.execute(
                        text(
                            "SELECT DISTINCT original_author_id FROM mobile_listing_provenance "
                            "WHERE kind='skill' AND listing_id=ANY(:ids)"
                        ),
                        {"ids": list(changed_skills)},
                    )
                )
                .scalars()
                .all()
            )
            subjects.update((author, "author") for author in skill_authors)
        if changed_hooks:
            hook_authors = (
                (
                    await db.execute(
                        text(
                            "SELECT DISTINCT original_author_id FROM mobile_listing_provenance "
                            "WHERE kind='hook' AND listing_id=ANY(:ids)"
                        ),
                        {"ids": list(changed_hooks)},
                    )
                )
                .scalars()
                .all()
            )
            subjects.update((author, "author") for author in hook_authors)
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
                    "UPDATE mobile_run_instances SET source_status=:status,root_verified=:verified "
                    "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                ),
                {
                    **scope,
                    "status": status if run_incarnation else "pending",
                    "verified": bool(resolved_root is not None and status in ("complete", "partial")),
                },
            )
        # ClickHouse and Postgres have no shared transaction. Recheck source
        # after publication preparation; a racing append/repair retries instead
        # of committing an already-stale generation.
        fresh = await _rows(project, user, harness, session)
        if (
            _revision(fresh or [], retained_suffix=True) != observed_revision
            or _source_retained_until(fresh or [], observed_revision, retention_days=days) != observed_floor
        ):
            await db.rollback()
            raise RuntimeError("Mobile source or retention floor changed during evidence publication")
        # A parent that becomes qualified after child ingest must cause every
        # admitted direct child to reproject. Each child in turn wakes its own
        # descendants; unrelated roots do not lose their scoped cursor.
        if run is not None:
            await db.execute(
                text(
                    "INSERT INTO mobile_projection_queue(project_id,user_id,harness,session_id) "
                    "SELECT project_id,user_id,harness,session_id FROM mobile_run_instances "
                    "WHERE project_id=:project AND user_id=:user AND harness='pi' "
                    "AND parent_run_incarnation=:run "
                    "ON CONFLICT (project_id,user_id,harness,session_id) DO UPDATE SET requested_at=now()"
                ),
                {**scope, "run": run.run_incarnation},
            )
        await db.commit()
    return {"status": status, "matched": len(valid) + len(valid_skills) + len(valid_hooks)}


async def scan_retained_mobile_sources(ctx: dict) -> dict:
    """Keyset-scan retained Pi v2 senders for missed uploads or source repairs.

    Old/legacy hashes are never inferred or upgraded. A complete sweep rewinds
    to pick up sessions before the cursor in the next bounded pass. The queue
    and publication generations make all retries idempotent.
    """
    del ctx
    retention_days = (
        await ds.get_int("retention.trace_days", default=0) if await ds.get_bool("retention.enabled") else 0
    )
    source_floor = "AND timestamp>=now()-INTERVAL {days:UInt32} DAY " if retention_days > 0 else ""
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
            "AND (startsWith(layer_hash,'v2_') OR startsWith(layer_hash,'v3_')) "
            f"{source_floor}"
            "AND (project_id,user_id,session_id)>({project:String},{user:String},{session:String}) "
            "GROUP BY project_id,user_id,session_id ORDER BY project_id,user_id,session_id LIMIT 51 "
            "SETTINGS max_execution_time=5 FORMAT JSON",
            {
                "param_project": cursor.project_id,
                "param_user": cursor.user_id,
                "param_session": cursor.session_id,
                "param_days": retention_days,
            },
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
    """Bounded derived-data cleanup with a persisted check cursor.

    Each pass checks up to 500 old publications, including ones whose source
    disappeared; failed/unchanged first candidates cannot starve later rows.
    The mobile read barrier remains closed until separate source freshness
    qualification; this sweep alone is not an atomic CH/PG read guarantee.
    """
    del ctx
    async with async_session() as db:
        candidates = (
            await db.execute(
                text(
                    "SELECT project_id,user_id,harness,session_id FROM mobile_session_publications "
                    "WHERE status IN ('complete','partial') AND ("
                    "(source_policy_epoch != (SELECT source_policy_epoch FROM mobile_read_controls "
                    "WHERE project_id='default') AND (last_checked_at IS NULL OR "
                    "last_checked_at<clock_timestamp()-INTERVAL '5 minutes')) OR (updated_at<now()-INTERVAL '1 day' "
                    "AND (last_checked_at IS NULL OR last_checked_at<now()-INTERVAL '12 hours'))) "
                    "ORDER BY last_checked_at NULLS FIRST,updated_at,project_id,user_id,session_id LIMIT 500"
                )
            )
        ).all()
    checked = 0
    revoked = 0
    failed = False
    async with async_session() as db:
        for project, user, harness, session in candidates:
            try:
                result = await project_pi_session({}, project, str(user), harness, session)
                if result["status"] not in ("complete", "partial"):
                    revoked += 1
            except Exception:
                from loguru import logger as optic

                optic.exception("mobile retained evidence cleanup failed")
                failed = True
            finally:
                checked += 1
                # A failed proof gets a short durable retry lease; without
                # one a permanently bad first key would starve later rows.
                await db.execute(
                    text(
                        "UPDATE mobile_session_publications SET last_checked_at=now() "
                        "WHERE project_id=:project AND user_id=:user AND harness=:harness AND session_id=:session"
                    ),
                    {"project": project, "user": user, "harness": harness, "session": session},
                )
                if checked % 25 == 0:
                    await db.commit()  # Preserve progress if the worker's 120s timeout interrupts a long sweep.
        await db.commit()
    return {"checked": checked, "revoked": revoked, "failed": failed}


async def run_mobile_projection_queue(ctx: dict) -> dict:
    """Drain a small durable queue; failed jobs stay available for later retry."""
    del ctx
    attempted = 0
    completed = 0
    async with async_session() as db:
        # Claim under row locks, then *commit before* projection. A parent may
        # enqueue a direct child during its projection; keeping that child's
        # selected row locked here would block the inner transaction forever.
        # The durable lease also prevents another worker from replaying the
        # same cohort while this worker processes it. A killed job retries.
        pending = (
            await db.execute(
                text(
                    "WITH picked AS (SELECT project_id,user_id,harness,session_id "
                    "FROM mobile_projection_queue WHERE requested_at<=now() "
                    "ORDER BY requested_at LIMIT 50 FOR UPDATE SKIP LOCKED) "
                    "UPDATE mobile_projection_queue q SET "
                    "requested_at=now()+INTERVAL '3 minutes',attempts=q.attempts+1 "
                    "FROM picked p WHERE q.project_id=p.project_id AND q.user_id=p.user_id "
                    "AND q.harness=p.harness AND q.session_id=p.session_id "
                    "RETURNING q.project_id,q.user_id,q.harness,q.session_id,q.requested_at"
                )
            )
        ).all()
        await db.commit()
        for project, user, harness, session, claimed_at in pending:
            attempted += 1
            params = {"project": project, "user": user, "harness": harness, "session": session, "claimed": claimed_at}
            try:
                result = await project_pi_session({}, project, str(user), harness, session)
                # A parent can request a fresh child projection while this job
                # runs. Exact lease equality preserves that newer request.
                if result["status"] in ("complete", "partial", "legacy_layer", "unsupported"):
                    await db.execute(
                        text(
                            "DELETE FROM mobile_projection_queue WHERE project_id=:project AND user_id=:user "
                            "AND harness=:harness AND session_id=:session AND requested_at=:claimed"
                        ),
                        params,
                    )
                    completed += 1
                else:
                    await db.execute(
                        text(
                            "UPDATE mobile_projection_queue SET requested_at=now()+INTERVAL '5 minutes' "
                            "WHERE project_id=:project AND user_id=:user AND harness=:harness "
                            "AND session_id=:session AND requested_at=:claimed"
                        ),
                        params,
                    )
            except Exception:
                # Fixed logger text only: no transcript or secrets in worker logs.
                from loguru import logger as optic

                optic.exception("mobile evidence projection failed for scoped session")
                await db.execute(
                    text(
                        "UPDATE mobile_projection_queue SET requested_at=now()+INTERVAL '1 minute' "
                        "WHERE project_id=:project AND user_id=:user AND harness=:harness "
                        "AND session_id=:session AND requested_at=:claimed"
                    ),
                    params,
                )
            await db.commit()
    return {"attempted": attempted, "completed": completed, "failed": False}
