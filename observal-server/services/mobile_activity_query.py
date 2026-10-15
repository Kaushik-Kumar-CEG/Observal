# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bounded, revalidated Pi MCP observations and source-verified partial zeros.

Reads are source-checked on EVERY request. A missing/purged/repaired source,
unsupported cohort, or oversized request returns unavailable, not a stale
aggregate. The bounded initial implementation does not assert whole-window
eligibility or complete historical coverage.
"""

import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from services.clickhouse.client import _query

MAX_SESSIONS = 20
MAX_SOURCE_LINES = 40000
Scope = Literal["user", "author"]

# This predicate is deliberately shared by candidate selection and the final
# aggregate. No hidden/private listing can affect a count or denominator.
_VISIBLE = """
FROM mobile_evidence_events e
JOIN mobile_layer_components map ON map.project_id=e.project_id
 AND map.user_id=e.user_id AND map.harness=e.harness AND map.layer_hash=e.layer_hash AND map.alias=e.alias
JOIN mcp_listings l ON l.id=e.component_id AND l.is_private=false
JOIN mcp_versions v ON v.id=map.version_id AND v.listing_id=l.id AND v.status IN ('approved','archived')
JOIN mobile_session_publications pub ON pub.project_id=e.project_id AND pub.user_id=e.user_id
 AND pub.harness=e.harness AND pub.session_id=e.session_id AND pub.status IN ('complete','partial')
WHERE e.project_id=:project AND e.harness='pi' AND e.event_time>=:start AND e.event_time<:end
 AND (SELECT pe.status FROM mobile_publication_events pe
      WHERE pe.kind='mcp' AND pe.listing_id=l.id AND pe.version_id=v.id AND pe.recorded_at<=e.event_time
      ORDER BY pe.recorded_at DESC,pe.id DESC LIMIT 1)='approved'
"""


def _scope(scope: Scope, component: uuid.UUID | None = None) -> tuple[str, dict]:
    predicate = (
        " AND e.user_id=:subject"
        if scope == "user"
        else (
            " AND EXISTS (SELECT 1 FROM mobile_listing_provenance author "
            "WHERE author.kind='mcp' AND author.listing_id=l.id AND author.original_author_id=:subject)"
        )
    )
    params = {}
    if component is not None:
        predicate += " AND l.id=:component"
        params["component"] = component
    return predicate, params


async def _source_verified(rows: list, project: str) -> bool:
    """Recheck only bound scoped source identities, with a fixed materialization budget."""
    if not rows or len(rows) > MAX_SESSIONS:
        return False
    expected = {(str(user), session): (revision, first) for user, session, revision, first in rows}
    users = sorted({user for user, _ in expected})
    sessions = sorted({sid for _, sid in expected})

    # ClickHouse Array(String) query parameters use single-quoted SQL literals,
    # not JSON arrays. Every value remains bound, with quotes/backslashes
    # escaped for the parameter parser (never interpolated into the SQL).
    def array_param(items: list[str]) -> str:
        return "[" + ",".join("'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'" for value in items) + "]"

    response = await _query(
        "SELECT user_id,session_id,line_offset,line_hash,raw_line_truncated,length(raw_line) AS raw_length "
        "FROM session_events FINAL WHERE project_id={project:String} AND harness='pi' "
        "AND user_id IN {users:Array(String)} AND session_id IN {sessions:Array(String)} "
        "AND is_source_record=1 ORDER BY user_id,session_id,line_offset LIMIT 40001 FORMAT JSON",
        {"param_project": project, "param_users": array_param(users), "param_sessions": array_param(sessions)},
    )
    response.raise_for_status()
    source = response.json().get("data", [])
    if len(source) > MAX_SOURCE_LINES:
        return False
    grouped = defaultdict(list)
    for row in source:
        key = (row["user_id"], row["session_id"])
        if key in expected:
            grouped[key].append(row)
    for key, (revision, first) in expected.items():
        lines = grouped.get(key, [])
        if (
            not lines
            or len(lines) > 10000
            or [int(r["line_offset"]) for r in lines] != list(range(first, first + len(lines)))
        ):
            return False
        if any(not r.get("line_hash") or int(r["raw_line_truncated"]) or not int(r["raw_length"]) for r in lines):
            return False
        source_revision = hashlib.sha256(
            json.dumps([[int(r["line_offset"]), r["line_hash"]] for r in lines], separators=(",", ":")).encode()
        ).hexdigest()
        if source_revision != revision:
            return False
    return True


async def _verified_restrict(
    db: AsyncSession,
    subject: uuid.UUID,
    scope: Scope,
    project: str,
    start: datetime,
    end: datetime,
    component: uuid.UUID | None = None,
) -> tuple[str, dict, str] | None:
    predicate, extras = _scope(scope, component)
    params = {"subject": subject, "project": project, "start": start, "end": end, **extras}
    # An overflow yields unavailable instead of truncating a supposedly exact
    # reading. Candidate and aggregate use identical visibility/author filters.
    candidate_sql = (
        "SELECT DISTINCT e.user_id,e.session_id,pub.source_revision,pub.first_source_offset "
        + _VISIBLE
        + predicate
        + " ORDER BY e.user_id,e.session_id,pub.source_revision,pub.first_source_offset LIMIT 21"
    )
    candidates = (await db.execute(text(candidate_sql), params)).all()
    if not candidates or len(candidates) > MAX_SESSIONS or not await _source_verified(candidates, project):
        return None
    clauses = []
    for index, (user, session, _revision, _first) in enumerate(candidates):
        params[f"u{index}"] = user
        params[f"s{index}"] = session
        clauses.append(f"(e.user_id=:u{index} AND e.session_id=:s{index})")
    return predicate, params, " AND (" + " OR ".join(clauses) + ")"


async def qualified_zero_subset(
    db: AsyncSession, subject: uuid.UUID, project: str, start: datetime, end: datetime
) -> dict | None:
    """Self-only tool-free activity in a currently eligible uploader-bound Pi layer.

    Not a general zero or a full-window measurement. Each candidate's complete
    source is rechecked in ClickHouse, including the persisted revision; exceeding
    the fixed verification budget returns unavailable.
    """
    params = {"project": project, "subject": subject, "start": start, "end": end}
    candidates = (
        await db.execute(
            text(
                "SELECT DISTINCT z.user_id,z.session_id,pub.source_revision,pub.first_source_offset "
                "FROM mobile_eligible_event_times z JOIN mobile_session_publications pub "
                "ON pub.project_id=z.project_id AND pub.user_id=z.user_id "
                "AND pub.harness=z.harness AND pub.session_id=z.session_id "
                "JOIN mobile_run_instances run ON run.project_id=z.project_id AND run.user_id=z.user_id "
                "AND run.harness=z.harness AND run.session_id=z.session_id "
                "WHERE z.project_id=:project AND z.user_id=:subject AND z.harness='pi' "
                "AND z.event_time>=:start AND z.event_time<:end AND pub.status='complete' "
                "AND pub.source_revision=z.source_revision AND run.root_verified=true "
                "AND run.run_incarnation=z.root_run_incarnation "
                "AND EXISTS (SELECT 1 FROM mobile_layer_components map "
                "JOIN mcp_listings l ON l.id=map.component_id AND l.is_private=false "
                "JOIN mcp_versions v ON v.id=map.version_id AND v.listing_id=l.id "
                "AND v.status IN ('approved','archived') "
                "WHERE map.project_id=z.project_id AND map.user_id=z.user_id "
                "AND map.harness=z.harness AND map.layer_hash=z.layer_hash "
                "AND (SELECT pe.status FROM mobile_publication_events pe WHERE pe.kind='mcp' "
                "AND pe.listing_id=l.id AND pe.version_id=v.id AND pe.recorded_at<=z.event_time "
                "ORDER BY pe.recorded_at DESC,pe.id DESC LIMIT 1)='approved') "
                "ORDER BY z.user_id,z.session_id,pub.source_revision,pub.first_source_offset LIMIT 21"
            ),
            params,
        )
    ).all()
    if not candidates or len(candidates) > MAX_SESSIONS or not await _source_verified(candidates, project):
        return None
    return {"roots": 0, "calls": 0, "days": 0, "eligible_sessions": len(candidates)}


async def qualified_observations(
    db: AsyncSession,
    subject: uuid.UUID,
    scope: Scope,
    project: str,
    start: datetime,
    end: datetime,
    component: uuid.UUID | None = None,
) -> dict | None:
    """Positive-only partial cohort. None means no safe reading, NOT zero."""
    verified = await _verified_restrict(db, subject, scope, project, start, end, component)
    if verified is None:
        return None
    predicate, params, restrict = verified
    stats_sql = (
        "SELECT count(*) AS calls, "
        "count(DISTINCT (e.user_id, e.session_id)) AS eligible_sessions, "
        "count(DISTINCT (e.user_id, e.root_run_incarnation)) FILTER (WHERE e.root_run_incarnation IS NOT NULL) AS roots, "
        "count(DISTINCT (e.event_time AT TIME ZONE 'UTC')::date) AS days " + _VISIBLE + predicate + restrict
    )
    row = (await db.execute(text(stats_sql), params)).one()
    if not row.calls:
        return None
    return {"calls": row.calls, "eligible_sessions": row.eligible_sessions, "roots": row.roots, "days": row.days}


async def qualified_components(
    db: AsyncSession,
    subject: uuid.UUID,
    scope: Scope,
    project: str,
    start: datetime,
    end: datetime,
) -> list[dict] | None:
    verified = await _verified_restrict(db, subject, scope, project, start, end)
    if verified is None:
        return None
    predicate, params, restrict = verified
    rows = (
        await db.execute(
            text(
                "SELECT l.id,l.name,count(*) AS calls,count(DISTINCT(e.user_id,e.session_id)) AS eligible_sessions,"
                "count(DISTINCT(e.user_id,e.root_run_incarnation)) FILTER (WHERE e.root_run_incarnation IS NOT NULL) AS roots,"
                "count(DISTINCT(e.event_time AT TIME ZONE 'UTC')::date) AS days "
                + _VISIBLE
                + predicate
                + restrict
                + " GROUP BY l.id,l.name ORDER BY l.id LIMIT 21"
            ),
            params,
        )
    ).all()
    if len(rows) > 20:
        return None
    return [
        dict(
            id=row.id,
            name=row.name,
            calls=row.calls,
            eligible_sessions=row.eligible_sessions,
            roots=row.roots,
            days=row.days,
        )
        for row in rows
    ]


# The prospective trace-first path reads indexed PG facts only. Existing v1
# functions above retain their bounded source revalidation until the project
# read-control/TTL/erasure gate is qualified. This is NOT a third projector.
_TRACE_FROM = """
FROM mobile_evidence_events e
JOIN mobile_run_instances run ON run.project_id=e.project_id AND run.user_id=e.user_id
 AND run.harness=e.harness AND run.run_incarnation=e.root_run_incarnation
 AND run.root_verified=true AND run.source_status IN ('complete','partial')
JOIN mobile_layer_components map ON map.project_id=e.project_id AND map.user_id=e.user_id
 AND map.harness=e.harness AND map.layer_hash=e.layer_hash AND map.alias=e.alias AND map.component_id=e.component_id
JOIN mobile_session_publications pub ON pub.project_id=e.project_id AND pub.user_id=e.user_id
 AND pub.harness=e.harness AND pub.session_id=e.session_id AND pub.status IN ('complete','partial')
JOIN mcp_listings l ON l.id=e.component_id
JOIN mobile_listing_provenance p ON p.kind='mcp' AND p.listing_id=l.id
JOIN users origin ON origin.id=p.original_author_id AND origin.auth_provider!='deactivated'
JOIN mcp_versions v ON v.id=map.version_id AND v.listing_id=l.id
JOIN users actor ON actor.id=e.user_id AND actor.auth_provider!='deactivated'
LEFT JOIN (
  SELECT pe.listing_id,pe.version_id,pe.status,pe.recorded_at,
   lead(pe.recorded_at) OVER (PARTITION BY pe.listing_id,pe.version_id
                             ORDER BY pe.recorded_at,pe.id) AS next_recorded_at
  FROM mobile_publication_events pe WHERE pe.kind='mcp'
) approval ON approval.listing_id=l.id AND approval.version_id=v.id
 AND approval.recorded_at<=e.event_time
 AND (approval.next_recorded_at IS NULL OR approval.next_recorded_at>e.event_time)
WHERE e.project_id=:project AND e.harness='pi' AND e.event_time>=:start AND e.event_time<:end
 AND e.root_run_incarnation IS NOT NULL
"""
_TRACE_APPROVED = " AND approval.status='approved'"


def _trace_scope(scope: Scope, *, viewer_self: bool) -> str:
    public = "l.is_private=false AND v.status IN ('approved','archived')" + _TRACE_APPROVED
    if scope == "author":
        return " AND p.original_author_id=:subject AND " + public
    # A private self-owned listing is visible only to the owner reading their
    # own User scope. An admin viewing another user never inherits that access.
    if viewer_self:
        return " AND e.user_id=:subject AND ((" + public + ") OR (l.is_private=true AND l.submitted_by=:subject))"
    return " AND e.user_id=:subject AND " + public


async def trace_union(
    db: AsyncSession,
    subject: uuid.UUID,
    scope: Scope,
    project: str,
    start: datetime,
    end: datetime,
    *,
    viewer_self: bool = False,
) -> dict | None:
    """Partial-only distinct actor/root union; no source JSONL per card.

    None is *not recorded*, never a measured zero. Full-window supported zero
    awaits an instrumented all-kind zero-positive eligibility cohort.
    """
    from services.mobile_read_control import readable

    if not await readable(db, project):
        return None
    sql = (
        "SELECT count(DISTINCT (e.user_id,e.root_run_incarnation)) AS roots, "
        "count(*) AS calls,count(DISTINCT (e.event_time AT TIME ZONE 'UTC')::date) AS days "
        + _TRACE_FROM
        + _trace_scope(scope, viewer_self=viewer_self)
    )
    # A concentrated original author otherwise provokes one nested lookup per
    # event into run, publication and account tables (10K+ repeated lookups).
    await db.execute(text("SET LOCAL enable_nestloop=off"))
    row = (await db.execute(text(sql), {"project": project, "subject": subject, "start": start, "end": end})).one()
    return {"roots": row.roots, "calls": row.calls, "days": row.days} if row.roots else None


async def trace_pair_batch(
    db: AsyncSession,
    subjects: list[uuid.UUID],
    viewer: uuid.UUID,
    project: str,
    start: datetime,
    end: datetime,
    *,
    include_author: bool = True,
) -> tuple[dict[uuid.UUID, dict], dict[uuid.UUID, dict]]:
    """Materialize bounded viewer-relevant facts once, then group two independent scopes."""
    from services.mobile_read_control import readable

    if not await readable(db, project):
        return {}, {}
    params = {"project": project, "subjects": subjects, "viewer": viewer, "start": start, "end": end}
    # The materialized CTE prevents repeated run/visibility/approval lookups
    # when both scopes are requested in the same viewport. It contains only
    # actors/authors on the requested 12 IDs, not the global evidence corpus.
    sql = (
        "WITH eligible AS MATERIALIZED (SELECT e.user_id,e.root_run_incarnation,e.event_time,"
        "p.original_author_id,l.is_private,l.submitted_by,v.status AS version_status,"
        "approval.status AS publication_status "
        + _TRACE_FROM
        + " AND ((:include_author AND p.original_author_id=ANY(CAST(:subjects AS uuid[]))) "
        "OR e.user_id=ANY(CAST(:subjects AS uuid[])))) "
        "SELECT 'author' AS scope_name,original_author_id AS subject,"
        "count(DISTINCT (user_id,root_run_incarnation)) AS roots,count(*) AS calls,"
        "count(DISTINCT (event_time AT TIME ZONE 'UTC')::date) AS days "
        "FROM eligible WHERE :include_author AND original_author_id=ANY(CAST(:subjects AS uuid[])) "
        "AND is_private=false AND version_status IN ('approved','archived') "
        "AND publication_status='approved' GROUP BY original_author_id "
        "UNION ALL SELECT 'user' AS scope_name,user_id AS subject,"
        "count(DISTINCT (user_id,root_run_incarnation)) AS roots,count(*) AS calls,"
        "count(DISTINCT (event_time AT TIME ZONE 'UTC')::date) AS days "
        "FROM eligible WHERE user_id=ANY(CAST(:subjects AS uuid[])) "
        "AND ((is_private=false AND version_status IN ('approved','archived') "
        "AND publication_status='approved') "
        "OR (user_id=:viewer AND is_private=true AND submitted_by=:viewer)) "
        "GROUP BY user_id"
    )
    params["include_author"] = include_author
    # PostgreSQL otherwise selects 10K+ repeated per-fact nested lookups into
    # publication, run and user tables on a concentrated original author.
    # This is transaction-local (never a global database configuration change).
    await db.execute(text("SET LOCAL enable_nestloop=off"))
    authors: dict[uuid.UUID, dict] = {}
    users: dict[uuid.UUID, dict] = {}
    for row in (await db.execute(text(sql), params)).all():
        if row.roots:
            (authors if row.scope_name == "author" else users)[row.subject] = {
                "roots": row.roots,
                "calls": row.calls,
                "days": row.days,
            }
    return authors, users


async def trace_component_page(
    db: AsyncSession,
    subject: uuid.UUID,
    scope: Scope,
    project: str,
    start: datetime,
    end: datetime,
    *,
    viewer_self: bool = False,
    after: tuple[int, uuid.UUID] | None = None,
    component: uuid.UUID | None = None,
    limit: int = 20,
) -> list[dict] | None:
    """Indexed PG fact aggregation with stable reach/id keyset, 21-row probe."""
    from services.mobile_read_control import readable

    if not await readable(db, project):
        return None
    params = {"project": project, "subject": subject, "start": start, "end": end, "limit": limit + 1}
    component_sql = ""
    if component is not None:
        component_sql = " AND l.id=:component"
        params["component"] = component
    after_sql = ""
    if after:
        after_sql = (
            " HAVING count(DISTINCT (e.user_id,e.root_run_incarnation))<:after_roots OR "
            "(count(DISTINCT (e.user_id,e.root_run_incarnation))=:after_roots AND l.id>:after_id)"
        )
        params.update(after_roots=after[0], after_id=after[1])
    sql = (
        "SELECT l.id,l.name,p.original_author_id,origin.username AS author_username, "
        "origin.name AS author_name, "
        "count(DISTINCT (e.user_id,e.root_run_incarnation)) AS roots, count(*) AS calls "
        + _TRACE_FROM
        + _trace_scope(scope, viewer_self=viewer_self)
        + component_sql
        + " GROUP BY l.id,l.name,p.original_author_id,origin.username,origin.name"
        + after_sql
        + " ORDER BY roots DESC,l.id LIMIT :limit"
    )
    await db.execute(text("SET LOCAL enable_nestloop=off"))
    return [dict(row._mapping) for row in (await db.execute(text(sql), params)).all()]
