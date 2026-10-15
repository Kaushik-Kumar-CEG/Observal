# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bounded, revalidated positive Pi MCP observations; never invents zeros.

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
        "count(DISTINCT (e.user_id, e.root_session_id)) FILTER (WHERE e.root_session_id IS NOT NULL) AS roots, "
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
                "count(DISTINCT(e.user_id,e.root_session_id)) FILTER (WHERE e.root_session_id IS NOT NULL) AS roots,"
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
