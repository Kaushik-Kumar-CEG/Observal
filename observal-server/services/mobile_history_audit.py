# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only, bounded LOCAL retained-source qualification; never a phone reading.

The scan describes *candidates* for the existing idempotent projection queue,
not historical positives. It neither fills missing authors/approvals nor guesses
aliases, skill content, hook receipts, parent links or uploader identity. No
identifiers or transcript bytes leave this module's returned aggregate.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from database import async_session
from jobs.mobile_evidence import (
    _matched,
    _matched_hook_receipts,
    _matched_skill_loads,
    _revision,
    _rows,
    _source_retained_until,
    _source_time,
)
from services.clickhouse.client import _query
from services.mobile_pi_hook_receipts import extract_hook_receipts
from services.mobile_pi_skill_loads import extract_skill_loads
from services.session_parsers.pi_invocations import PiInvocationExtractor

_KINDS = ("mcp", "skill", "hook")
_PINS = {
    "mcp": "mobile_layer_components",
    "skill": "mobile_skill_layer_components",
    "hook": "mobile_hook_layer_components",
}
_REGISTRY = {
    "mcp": ("mcp_listings", "mcp_versions"),
    "skill": ("skill_listings", "skill_versions"),
    "hook": ("hook_listings", "hook_versions"),
}


def _root_source(rows: list[dict], run, session: str, now: datetime) -> bool:
    """A complete, retained, witnessed same-session root; no inferred parent."""
    revision = _revision(rows)
    until = _source_retained_until(rows, revision)
    if (
        revision is None
        or until is None
        or until <= now
        or not run
        or not run.root_verified
        or run.origin_witness != "pi_session_start_root_v1"
        or run.parent_session_id is not None
        or run.source_status not in ("complete", "partial")
    ):
        return False
    try:
        header = json.loads(rows[0]["raw_line"])
    except (TypeError, KeyError, ValueError):
        return False
    return bool(
        isinstance(header, dict)
        and header.get("type") == "session"
        and header.get("id") == session
        and not header.get("parentSession")
        and _source_time(header.get("timestamp")) is not None
        and hashlib.sha256(rows[0]["raw_line"].encode()).hexdigest() == run.header_hash
        and all(not row.get("parent_session_id") for row in rows)
    )


async def _registry_at_event(db, kind: str, component: uuid.UUID, version: uuid.UUID, when: datetime) -> bool:
    """Original author, current public listing and recorded event-time approval."""
    listing, versions = _REGISTRY[kind]  # fixed table names, never user input
    return bool(
        await db.scalar(
            text(
                f"SELECT 1 FROM {listing} l JOIN {versions} v ON v.listing_id=l.id "
                "JOIN mobile_listing_provenance p ON p.kind=:kind AND p.listing_id=l.id "
                "JOIN users author ON author.id=p.original_author_id AND author.auth_provider!='deactivated' "
                "WHERE l.id=:component AND v.id=:version AND l.is_private=false "
                "AND p.captured_at<=:when AND v.status IN ('approved','archived') AND EXISTS ("
                "SELECT 1 FROM mobile_publication_events e WHERE e.kind=:kind AND e.listing_id=l.id "
                "AND e.version_id=v.id AND e.status='approved' AND e.recorded_at<=:when "
                "AND NOT EXISTS (SELECT 1 FROM mobile_publication_events later "
                "WHERE later.kind=e.kind AND later.listing_id=e.listing_id AND later.version_id=e.version_id "
                "AND later.recorded_at<=:when AND (later.recorded_at,later.id)>(e.recorded_at,e.id))) LIMIT 1"
            ),
            {"kind": kind, "component": component, "version": version, "when": when},
        )
    )


async def _candidates(
    db, project: str, user: uuid.UUID, rows: list[dict], run, now: datetime
) -> dict[str, list[datetime]]:
    """Reuse projection's exact event extractors; never materialize an audit fact."""
    found: dict[str, list[datetime]] = {kind: [] for kind in _KINDS}
    hashes = {row.get("layer_hash") for row in rows}
    if not hashes or any(not isinstance(h, str) or not h.startswith(("v2_", "v3_")) for h in hashes):
        return found
    layers = (
        await db.execute(
            text(
                "SELECT layer_hash,expected_components,expected_skills,expected_hooks "
                "FROM mobile_verified_layers WHERE project_id=:project AND user_id=:user AND harness='pi' "
                "AND layer_hash=ANY(:hashes)"
            ),
            {"project": project, "user": user, "hashes": list(hashes)},
        )
    ).all()
    if {row.layer_hash for row in layers} != hashes:
        return found
    pins: dict[str, dict[str, dict]] = {kind: {} for kind in _KINDS}
    for kind, table in _PINS.items():
        columns = {
            "mcp": "alias,component_id,version_id",
            "skill": "scope,alias,component_id,version_id,location_sha256,content_sha256",
            "hook": "binding_sha256,component_id,version_id,event",
        }[kind]
        records = (
            (
                await db.execute(
                    text(
                        f"SELECT layer_hash,{columns} FROM {table} "
                        "WHERE project_id=:project AND user_id=:user AND harness='pi' AND layer_hash=ANY(:hashes)"
                    ),
                    {"project": project, "user": user, "hashes": list(hashes)},
                )
            )
            .mappings()
            .all()
        )
        for record in records:
            layer = pins[kind].setdefault(record["layer_hash"], {})
            key = {
                "mcp": lambda r: r["alias"],
                "skill": lambda r: (r["scope"], r["alias"]),
                "hook": lambda r: r["binding_sha256"],
            }[kind](record)
            layer[key] = record
    if any(
        len(pins["mcp"].get(layer.layer_hash, {})) != layer.expected_components
        or len(pins["skill"].get(layer.layer_hash, {})) != layer.expected_skills
        or len(pins["hook"].get(layer.layer_hash, {})) != layer.expected_hooks
        for layer in layers
    ):
        return found
    mcp_map = {h: {alias: r["component_id"] for alias, r in pins["mcp"].get(h, {}).items()} for h in hashes}
    skill_map = {
        h: {
            key: (r["component_id"], r["location_sha256"], r["content_sha256"])
            for key, r in pins["skill"].get(h, {}).items()
        }
        for h in hashes
    }
    hook_map = {h: {key: (r["component_id"], r["event"]) for key, r in pins["hook"].get(h, {}).items()} for h in hashes}
    revision = _revision(rows)
    started = _source_time(json.loads(rows[0]["raw_line"]).get("timestamp"))
    common = {
        "revision": revision,
        "run_incarnation": run.run_incarnation,
        "root": run.run_incarnation,
        "root_session_id": rows[0]["session_id"],
        "root_start": started,
    }
    mcps, _ = _matched(
        PiInvocationExtractor().extract(rows),
        rows,
        mcp_map,
        verified_root=run.run_incarnation,
        root_start=started,
        root_session_id=rows[0]["session_id"],
    )
    skills, _ = _matched_skill_loads(extract_skill_loads(rows)[0], rows, skill_map, **common)
    hooks, _ = _matched_hook_receipts(extract_hook_receipts(rows)[0], rows, hook_map, **common)
    for kind, facts in (("mcp", mcps), ("skill", skills), ("hook", hooks)):
        for fact in facts:
            if kind == "mcp" and fact["result_state"] == "unknown":
                continue
            stamp = fact["event_time"]
            if not isinstance(stamp, datetime) or stamp > now + timedelta(minutes=5):
                continue
            source = rows[fact["source_line_offset"]]
            if kind == "mcp":
                key = fact["alias"]
            elif kind == "skill":
                key = (fact["scope"], fact["alias"])
            else:
                key = fact["binding_sha256"]
            pin = pins[kind].get(source["layer_hash"], {}).get(key)
            if pin and await _registry_at_event(db, kind, fact["component_id"], pin["version_id"], stamp):
                found[kind].append(stamp)
    return found


async def audit_local_history(project: str = "default", *, limit: int = 50, now: datetime | None = None) -> dict:
    """Bounded aggregate; read-only transaction; small cells withheld even locally."""
    if not 1 <= limit <= 50 or not project or len(project) > 64:
        raise ValueError("invalid audit bound")
    now = now or datetime.now(UTC)
    response = await _query(
        "SELECT DISTINCT user_id,harness,session_id FROM session_events FINAL "
        "WHERE project_id={project:String} AND is_source_record=1 "
        "AND timestamp>={since:DateTime64(3)} AND timestamp<{until:DateTime64(3)} "
        "ORDER BY user_id,harness,session_id LIMIT {limit:UInt32} "
        "SETTINGS max_execution_time=5 FORMAT JSON",
        {
            "param_project": project,
            "param_since": (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
            "param_until": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
            "param_limit": limit + 1,
        },
    )
    response.raise_for_status()
    sources = response.json().get("data", [])
    if len(sources) > limit:
        return {"status": "incomplete", "reason": "bounded_page_overflow", "periods": {}}
    counts = {
        (period, harness, kind): 0 for period in ("1w", "1m") for harness in ("pi", "unsupported") for kind in _KINDS
    }
    async with async_session() as db:
        await db.execute(text("SET TRANSACTION READ ONLY"))
        for source in sources:
            harness = source.get("harness")
            if harness != "pi":
                continue  # unsupported harness cannot become a Pi positive
            try:
                user = uuid.UUID(source["user_id"])
                session = source["session_id"]
            except (KeyError, TypeError, ValueError):
                continue
            if not isinstance(session, str) or not session or len(session) > 256:
                continue
            alive = await db.scalar(
                text("SELECT 1 FROM users WHERE id=:user AND auth_provider!='deactivated'"), {"user": user}
            )
            if not alive:
                continue
            rows = await _rows(project, str(user), "pi", session)
            run = (
                await db.execute(
                    text(
                        "SELECT run_incarnation,header_hash,root_verified,origin_witness,parent_session_id,"
                        "source_status FROM mobile_run_instances WHERE project_id=:project AND user_id=:user "
                        "AND harness='pi' AND session_id=:session"
                    ),
                    {"project": project, "user": user, "session": session},
                )
            ).first()
            if not rows or not _root_source(rows, run, session, now):
                continue  # child/missing root lineage remains unknown, not zero
            for kind, stamps in (await _candidates(db, project, user, rows, run, now)).items():
                for period, days in (("1w", 7), ("1m", 30)):
                    if any(now - timedelta(days=days) <= stamp < now for stamp in stamps):
                        counts[(period, "pi", kind)] += 1  # one session, never call count
        await db.rollback()

    # No individual identifiers or raw transcript text, nor small-cell counts.
    def bucket(period: str, harness: str, kind: str) -> dict:
        if harness != "pi":
            return {"status": "unsupported", "candidate_roots": None}
        count = counts[(period, harness, kind)]
        return {
            "status": "partial_candidate" if count >= 5 else "not_recorded_or_suppressed",
            "candidate_roots": count if count >= 5 else None,
        }

    return {
        "status": "bounded",
        "source_sessions_examined": len(sources) if len(sources) >= 5 else "suppressed",
        "periods": {
            period: {
                harness: {kind: bucket(period, harness, kind) for kind in _KINDS} for harness in ("pi", "unsupported")
            }
            for period in ("1w", "1m")
        },
    }
