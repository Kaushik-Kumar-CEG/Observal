# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Read-only, conditional legacy Pi MCP attribution preview; NEVER a phone fact.

Pre-v2/v3 snapshots are client reports rather than verified layer manifests. A
candidate may be used only after separate operator-approved, deletion-safe
backfill and read-time version/author/retention checks. Missing pins or old
publication history never become a named Author reading or supported zero.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from jobs.mobile_evidence import _revision, _source_retained_until, _source_time
from services.mobile_history_audit import _registry_at_event
from services.session_parsers.pi_invocations import PiInvocationExtractor

_LEGACY_HASH = re.compile(r"[0-9a-f]{16}\Z")
_FILE_HASH = re.compile(r"sha256-[0-9a-f]{64}\Z")
_ALIAS = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}\Z")
_MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class LegacyCallCandidate:
    project: str
    uploader: uuid.UUID
    layer_hash: str
    root_key: str
    source_revision: str
    source_line_offset: int
    block_key: str
    event_time: datetime
    component_id: uuid.UUID
    version: str
    alias: str
    result_state: str


@dataclass(frozen=True)
class LegacyQualifiedCall:
    candidate: LegacyCallCandidate
    version_id: uuid.UUID
    author_id: uuid.UUID | None  # Author requires original-author and recorded approval evidence.
    status: str = "observed_partial"  # Never a complete cohort, attestation, or supported zero.


def _pins(snapshot: dict) -> dict[str, tuple[uuid.UUID, str]] | None:
    try:
        content = snapshot["content"]
        if not isinstance(content, str) or len(content.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
            return None
        body = json.loads(content)
        harnesses = body["harnesses"]
        if not isinstance(harnesses, dict) or not isinstance(harnesses.get("pi"), list):
            return None
        entries = []
        pi_has_config = False
        for harness, files in harnesses.items():
            if not isinstance(harness, str) or not isinstance(files, list):
                return None
            for file in files:
                if (
                    not isinstance(file, dict)
                    or not isinstance(file.get("path"), str)
                    or not isinstance(file.get("hash"), str)
                ):
                    return None
                if not _FILE_HASH.fullmatch(file["hash"]):
                    return None
                entries.append((f"{harness}/{file['path']}", file["hash"]))
                if harness == "pi" and file["path"] in ("user:mcp.json", "project:.pi/mcp.json"):
                    pi_has_config = True
        if not pi_has_config or not entries or len(entries) > 200 or len({key for key, _ in entries}) != len(entries):
            return None
        digest = hashlib.sha256(json.dumps(sorted(entries), sort_keys=True).encode()).hexdigest()[:16]
        if digest != snapshot.get("hash"):
            return None
        recorded = body["pinned_versions"]
        if (
            not isinstance(recorded, dict)
            or not isinstance(recorded.get("standalone"), list)
            or not isinstance(recorded.get("agents"), list)
        ):
            return None
        pins = list(recorded["standalone"])
        for agent in recorded["agents"]:
            if not isinstance(agent, dict) or not isinstance(agent.get("components"), list):
                return None
            pins.extend(agent["components"])
        if len(pins) > 100:
            return None
        matched: dict[str, tuple[uuid.UUID, str]] = {}
        used_ids: set[uuid.UUID] = set()
        for pin in pins:
            if not isinstance(pin, dict):
                return None
            if pin.get("harness") != "pi" or pin.get("type") != "mcp":
                continue
            alias, version = pin.get("local_name"), pin.get("version")
            if (
                not isinstance(alias, str)
                or not _ALIAS.fullmatch(alias)
                or not isinstance(version, str)
                or not _VERSION.fullmatch(version)
            ):
                return None
            component = uuid.UUID(pin["id"])
            if alias in matched or component in used_ids:
                return None
            matched[alias] = (component, version)
            used_ids.add(component)
        return matched or None
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None


def legacy_mcp_candidates(
    rows: list[dict],
    snapshot: dict,
    *,
    project: str,
    uploader: uuid.UUID,
    session: str,
    now: datetime,
    modern_run_exists: bool,
) -> list[LegacyCallCandidate]:
    """No inference from arguments, bare aliases, mutable current owner, or central totals."""
    if (
        modern_run_exists
        or not rows
        or rows[0].get("line_offset") != 0
        or any(
            row.get("project_id") != project
            or row.get("user_id") != str(uploader)
            or row.get("session_id") != session
            or row.get("harness") != "pi"
            or row.get("is_source_record") != 1
            or row.get("parent_session_id")
            for row in rows
        )
    ):
        return []
    # Old rows missing the ingest-time SHA-256 cannot prove that the retained
    # raw bytes are the same source that the server originally accepted.
    if any(
        not isinstance(row.get("raw_line"), str)
        or row.get("source_sha256") != hashlib.sha256(row["raw_line"].encode("utf-8")).hexdigest()
        for row in rows
    ):
        return []
    revision = _revision(rows)
    expiry = _source_retained_until(rows, revision)
    if revision is None or expiry is None or expiry <= now:
        return []
    layer = rows[0].get("layer_hash")
    if (
        not isinstance(layer, str)
        or not _LEGACY_HASH.fullmatch(layer)
        or any(row.get("layer_hash") != layer for row in rows)
    ):
        return []  # A mixed upgraded source is owned by the new projector only.
    if (
        snapshot.get("hash") != layer
        or snapshot.get("project_id") != project
        or snapshot.get("user_id") != str(uploader)
    ):
        return []
    if "pi" not in str(snapshot.get("harness", "")).split(","):
        return []
    # ClickHouse's UTC DateTime64 JSON encoding normally omits the zone;
    # unlike the session header's client time this column itself is UTC-typed.
    uploaded_raw = snapshot.get("uploaded_at")
    if not isinstance(uploaded_raw, str):
        return []
    try:
        uploaded = datetime.fromisoformat(uploaded_raw.replace("Z", "+00:00"))
        uploaded = uploaded.replace(tzinfo=UTC) if uploaded.tzinfo is None else uploaded.astimezone(UTC)
    except ValueError:
        return []
    if not 1971 <= uploaded.year < 2100 or uploaded > now:
        return []
    try:
        header = json.loads(rows[0]["raw_line"])
    except (KeyError, ValueError, TypeError):
        return []
    if (
        not isinstance(header, dict)
        or header.get("type") != "session"
        or header.get("id") != session
        or header.get("parentSession")
    ):
        return []
    started = _source_time(header.get("timestamp"))
    if started is None or started > now + timedelta(minutes=5):
        return []
    pins = _pins(snapshot)
    if not pins:
        return []
    extracted = PiInvocationExtractor().extract(rows)
    if extracted.malformed_source_records:
        return []
    root_key = hashlib.sha256(
        f"legacy-pi\0{project}\0{uploader}\0{session}\0{hashlib.sha256(rows[0]['raw_line'].encode()).hexdigest()}".encode()
    ).hexdigest()
    candidates = []
    for call in extracted.invocations:
        when = call.event_time
        if (
            call.result_state not in ("success", "error")
            or when is None
            or not started <= when <= now + timedelta(minutes=5)
            or uploaded > when
        ):
            continue
        pin = pins.get(call.mcp_server)
        if pin is None:
            continue
        candidates.append(
            LegacyCallCandidate(
                project,
                uploader,
                layer,
                root_key,
                revision,
                call.source_line_offset,
                call.source_block_key,
                when,
                pin[0],
                pin[1],
                call.mcp_server,
                call.result_state,
            )
        )
    return candidates


async def qualify_legacy_mcp(db, calls: list[LegacyCallCandidate]) -> list[LegacyQualifiedCall]:
    """Recheck current public version for User; Author additionally needs recorded event-time provenance."""
    facts = []
    for call in calls:
        version = await db.scalar(
            text(
                "SELECT v.id FROM mcp_versions v JOIN mcp_listings l ON l.id=v.listing_id "
                "WHERE l.id=:listing AND v.version=:version AND l.is_private=false "
                "AND l.created_at<=:when AND v.created_at<=:when AND v.released_at<=:when "
                "AND v.status IN ('approved','archived') LIMIT 1"
            ),
            {"listing": call.component_id, "version": call.version, "when": call.event_time},
        )
        if not isinstance(version, uuid.UUID):
            continue
        # A client-authored pre-v2 pin cannot establish a named component
        # version even for the uploader. Public registry presence proves only
        # that a listing exists, not that this alias was bound to it. An
        # independent complete server-registered binding must predate the call.
        verified_binding = await db.scalar(
            text(
                "SELECT 1 FROM mobile_verified_layers vl JOIN mobile_layer_components pin "
                "ON pin.project_id=vl.project_id AND pin.user_id=vl.user_id "
                "AND pin.harness=vl.harness AND pin.layer_hash=vl.layer_hash "
                "WHERE vl.project_id=:project AND vl.user_id=:user AND vl.harness='pi' "
                "AND vl.layer_hash=:hash AND vl.uploaded_at<=:when AND pin.alias=:alias "
                "AND pin.component_id=:component AND pin.version_id=:version "
                "AND vl.expected_components=(SELECT count(*) FROM mobile_layer_components rest "
                "WHERE rest.project_id=vl.project_id AND rest.user_id=vl.user_id "
                "AND rest.harness=vl.harness AND rest.layer_hash=vl.layer_hash) LIMIT 1"
            ),
            {
                "project": call.project,
                "user": call.uploader,
                "hash": call.layer_hash,
                "alias": call.alias,
                "component": call.component_id,
                "version": version,
                "when": call.event_time,
            },
        )
        if not verified_binding:
            continue
        author = None
        if await _registry_at_event(db, "mcp", call.component_id, version, call.event_time):
            author = await db.scalar(
                text(
                    "SELECT p.original_author_id FROM mobile_listing_provenance p "
                    "WHERE p.kind='mcp' AND p.listing_id=:listing AND p.captured_at<=:when LIMIT 1"
                ),
                {"listing": call.component_id, "when": call.event_time},
            )
            if not isinstance(author, uuid.UUID):
                author = None
        facts.append(LegacyQualifiedCall(call, version, author))
    return facts
