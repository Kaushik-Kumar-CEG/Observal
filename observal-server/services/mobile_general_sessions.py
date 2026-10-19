# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Source-revalidated prompted logical roots, independent of component calls.

A bounded positive-only lower bound. Unqualified sessions are excluded from
partial positives; if no roots qualify or the candidate page overflows the
reading is unknown, never a fabricated zero.
"""

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from jobs.mobile_evidence import _policy_source_complete, _revision, _rows, _source_retained_until
from models.user import User
from services.clickhouse.client import _query

_ACTIVITY = ("user_prompt", "assistant_text", "tool_call", "tool_result", "thinking")


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or not 1971 <= parsed.year < 2100:
        return None
    return parsed.astimezone(UTC)


async def prompted_roots(
    db: AsyncSession,
    project: str,
    start: datetime,
    end: datetime,
    *,
    subject: uuid.UUID | None = None,
) -> dict | None:
    """Count only proven prompted roots; None means no complete bounded cohort."""
    max_sessions = 20 if subject else 100
    configured = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='data.retention_days'"), {})
    try:
        retention_days = int(configured) if configured is not None else 90
    except (TypeError, ValueError):
        return None
    if not 0 <= retention_days <= 36500:
        return None
    policy = (
        await db.execute(
            text(
                "SELECT source_policy_epoch,source_policy_since FROM mobile_read_controls "
                "WHERE project_id=:project AND source_policy_ready"
            ),
            {"project": project},
        )
    ).one_or_none()
    if policy is None or policy.source_policy_since is None:
        return None
    params = {
        "param_project": project,
        "param_start": start.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        "param_end": end.strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
    }
    subject_filter = "AND user_id={user:String}" if subject else ""
    if subject:
        params["param_user"] = str(subject)
    # This candidate set includes sessions whose LAST event is outside the
    # window. A query by last_event_time would silently lose those roots.
    result = await _query(
        "SELECT DISTINCT user_id,session_id FROM session_events FINAL "
        "WHERE project_id={project:String} AND harness='pi' "
        "AND timestamp>={start:DateTime64(3)} AND timestamp<{end:DateTime64(3)} "
        "AND event_type IN ('user_prompt','assistant_text','tool_call','tool_result','thinking') "
        f"{subject_filter} ORDER BY user_id,session_id LIMIT {max_sessions + 1} "
        "SETTINGS max_execution_time=5 FORMAT JSON",
        params,
    )
    result.raise_for_status()
    candidates = result.json().get("data", [])
    if not candidates or len(candidates) > max_sessions:
        return None
    active = set()
    for record in candidates:
        try:
            active.add(uuid.UUID(record["user_id"]))
        except (TypeError, ValueError, KeyError):
            return None
    # Only accounts that still exist and are active may contribute to a
    # named reading or the platform-wide numerator/threshold.
    surviving = set(
        (await db.scalars(select(User.id).where(User.id.in_(active), User.auth_provider != "deactivated"))).all()
    )
    candidates = [row for row in candidates if uuid.UUID(row["user_id"]) in surviving]
    if not candidates:
        return None

    cache: dict[tuple[str, str], list[dict] | None] = {}
    verified_layers: dict[tuple[str, str], bool] = {}
    source_modes: dict[tuple[str, str], str] = {}
    source_bytes = 0

    async def source(user_id: str, session_id: str) -> list[dict] | None:
        nonlocal source_bytes
        key = (user_id, session_id)
        if key not in cache:
            if len(cache) >= (32 if subject else 128):
                return None
            records = await _rows(project, user_id, "pi", session_id)
            revision = _revision(records or [])
            identity = {"project": project, "user": uuid.UUID(user_id), "session": session_id}
            publication = (
                await db.execute(
                    text(
                        "SELECT source_revision,source_highest_line,status,source_policy_epoch "
                        "FROM mobile_session_publications WHERE project_id=:project AND user_id=:user "
                        "AND harness='pi' AND session_id=:session"
                    ),
                    identity,
                )
            ).one_or_none()
            highwater = await db.scalar(
                text(
                    "SELECT max_line FROM mobile_source_line_highwater WHERE project_id=:project "
                    "AND user_id=:user AND harness='pi' AND session_id=:session"
                ),
                identity,
            )
            final = (
                await db.execute(
                    text(
                        "SELECT final_line,source_hash FROM mobile_source_final_receipts "
                        "WHERE project_id=:project AND user_id=:user AND harness='pi' AND session_id=:session"
                    ),
                    identity,
                )
            ).one_or_none()
            if (
                revision is None
                or publication is None
                or publication.source_revision != revision
                or publication.status not in ("complete", "partial")
                or publication.source_policy_epoch != policy.source_policy_epoch
                or publication.source_highest_line is None
                or publication.source_highest_line != records[-1]["line_offset"]
                or not _policy_source_complete(
                    records,
                    revision,
                    publication.source_revision,
                    publication.source_highest_line,
                    highwater,
                    policy.source_policy_since,
                    final.final_line if final else None,
                    final.source_hash if final else None,
                )
            ):
                cache[key] = None
                return None
            digests = {row.get("layer_hash") for row in records}
            legacy = bool(digests) and all(
                isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{16}", digest) for digest in digests
            )
            until = _source_retained_until(records, revision, retention_days=retention_days)
            if until is None or until <= datetime.now(UTC):
                cache[key] = None
                return None
            if legacy:
                # Old pre-pin uploads may support *only* the uploader's own
                # observed general prompted roots. No component or Author
                # identity is inferred, and a mixed old/new source is denied.
                source_modes[key] = "legacy"
            else:
                for digest in digests:
                    layer_key = (user_id, digest)
                    if layer_key not in verified_layers:
                        verified_layers[layer_key] = bool(
                            isinstance(digest, str)
                            and digest.startswith(("v2_", "v3_"))
                            and await db.scalar(
                                text(
                                    "SELECT 1 FROM mobile_verified_layers WHERE project_id=:project "
                                    "AND user_id=:user AND harness='pi' AND layer_hash=:hash"
                                ),
                                {"project": project, "user": uuid.UUID(user_id), "hash": digest},
                            )
                        )
                    if not verified_layers[layer_key]:
                        cache[key] = None
                        return None
                source_modes[key] = "verified"
            size = sum(len(row["raw_line"].encode("utf-8")) for row in records)
            if source_bytes + size > 8 * 1024 * 1024:
                cache[key] = None
                return None
            source_bytes += size
            cache[key] = records
        return cache[key]

    roots: set[tuple[str, str]] = set()
    qualified: set[tuple[str, str]] = set()
    for candidate in candidates:
        user_id, session_id = candidate["user_id"], candidate["session_id"]
        child = await source(user_id, session_id)
        if not child:
            continue
        # Verify a real in-window event from the original JSONL timestamp;
        # the CH timestamp alone can be inherited from an adjacent line.
        in_window = False
        invalid_time = False
        for row in child:
            try:
                raw = json.loads(row["raw_line"])
            except (ValueError, TypeError):
                invalid_time = True
                break
            if not isinstance(raw, dict):
                invalid_time = True
                break
            if row["event_type"] in _ACTIVITY:
                when = _time(raw.get("timestamp"))
                if when is None:
                    invalid_time = True
                    break
                if start <= when < end:
                    in_window = True
        if invalid_time or not in_window:
            continue
        current = session_id
        visited = set()
        last_start: datetime | None = None
        for _ in range(8):
            if current in visited:
                break
            visited.add(current)
            lines = await source(user_id, current)
            if not lines:
                break
            try:
                header = json.loads(lines[0]["raw_line"])
            except (KeyError, ValueError, TypeError):
                break
            if not isinstance(header, dict) or header.get("type") != "session" or header.get("id") != current:
                break
            began = _time(header.get("timestamp"))
            if began is None or (last_start is not None and began > last_start):
                break
            last_start = began
            parents = {row.get("parent_session_id") for row in lines if row.get("parent_session_id")}
            if len(parents) > 1 or (parents and any(row.get("parent_session_id") not in parents for row in lines)):
                break
            if not parents:
                legacy_root = source_modes.get((user_id, current)) == "legacy"
                if legacy_root:
                    # No prospective runtime nonce exists on old source. Its
                    # complete, parent-free header is a *lower-bound observed*
                    # general root only when no new run identity already owns
                    # the session. The caller still applies self-User or the
                    # platform minimum-cell gate.
                    if header.get("parentSession") or any(row.get("parent_session_id") for row in lines):
                        break
                    existing_run = await db.scalar(
                        text(
                            "SELECT 1 FROM mobile_run_instances WHERE project_id=:project AND user_id=:user "
                            "AND harness='pi' AND session_id=:session LIMIT 1"
                        ),
                        {"project": project, "user": uuid.UUID(user_id), "session": current},
                    )
                    if existing_run:
                        break
                witnessed = legacy_root or await db.scalar(
                    text(
                        "SELECT 1 FROM mobile_run_instances WHERE project_id=:project AND user_id=:user "
                        "AND harness='pi' AND session_id=:session AND root_verified=true "
                        "AND source_status IN ('complete','partial') "
                        "AND origin_witness='pi_session_start_root_v1' AND parent_session_id IS NULL "
                        "AND header_hash=:hash LIMIT 1"
                    ),
                    {
                        "project": project,
                        "user": uuid.UUID(user_id),
                        "session": current,
                        "hash": hashlib.sha256(lines[0]["raw_line"].encode()).hexdigest(),
                    },
                )
                if not witnessed:
                    break
                for row in lines:
                    if row["event_type"] != "user_prompt":
                        continue
                    try:
                        parsed = json.loads(row["raw_line"])
                    except (ValueError, TypeError):
                        break
                    if not isinstance(parsed, dict):
                        break
                    message = parsed.get("message")
                    if (
                        isinstance(message, dict)
                        and message.get("role") == "user"
                        and message.get("content")
                        and (prompt_time := _time(parsed.get("timestamp")))
                        and prompt_time >= began
                        and prompt_time
                        <= min(
                            (
                                _time(json.loads(row["raw_line"]).get("timestamp"))
                                for row in child
                                if row["event_type"] in _ACTIVITY
                            ),
                            default=prompt_time,
                        )
                    ):
                        roots.add((user_id, current))
                        qualified.add((user_id, session_id))
                        break
                # A full source with no validated prompt does not contribute
                # a root; partial failures never erase other proven roots.
                break
            # Parent IDs by themselves are not proof. Use the immutable,
            # uploader-bound nonce and header digest admitted at source upload.
            # Recheck the original ancestor bytes before counting any child.
            if not header.get("parentSession"):
                break
            parent_id = next(iter(parents))
            link = (
                await db.execute(
                    text(
                        "SELECT child.parent_run_incarnation,child.parent_header_hash "
                        "FROM mobile_run_instances child WHERE child.project_id=:project AND child.user_id=:user "
                        "AND child.harness='pi' AND child.session_id=:session "
                        "AND child.header_hash=:hash AND child.parent_session_id=:parent "
                        "AND child.root_verified=true AND child.source_status IN ('complete','partial')"
                    ),
                    {
                        "project": project,
                        "user": uuid.UUID(user_id),
                        "session": current,
                        "hash": hashlib.sha256(lines[0]["raw_line"].encode()).hexdigest(),
                        "parent": parent_id,
                    },
                )
            ).first()
            if link is None or parent_id in visited:
                break
            parent_lines = await source(user_id, parent_id)
            if (
                not parent_lines
                or hashlib.sha256(parent_lines[0]["raw_line"].encode()).hexdigest() != link.parent_header_hash
            ):
                break
            parent_run = await db.scalar(
                text(
                    "SELECT 1 FROM mobile_run_instances WHERE project_id=:project AND user_id=:user "
                    "AND harness='pi' AND session_id=:parent AND run_incarnation=:nonce "
                    "AND header_hash=:hash AND root_verified=true "
                    "AND source_status IN ('complete','partial')"
                ),
                {
                    "project": project,
                    "user": uuid.UUID(user_id),
                    "parent": parent_id,
                    "nonce": link.parent_run_incarnation,
                    "hash": link.parent_header_hash,
                },
            )
            if not parent_run:
                break
            current = parent_id
    if not roots:
        return None
    # A source may cross its UTC-midnight whole-row cutoff while we traverse
    # at most 32/128 bounded sessions. Never return an earlier positive after
    # its supporting raw bytes become eligible for deletion mid-request.
    now = datetime.now(UTC)
    for source_rows in cache.values():
        if source_rows and (
            (floor := _source_retained_until(source_rows, _revision(source_rows), retention_days=retention_days))
            is None
            or floor <= now
        ):
            return None
    return {
        "active_accounts": len({user for user, _ in roots}),
        "roots": len(roots),
        "eligible_sessions": len(qualified),
    }
