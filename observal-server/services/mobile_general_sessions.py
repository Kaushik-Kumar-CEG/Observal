# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Source-revalidated prompted logical roots, independent of component calls.

A bounded positive-only lower bound. Unqualified sessions are excluded from
partial positives; if no roots qualify or the candidate page overflows the
reading is unknown, never a fabricated zero.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from jobs.mobile_evidence import _revision, _rows
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
    source_bytes = 0

    async def source(user_id: str, session_id: str) -> list[dict] | None:
        nonlocal source_bytes
        key = (user_id, session_id)
        if key not in cache:
            if len(cache) >= (32 if subject else 128):
                return None
            records = await _rows(project, user_id, "pi", session_id)
            if _revision(records or []) is None:
                cache[key] = None
                return None
            # A valid source alone does not establish an upgraded, uploader-
            # bound sender. Legacy/unregistered hashes must not manufacture
            # phone or platform root counts.
            for digest in {row.get("layer_hash") for row in records}:
                layer_key = (user_id, digest)
                if layer_key not in verified_layers:
                    verified_layers[layer_key] = bool(
                        isinstance(digest, str)
                        and digest.startswith("v2_")
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
        for _ in range(8):
            if current in visited:
                break
            visited.add(current)
            lines = await source(user_id, current)
            if not lines:
                break
            parents = {row.get("parent_session_id") for row in lines if row.get("parent_session_id")}
            if len(parents) > 1:
                break
            if not parents:
                try:
                    header = json.loads(lines[0]["raw_line"])
                except (KeyError, ValueError, TypeError):
                    break
                if not isinstance(header, dict) or header.get("type") != "session" or header.get("id") != current:
                    break
                witnessed = await db.scalar(
                    text(
                        "SELECT 1 FROM mobile_run_instances WHERE project_id=:project AND user_id=:user "
                        "AND harness='pi' AND session_id=:session AND root_verified=true "
                        "AND source_status IN ('complete','partial') AND header_hash=:hash LIMIT 1"
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
                        and _time(parsed.get("timestamp"))
                    ):
                        roots.add((user_id, current))
                        qualified.add((user_id, session_id))
                        break
                # A full source with no validated prompt does not contribute
                # a root; partial failures never erase other proven roots.
                break
            # Bare parent IDs are not incarnation-scoped linkage. A child
            # cannot qualify until both run nonces and launcher association
            # are independently bound; never use this legacy chain for counts.
            break
    if not roots:
        return None
    return {
        "active_accounts": len({user for user, _ in roots}),
        "roots": len(roots),
        "eligible_sessions": len(qualified),
    }
