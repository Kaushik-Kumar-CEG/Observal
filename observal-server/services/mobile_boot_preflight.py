# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Redacted read-only mobile PostgreSQL prerequisite and qualification diagnostic.

Run inside the installed API image with its configured DATABASE_URL:
    /app/.venv/bin/python -m services.mobile_boot_preflight
Never log a DSN, a user row, an individual scope, token, or trace source.
"""

import asyncio
import json
import sys
from dataclasses import asdict, dataclass

from sqlalchemy import text

from database import engine

MOBILE_SCHEMA_HEAD = "070_mobile_follow_sync_state"


@dataclass(frozen=True)
class MobilePreflight:
    status: str
    pg_commit_clock: str
    pg_restart_pending: bool
    schema_head: str
    follow_erasure_trigger_ready: bool
    auth_enabled: bool
    barrier_closed: bool
    source_policy_ready: bool
    production_qualified: bool


async def inspect_mobile_postgres() -> MobilePreflight:
    """Fail closed if the DB is unreachable; do not change a PostgreSQL setting."""
    async with engine.connect() as conn:
        setting = (
            await conn.execute(
                text("SELECT setting,pending_restart FROM pg_settings WHERE name=:name"),
                {"name": "track_commit_timestamp"},
            )
        ).one_or_none()
        clock = setting.setting if setting else "unavailable"
        pending = bool(setting.pending_restart) if setting else False
        has_migrations = await conn.scalar(text("SELECT to_regclass('alembic_version') IS NOT NULL"))
        head = (
            (await conn.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))) or "unversioned"
            if has_migrations
            else "missing"
        )
        if head != MOBILE_SCHEMA_HEAD:
            return MobilePreflight("OLD_OR_INCOMPATIBLE_SCHEMA", clock, pending, head, False, False, True, False, False)
        # create_all() does not install 070's subject-deletion privacy trigger.
        # A stamped or partly restored DB must never pass an image's boot gate.
        trigger_ready = bool(
            await conn.scalar(
                text("""SELECT EXISTS (
                    SELECT 1 FROM pg_trigger t
                    WHERE t.tgrelid = to_regclass('users')
                      AND t.tgname = 'mobile_follow_erase_subject'
                      AND t.tgenabled = 'O' AND NOT t.tgisinternal
                      AND t.tgfoid = to_regprocedure('mobile_follow_erase_subject()')
                )""")
            )
        )
        if not trigger_ready:
            return MobilePreflight(
                "MISSING_FOLLOW_ERASURE_TRIGGER", clock, pending, head, False, False, True, False, False
            )
        settings = dict(
            (
                await conn.execute(
                    text(
                        "SELECT key,value FROM enterprise_config WHERE key IN "
                        "('mobile.auth_enabled','trace_headlines','mobile.trace_qualification_ack',"
                        "'mobile.trace_qualification_server_id')"
                    )
                )
            ).all()
        )
        auth = settings.get("mobile.auth_enabled") == "true"
        if clock != "on" or pending:
            return MobilePreflight("MISSING_DB_PREREQUISITE", clock, pending, head, True, auth, True, False, False)
        state = (
            await conn.execute(
                text("SELECT blocked,source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
            )
        ).one_or_none()
        closed = state is None or bool(state.blocked)
        source_ready = state is not None and bool(state.source_policy_ready)
        # The active cohort still checks the actual server UUID and viewer on
        # every route. This diagnostic is never proof that any viewer may read.
        qualified = (
            settings.get("trace_headlines") == "true"
            and settings.get("mobile.trace_qualification_ack") == "owner-approved-v3-all-kinds-v1"
            and bool(settings.get("mobile.trace_qualification_server_id"))
        )
        if not auth:
            status = "MOBILE_NOT_CONFIGURED"
        elif closed:
            status = "PRIVACY_CLOSED"
        elif not source_ready or not qualified:
            status = "EVIDENCE_UNQUALIFIED"
        else:
            status = "PREFLIGHT_ONLY"
        return MobilePreflight(status, clock, pending, head, True, auth, closed, source_ready, qualified)


async def main(*, require_schema: bool = False) -> int:
    try:
        result = await inspect_mobile_postgres()
    except Exception:
        # Omit exception details; connection errors can include URL credentials.
        print(json.dumps({"status": "OFFLINE", "detail": "PostgreSQL unavailable; no mobile reads authorized"}))
        return 2
    finally:
        await engine.dispose()
    print(json.dumps(asdict(result), sort_keys=True))
    if require_schema:
        # A retained Helm Job alone is not proof after a volume restore. Every
        # API/worker pod rechecks its DB against its own image before starting.
        return (
            0
            if result.schema_head == MOBILE_SCHEMA_HEAD
            and result.follow_erasure_trigger_ready
            and (not result.auth_enabled or (result.pg_commit_clock == "on" and not result.pg_restart_pending))
            else 2
        )
    return 0 if result.status == "PREFLIGHT_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(require_schema=sys.argv[1:] == ["--require-schema"])))
