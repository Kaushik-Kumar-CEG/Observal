# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Mobile read/retention serialization. No cross-store atomicity is claimed.

Readers take a PostgreSQL transaction-scoped shared project lock before any
source-derived response and hold it until the FastAPI session closes. Retention
commits a deny barrier under the exclusive lock BEFORE issuing ClickHouse's
asynchronous delete. A read linearized earlier may finish afterward; already
sent bytes cannot be recalled. A missing control row is denied.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services import dynamic_settings as ds


class MobileCohortDeniedError(Exception):
    """No named phone data without an explicitly authorized cohort."""


def _lock_key(project: str) -> str:
    return "mobile-read:" + project


async def readable(db: AsyncSession, project: str) -> bool:
    await db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0))"), {"key": _lock_key(project)}
    )
    return bool(
        await db.scalar(
            text("SELECT NOT blocked FROM mobile_read_controls WHERE project_id=:project"), {"project": project}
        )
    )


async def active_mobile_cohort(db: AsyncSession, viewer: User, *, server_id: str | None = None) -> str | None:
    """Authorize this viewer on the barrier-bound server, not merely a valid phone token.

    The synthetic allowlist and owner-qualified all-kind production release are
    mutually exclusive. A capability response is not an authorization boundary:
    every named data route must call this before reading any subject.
    """
    if not await ds.get_bool("mobile.auth_enabled") or not await readable(db, str(DEFAULT_PROJECT_ID)):
        return None
    if server_id is None:
        row = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
        if row is None:
            return None
        server_id = str(row)
    if await ds.get_bool("trace_headlines"):
        if (
            await ds.get("mobile.trace_qualification_server_id") == server_id
            and await ds.get("mobile.trace_qualification_ack") == "owner-approved-v3-all-kinds-v1"
        ):
            return "live"
        # Never fall back to a forgotten synthetic allowlist when an unqualified
        # production switch is requested on a different server.
        return None
    if await ds.get("mobile.trace_qualification_server_id") or await ds.get("mobile.trace_qualification_ack"):
        # A production rollback must not silently reactivate old test principals.
        return None
    if (
        await ds.get_bool("mobile.synthetic_test_enabled")
        and await ds.get("mobile.synthetic_test_server_id") == server_id
        and await ds.get("mobile.synthetic_test_ack") == "isolated-disposable-synthetic-only-v1"
    ):
        if await ds.get("mobile.synthetic_test_self_user_viewer_id") == str(viewer.id):
            return "synthetic-user"
        if await ds.get("mobile.synthetic_test_viewer_id") == str(viewer.id) and (
            viewer.role == UserRole.super_admin
            or (viewer.role == UserRole.admin and not await ds.get_bool("security.trace_privacy"))
        ):
            return "synthetic-author"
    return None


async def deny_before_purge(project: str) -> None:
    async with async_session() as db:
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": _lock_key(project)})
        await db.execute(
            text(
                "INSERT INTO mobile_read_controls(project_id,blocked,generation) VALUES (:project,true,1) "
                "ON CONFLICT (project_id) DO UPDATE SET blocked=true,generation=mobile_read_controls.generation+1,"
                "updated_at=now()"
            ),
            {"project": project},
        )
        await db.commit()
