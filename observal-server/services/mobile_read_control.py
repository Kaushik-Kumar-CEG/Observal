# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Mobile read/retention serialization. No cross-store atomicity is claimed.

Readers take a PostgreSQL transaction-scoped shared project lock before any
source-derived response and hold it until the FastAPI session closes. Retention
commits a deny barrier under the exclusive lock BEFORE issuing ClickHouse's
asynchronous delete. A read linearized earlier may finish afterward; already
sent bytes cannot be recalled. A missing control row is denied.
"""

from uuid import UUID

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


async def mobile_issue_allowed(db: AsyncSession) -> bool:
    """Serialize mobile token mint with audited operator revoke.

    A process-local or Redis setting may lag another API worker's revoke. Read
    the authoritative PostgreSQL value under the same transaction lock held by
    setup/revoke, and hold the shared lock through token issuance.
    """
    await db.execute(
        text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0))"),
        {"key": _lock_key(str(DEFAULT_PROJECT_ID))},
    )
    state = (
        await db.execute(
            text(
                "SELECT revocation_pending,synthetic_expires_at > clock_timestamp() AS synthetic_valid "
                "FROM mobile_read_controls WHERE project_id=:project"
            ),
            {"project": str(DEFAULT_PROJECT_ID)},
        )
    ).one_or_none()
    if state is None or state.revocation_pending:
        return False
    value = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='mobile.auth_enabled'"))
    synthetic = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='mobile.synthetic_test_enabled'"))
    return value == "true" and (synthetic != "true" or state.synthetic_valid is True)


def _disposable_email(value: str) -> bool:
    return "@" in value and value.rsplit("@", 1)[1].lower().endswith((".test", ".invalid"))


async def synthetic_principals_valid(db: AsyncSession, author_id: UUID, user_id: UUID) -> bool:
    """Lock both current identities through this read; SCIM edits cannot swap them mid-response."""
    if author_id == user_id:
        return False
    rows = (
        await db.execute(
            text("SELECT id,email,role,auth_provider FROM users WHERE id IN (:author,:actor) FOR SHARE"),
            {"author": author_id, "actor": user_id},
        )
    ).all()
    by_id = {row.id: row for row in rows}
    return (
        len(by_id) == 2
        and by_id[author_id].role == UserRole.super_admin.value
        and all(row.auth_provider != "deactivated" and _disposable_email(row.email) for row in by_id.values())
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
        try:
            author_id = UUID(await ds.get("mobile.synthetic_test_viewer_id"))
            user_id = UUID(await ds.get("mobile.synthetic_test_self_user_viewer_id"))
        except (ValueError, TypeError):
            return None
        if not await db.scalar(
            text("SELECT synthetic_expires_at > clock_timestamp() FROM mobile_read_controls WHERE project_id=:project"),
            {"project": str(DEFAULT_PROJECT_ID)},
        ):
            return None
        if viewer.id not in (author_id, user_id) or not await synthetic_principals_valid(db, author_id, user_id):
            return None
        if viewer.id == user_id:
            return "synthetic-user"
        if viewer.role == UserRole.super_admin:
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
