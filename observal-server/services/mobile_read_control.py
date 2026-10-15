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
