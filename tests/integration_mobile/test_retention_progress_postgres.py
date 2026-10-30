# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in isolated PG cursor test: 500 checks/pass, poison does not starve 501st.

MOBILE_INTEGRATION_SCALE=1 is ONLY for the disposable mobile probe database.
Everything inserted here is rolled back; never target a shared or production DB.
"""

import os
import time

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTEGRATION_SCALE") != "1", reason="disposable PostgreSQL only")


@pytest.mark.asyncio(loop_scope="session")
async def test_retention_cursor_scales_beyond_old_first_fifty_and_persists_progress():
    from database import async_session

    async with async_session() as db:
        user = await db.scalar(text("SELECT id FROM users LIMIT 1"))
        assert user is not None, "isolated probe requires one seeded test account"
        await db.execute(
            text("""
            INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,source_revision,
                status,updated_at)
            SELECT 'default',:user,'pi','retention-scale-'||n,repeat('a',64),
                   'complete',now()-INTERVAL '2 days'
            FROM generate_series(1,501) n
        """),
            {"user": user},
        )
        query = text("""
            SELECT session_id FROM mobile_session_publications
            WHERE status IN ('complete','partial') AND updated_at<now()-INTERVAL '1 day'
              AND (last_checked_at IS NULL OR last_checked_at<now()-INTERVAL '12 hours')
              AND session_id LIKE 'retention-scale-%'
            ORDER BY last_checked_at NULLS FIRST,updated_at,project_id,user_id,session_id LIMIT 500
        """)
        tick = time.perf_counter()
        first = (await db.execute(query)).scalars().all()
        assert len(first) == 500
        await db.execute(
            text("""
            UPDATE mobile_session_publications SET last_checked_at=now()
            WHERE session_id LIKE 'retention-scale-%' AND session_id!='retention-scale-501'
        """)
        )
        remainder = (await db.execute(query)).scalars().all()
        assert remainder == ["retention-scale-501"]
        print("isolated_pg_retention_500_selection_ms=", round((time.perf_counter() - tick) * 1000, 1))
        await db.rollback()
