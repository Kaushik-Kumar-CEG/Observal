# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in PG 18: publication transition cannot precede its approval statement."""

import asyncio
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from models import Base
from services.mobile_publication_clock import committed_at

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable loopback PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_approval_records_statement_clock_and_preupgrade_history_is_quarantined():
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    database = "mobile_publication_clock_" + uuid.uuid4().hex[:10]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    engine = None
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + database))
            created = True
        target = base.set(database=database)
        engine = create_async_engine(target)
        env = os.environ.copy()
        env["DATABASE_URL"] = target.render_as_string(hide_password=False)
        # The existing integration suite bootstraps the pre-mobile schema
        # before the additive 045.. head chain; reproduce that same fixture.
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.run_sync(Base.metadata.create_all)
        for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "068_mobile_erasure_epoch_guard")):
            subprocess.run(
                [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=120
            )
        # Preserve the independent 068 no-downgrade guarantee even though
        # the later 069 guard blocks downgrades before reaching 068.
        refusal_068 = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "067_mobile_short_retention_fence"],
            env=env,
            capture_output=True,
            timeout=80,
        )
        assert refusal_068.returncode != 0
        assert b"Cannot restore unsafe pre-068 mobile erasure triggers" in refusal_068.stderr
        old = datetime(2020, 1, 1, tzinfo=UTC)
        async with engine.begin() as conn:
            old_id = await conn.scalar(
                text(
                    "INSERT INTO mobile_publication_events(kind,listing_id,version_id,status,recorded_at) "
                    "VALUES ('mcp',:listing,:version,'approved',:old) RETURNING id"
                ),
                {"listing": uuid.uuid4(), "version": uuid.uuid4(), "old": old},
            )
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"], env=env, capture_output=True, timeout=120
        )
        assert result.returncode == 0, result.stderr.decode()[-2500:]
        async with engine.begin() as conn:
            quarantined = await conn.scalar(
                text("SELECT recorded_at FROM mobile_publication_events WHERE id=:id"), {"id": old_id}
            )
            assert quarantined > old, "pre-fix approvals cannot retroactively qualify old event times"
            # Transaction start and approval statement are deliberately apart.
            await conn.execute(text("SELECT pg_sleep(0.08)"))
            before_insert = await conn.scalar(text("SELECT clock_timestamp()"))
            recorded = await conn.scalar(
                text(
                    "INSERT INTO mobile_publication_events(kind,listing_id,version_id,status) "
                    "VALUES ('mcp',:listing,:version,'approved') RETURNING recorded_at"
                ),
                {"listing": uuid.uuid4(), "version": uuid.uuid4()},
            )
            assert recorded >= before_insert, "a late approval must not predate activity within its transaction"
        # The statement clock still precedes commit. Only the committed row
        # transaction timestamp can prove approval preceded a separate event.
        assert os.getenv("MOBILE_COMMIT_CLOCK_SCRATCH") == "1"
        async with engine.connect() as check:
            assert await check.scalar(text("SELECT current_setting('track_commit_timestamp')")) == "on"
        review_written = asyncio.Event()
        may_commit = asyncio.Event()
        listed = uuid.uuid4()
        version = uuid.uuid4()

        async def delayed_review():
            async with engine.begin() as tx:
                await tx.execute(
                    text(
                        "INSERT INTO mobile_publication_events(kind,listing_id,version_id,status) "
                        "VALUES ('mcp',:listing,:version,'approved')"
                    ),
                    {"listing": listed, "version": version},
                )
                review_written.set()
                await asyncio.wait_for(may_commit.wait(), 5)

        task = asyncio.create_task(delayed_review())
        try:
            await asyncio.wait_for(review_written.wait(), 5)
            await asyncio.sleep(0.04)
            async with engine.connect() as observer:
                between_statement_and_commit = await observer.scalar(text("SELECT clock_timestamp()"))
            may_commit.set()
            await task
            async with engine.connect() as observer:
                row = (
                    await observer.execute(
                        text(
                            "SELECT pe.recorded_at, " + committed_at("pe") + " AS committed "
                            "FROM mobile_publication_events pe WHERE pe.listing_id=:listing"
                        ),
                        {"listing": listed},
                    )
                ).one()
                assert row.recorded_at < between_statement_and_commit < row.committed
                assert not (row.committed <= between_statement_and_commit)
        finally:
            may_commit.set()
            if not task.done():
                await task
    finally:
        if engine is not None:
            await engine.dispose()
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE IF EXISTS " + database + " WITH (FORCE)"))
        await admin.dispose()
