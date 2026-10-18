# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in fresh Docker-style Alembic bootstrap in a UNIQUE disposable PostgreSQL DB.

Never run against a shared or production PostgreSQL host. Scratch DB is
created on the loopback-only mobile probe cluster and dropped even on failure.
"""

import os
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable PostgreSQL only")


@pytest.mark.asyncio(loop_scope="session")
async def test_fresh_upstream_usage_then_mobile_migrations_apply_in_order():
    from models import Base

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) in {
        ("127.0.0.1", 15438, "observal"),
        ("127.0.0.1", 15440, "observal"),
    }
    name = "mobile_migration_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + name))
            created = True
        scratch_url = base.set(database=name)
        schema = create_async_engine(scratch_url)
        try:
            async with schema.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                await conn.run_sync(Base.metadata.create_all)
        finally:
            await schema.dispose()
        env = os.environ.copy()
        env["DATABASE_URL"] = scratch_url.render_as_string(hide_password=False)
        # The v1 baseline is intentionally empty. Match docker/entrypoint.sh;
        # stamping is permitted ONLY on this just-created scratch DB.
        subprocess.run(
            [sys.executable, "-m", "alembic", "stamp", "044_review_orphan_authors"],
            env=env,
            check=True,
            capture_output=True,
            timeout=45,
        )
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=env,
            check=True,
            capture_output=True,
            timeout=105,
        )
        verify = create_async_engine(scratch_url)
        try:
            async with verify.connect() as conn:
                assert (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one() == (
                    "062_mobile_operator_audit"
                )
                assert (
                    await conn.execute(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'"))
                ).scalar_one() is True
                assert (await conn.execute(text("SELECT count(*) FROM mobile_operator_audit"))).scalar_one() == 0
                assert (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM information_schema.columns WHERE table_name='mobile_session_publications' "
                            "AND column_name='source_retained_until'"
                        )
                    )
                ).scalar_one() == 1
                assert (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM enterprise_config WHERE key IN ('usage_ping.enabled', 'usage_ping.frequency')"
                        )
                    )
                ).scalar_one() == 0
        finally:
            await verify.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
