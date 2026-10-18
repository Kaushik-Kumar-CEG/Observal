# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in 060→061 disposable PostgreSQL upgrade leaves old facts fail-closed."""

import os
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable loopback PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_existing_publication_gets_null_retained_floor_on_upgrade():
    from models import Base

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.database) == ("127.0.0.1", "observal")
    assert 15000 <= base.port < 16000 and base.port == int(os.environ["MOBILE_MIGRATION_SCRATCH_PORT"])
    name = "mobile_061_upgrade_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    try:
        async with admin.connect() as conn:
            assert (
                await conn.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'")) is True
            )
            assert await conn.scalar(text("SELECT count(*) FROM users WHERE email NOT LIKE '%@demo.example'")) == 0
            await conn.execute(text("CREATE DATABASE " + name))
            created = True
        target = base.set(database=name)
        schema = create_async_engine(target)
        try:
            async with schema.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                await conn.run_sync(Base.metadata.create_all)
        finally:
            await schema.dispose()
        env = os.environ.copy()
        env["DATABASE_URL"] = target.render_as_string(hide_password=False)
        for arguments in (
            ("stamp", "044_review_orphan_authors"),
            ("upgrade", "060_mobile_pi_hook_facts"),
        ):
            subprocess.run(
                [sys.executable, "-m", "alembic", *arguments], env=env, check=True, capture_output=True, timeout=110
            )
        target_db = create_async_engine(target)
        try:
            async with target_db.begin() as db:
                actor = uuid.uuid4()
                await db.execute(
                    text(
                        "INSERT INTO users(id,email,username,name,role,created_at) "
                        "VALUES (:id,:email,:username,'Synthetic', 'user'::userrole,now())"
                    ),
                    {
                        "id": actor,
                        "email": "upgrade-" + actor.hex + "@example.invalid",
                        "username": "upgrade_" + actor.hex[:12],
                    },
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,"
                        "source_revision,status) VALUES ('default',:id,'pi','synthetic-no-source',:revision,'complete')"
                    ),
                    {"id": actor, "revision": "a" * 64},
                )
        finally:
            await target_db.dispose()
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"], env=env, check=True, capture_output=True, timeout=90
        )
        verify = create_async_engine(target)
        try:
            async with verify.connect() as db:
                assert (
                    await db.scalar(text("SELECT version_num FROM alembic_version"))
                    == "063_first_admin_provision_audit"
                )
                assert await db.scalar(text("SELECT count(*) FROM first_admin_provision_audit")) == 0
                assert (
                    await db.scalar(
                        text(
                            "SELECT source_retained_until FROM mobile_session_publications "
                            "WHERE session_id='synthetic-no-source'"
                        )
                    )
                    is None
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT count(*) FROM mobile_session_publications "
                            "WHERE session_id='synthetic-no-source' "
                            "AND source_retained_until>now()"
                        )
                    )
                    == 0
                )
                assert (
                    await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'")) is True
                )
        finally:
            await verify.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
