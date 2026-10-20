# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Real 068 erasure: deleting a fully published Pi actor and author cannot recreate FK epochs."""

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
async def test_both_published_pi_actor_and_original_author_can_be_erased_after_closed_gate():
    from models import Base

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    name = "mobile_erasure_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + name))
            created = True
        target = base.set(database=name)
        engine = create_async_engine(target)
        try:
            async with engine.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                await conn.run_sync(Base.metadata.create_all)
            env = os.environ.copy()
            env["DATABASE_URL"] = target.render_as_string(hide_password=False)
            for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "head")):
                subprocess.run(
                    [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=105
                )
            actor, author = uuid.uuid4(), uuid.uuid4()
            async with engine.begin() as conn:
                for ident, role in ((actor, "user"), (author, "admin")):
                    await conn.execute(
                        text(
                            "INSERT INTO users(id,email,username,name,role,created_at) "
                            "VALUES (:id,:email,:name,'Disposable',CAST(:role AS userrole),now())"
                        ),
                        {
                            "id": ident,
                            "email": f"{ident}@example.invalid",
                            "name": "erase_" + ident.hex[:12],
                            "role": role,
                        },
                    )
                await conn.execute(
                    text(
                        "INSERT INTO mobile_author_actor_links(project_id,author_id,actor_id) "
                        "VALUES ('default',:author,:actor)"
                    ),
                    {"author": author, "actor": actor},
                )
                await conn.execute(
                    text(
                        "INSERT INTO mobile_session_publications "
                        "(project_id,user_id,harness,session_id,source_revision,status) "
                        "VALUES ('default',:actor,'pi','erasure-session',:revision,'complete')"
                    ),
                    {"actor": actor, "revision": "a" * 64},
                )
                for table, columns, values in (
                    ("mobile_source_line_highwater", "max_line", "4"),
                    ("mobile_source_final_receipts", "final_line,source_hash", "4,'" + "a" * 64 + "'"),
                ):
                    await conn.execute(
                        text(
                            f"INSERT INTO {table}(project_id,user_id,harness,session_id,{columns}) "
                            f"VALUES ('default',:actor,'pi','erasure-session',{values})"
                        ),
                        {"actor": actor},
                    )
                await conn.execute(
                    text(
                        "UPDATE mobile_backfill_cursor SET project_id='default',user_id=:actor,"
                        "session_id='erasure-session',skip_count=50 WHERE singleton=true"
                    ),
                    {"actor": str(actor)},
                )
                assert await conn.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'"))
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM users WHERE id IN (:actor,:author)"), {"actor": actor, "author": author}
                )
                assert (
                    await conn.scalar(
                        text("SELECT count(*) FROM users WHERE id IN (:actor,:author)"),
                        {"actor": actor, "author": author},
                    )
                    == 0
                )
                assert (
                    await conn.scalar(
                        text("SELECT count(*) FROM mobile_session_publications WHERE user_id=:actor"), {"actor": actor}
                    )
                    == 0
                )
                for table in ("mobile_source_line_highwater", "mobile_source_final_receipts"):
                    assert (
                        await conn.scalar(text(f"SELECT count(*) FROM {table} WHERE user_id=:actor"), {"actor": actor})
                        == 0
                    )
                cursor = (
                    await conn.execute(
                        text("SELECT user_id,session_id,skip_count FROM mobile_backfill_cursor WHERE singleton=true")
                    )
                ).one()
                assert tuple(cursor) == ("", "", 0)
            async with engine.begin() as conn:
                assert (
                    await conn.scalar(
                        text("SELECT count(*) FROM mobile_scope_epochs WHERE subject_id IN (:actor,:author)"),
                        {"actor": actor, "author": author},
                    )
                    == 0
                )
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
