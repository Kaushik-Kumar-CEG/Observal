# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in isolated PostgreSQL proof that local first-admin and init cannot race."""

import asyncio
import os
import subprocess
import sys
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable loopback PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_first_super_admin_receipt_and_competing_init_on_fresh_063():
    from api.routes.auth import init_admin
    from models import Base
    from models.user import User
    from schemas.auth import InitRequest
    from services.first_admin import lock_first_user, provision_first_super_admin

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    name = "first_admin_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + name))
            created = True
        engine = create_async_engine(base.set(database=name))
        try:
            async with engine.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                await conn.run_sync(Base.metadata.create_all)
            env = os.environ.copy()
            env["DATABASE_URL"] = base.set(database=name).render_as_string(hide_password=False)
            for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "head")):
                subprocess.run(
                    [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=120
                )
            sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
            async with sessionmaker() as first, sessionmaker() as competing, sessionmaker() as writer:
                await lock_first_user(first)
                request = Request({"type": "http", "client": ("127.0.0.1", 39422), "headers": []})
                rival = asyncio.create_task(
                    init_admin(request, InitRequest(email="rival@example.com", name="Rival"), competing)
                )
                writer.add(User(username="outside_lock", email="outside@example.com", name="Other writer"))
                uncoordinated = asyncio.create_task(writer.commit())
                await asyncio.sleep(0.05)
                assert not rival.done(), "Other first-user writer must wait for the shared PostgreSQL lock"
                assert not uncoordinated.done(), "Table lock must hold back a writer not using the advisory lock"
                identifier = await provision_first_super_admin(first, "author@candidate.test", "Valid1!Password")
                with pytest.raises(HTTPException) as denied:
                    await asyncio.wait_for(rival, timeout=4)
                assert denied.value.status_code == 400
                rows = (
                    await first.execute(text("SELECT id,role,is_demo FROM users WHERE email='author@candidate.test'"))
                ).all()
                assert len(rows) == 1 and rows[0].id == identifier and rows[0].role == "super_admin"
                assert rows[0].is_demo is False
                assert (
                    await first.scalar(
                        text("SELECT count(*) FROM first_admin_provision_audit WHERE actor_id=:id"), {"id": identifier}
                    )
                    == 1
                )
                await first.rollback()
                await asyncio.wait_for(uncoordinated, timeout=4)
            rollback = subprocess.run(
                [sys.executable, "-m", "alembic", "downgrade", "062_mobile_operator_audit"],
                env=env,
                capture_output=True,
                timeout=45,
            )
            assert rollback.returncode != 0, "Live first-admin receipt must prevent destructive schema downgrade"
            async with sessionmaker() as check:
                assert await check.scalar(text("SELECT version_num FROM alembic_version")) == (
                    "063_first_admin_provision_audit"
                )
                assert await check.scalar(text("SELECT count(*) FROM first_admin_provision_audit")) == 1
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
