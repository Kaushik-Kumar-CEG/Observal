# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in isolated PostgreSQL proof of atomic mobile operator setup/open/deny."""

import os
import subprocess
import sys
import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable loopback PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_operator_lifecycle_is_atomically_audited_and_deny_first(monkeypatch):
    from api.routes.admin import mobile_setup as ops
    from models import Base
    from models.user import User, UserRole
    from services.mobile_read_control import mobile_issue_allowed

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    name = "mobile_operator_scratch_" + uuid.uuid4().hex[:12]
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
                    [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=120
                )
            author_id, user_id = uuid.uuid4(), uuid.uuid4()
            sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
            async with sessionmaker() as db:
                db.add_all(
                    [
                        User(
                            id=author_id,
                            username="operator_author",
                            name="Test Author",
                            email="author@example.invalid",
                            role=UserRole.super_admin,
                        ),
                        User(
                            id=user_id,
                            username="operator_user",
                            name="Test User",
                            email="user@example.invalid",
                            role=UserRole.user,
                        ),
                    ]
                )
                await db.commit()
                server_id = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
                actor = await db.get(User, author_id)
                req = ops.MobileTestSetup(
                    server_id=server_id,
                    author_viewer_id=author_id,
                    user_viewer_id=user_id,
                    acknowledgement="isolated-disposable-synthetic-only-v1",
                )
                monkeypatch.setattr(ops, "_refresh", AsyncMock())
                monkeypatch.setattr(ops, "_audit", AsyncMock())
                monkeypatch.setattr(ops, "get_redis", lambda: object())
                revoked = AsyncMock()

                async def reject_interleaved_reopen(redis, viewer_id):
                    if revoked.await_count == 0:
                        async with sessionmaker() as competing:
                            for action in (ops.mobile_test_setup, ops.mobile_test_open):
                                with pytest.raises(HTTPException) as denied:
                                    await action(req, competing, actor)
                                assert denied.value.status_code == 409
                            await competing.rollback()
                    await revoked(redis, viewer_id)

                monkeypatch.setattr(ops, "revoke_user_tokens", reject_interleaved_reopen)
                assert (await ops.mobile_test_status(db, actor)).blocked
                prepared = await ops.mobile_test_setup(req, db, actor)
                assert prepared.configured and prepared.blocked and not prepared.trace_headlines
                opened = await ops.mobile_test_open(req, db, actor)
                assert opened.configured and not opened.blocked and opened.generation > prepared.generation
                assert await mobile_issue_allowed(db) is True
                await db.commit()  # release the test issuer's shared project lock before revoke
                closed = await ops.mobile_test_revoke(db, actor)
                assert await mobile_issue_allowed(db) is False
                assert closed.blocked and not closed.configured and not closed.trace_headlines
                assert revoked.await_count == 2
                entries = (
                    (await db.execute(text("SELECT action FROM mobile_operator_audit ORDER BY created_at,id")))
                    .scalars()
                    .all()
                )
                assert entries.count("setup") == 1 and entries.count("open") == 1
                assert entries.count("revoking") == 1 and entries.count("revoke") == 1
                assert (
                    await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'"))
                ) is True
                assert (
                    await db.scalar(text("SELECT value FROM enterprise_config WHERE key='mobile.auth_enabled'"))
                ) == "false"
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
