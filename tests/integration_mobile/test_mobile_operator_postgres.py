# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in isolated PostgreSQL proof of atomic mobile operator setup/open/deny."""

import asyncio
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
    from services.mobile_read_control import mobile_issue_allowed, synthetic_principals_valid

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
                # This fixture has no ClickHouse; simulate only the startup
                # assertion that a finite source TTL was applied and verified.
                await db.execute(
                    text("UPDATE mobile_read_controls SET source_policy_ready=true WHERE project_id='default'")
                )
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
                    expires_in_minutes=30,
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
                assert prepared.expires_at is not None
                await db.commit()
                for replacement in (
                    req,
                    req.model_copy(update={"user_viewer_id": uuid.uuid4()}),
                    req.model_copy(update={"expires_in_minutes": 120}),
                ):
                    with pytest.raises(HTTPException) as denied:
                        await ops.mobile_test_setup(replacement, db, actor)
                    assert denied.value.status_code == 409
                    await db.rollback()
                    await db.refresh(actor)  # Rollback expires authenticated principal ORM fields.
                assert await db.scalar(text("SELECT count(*) FROM mobile_operator_audit WHERE action='setup'")) == 1
                await db.commit()
                rollback = subprocess.run(
                    [sys.executable, "-m", "alembic", "downgrade", "064_mobile_revoke_guard"],
                    env=env,
                    capture_output=True,
                    timeout=40,
                )
                assert rollback.returncode != 0, "Configured cohort cannot lose its expiry on downgrade"
                opened = await ops.mobile_test_open(req, db, actor)
                assert opened.configured and not opened.blocked and opened.generation > prepared.generation
                assert await synthetic_principals_valid(db, author_id, user_id)
                await db.commit()
                async with sessionmaker() as reader, sessionmaker() as editor:
                    assert await synthetic_principals_valid(reader, author_id, user_id)
                    change = asyncio.create_task(
                        editor.execute(
                            text("UPDATE users SET email='actor@real.example' WHERE id=:id"), {"id": user_id}
                        )
                    )
                    await asyncio.sleep(0.05)
                    assert not change.done(), "SCIM-style identity update must wait behind the protected read"
                    await reader.commit()
                    await asyncio.wait_for(change, timeout=3)
                    await editor.commit()
                assert not await synthetic_principals_valid(db, author_id, user_id)
                await db.execute(text("UPDATE users SET email='user@example.invalid' WHERE id=:id"), {"id": user_id})
                await db.commit()
                assert await mobile_issue_allowed(db) is True
                await db.commit()  # release the issuer's shared lock before the deadline test
                await db.execute(
                    text(
                        "UPDATE mobile_read_controls SET synthetic_expires_at=now()-interval '1 second' "
                        "WHERE project_id='default'"
                    )
                )
                await db.commit()
                assert await mobile_issue_allowed(db) is False  # expired issuance is denied across workers
                await db.commit()
                await db.execute(
                    text(
                        "UPDATE mobile_read_controls SET synthetic_expires_at=clock_timestamp()+interval '0.2 seconds' "
                        "WHERE project_id='default'"
                    )
                )
                await db.commit()
                await db.execute(text("SELECT 1"))  # begin a transaction before the expiry
                await asyncio.sleep(0.35)
                assert await mobile_issue_allowed(db) is False  # transaction-start now() would wrongly allow it
                await db.commit()
                await db.execute(
                    text(
                        "UPDATE mobile_read_controls SET synthetic_expires_at=now()+interval '30 minutes' "
                        "WHERE project_id='default'"
                    )
                )
                await db.commit()
                assert await mobile_issue_allowed(db) is True
                await db.commit()  # release the test issuer's shared project lock before revoke
                real_write = ops._write

                async def fail_disable(session, values):
                    if values.get("mobile.auth_enabled") == "false":
                        raise RuntimeError("isolated settings failure")
                    return await real_write(session, values)

                monkeypatch.setattr(ops, "_write", fail_disable)
                with pytest.raises(RuntimeError, match="isolated settings failure"):
                    await ops.mobile_test_revoke(db, actor)
                await db.rollback()  # failed phase-two transaction must not undo phase-one deny
                assert await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'"))
                assert await db.scalar(
                    text("SELECT revocation_pending FROM mobile_read_controls WHERE project_id='default'")
                )
                assert await mobile_issue_allowed(db) is False
                await db.commit()
                monkeypatch.setattr(ops, "_write", real_write)
                await db.refresh(actor)  # a new HTTP request reloads its authenticated principal after rollback
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
                assert entries.count("revoking") == 2 and entries.count("revoke") == 1
                assert (
                    await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'"))
                ) is True
                assert (
                    await db.scalar(text("SELECT value FROM enterprise_config WHERE key='mobile.auth_enabled'"))
                ) == "false"
                await db.commit()
                downgrade = subprocess.run(
                    [sys.executable, "-m", "alembic", "downgrade", "061_mobile_source_expiry_floor"],
                    env=env,
                    capture_output=True,
                    timeout=60,
                )
                assert downgrade.returncode != 0, "Audited closed cohort cannot discard operator receipts"
                assert b"Cannot restore untrusted historic mobile publication timestamps" in downgrade.stderr
                # The 067 policy transition is independent of revoke: neither
                # deadline expiry nor a later TTL increase can resurrect a
                # publication from an older unverified source epoch.
                before = await db.scalar(
                    text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                )
                await db.execute(
                    text(
                        "INSERT INTO enterprise_config(id,key,value,updated_at) VALUES (:id,'data.retention_days','90',now())"
                    ),
                    {"id": uuid.uuid4()},
                )
                await db.commit()
                epoch = await db.scalar(
                    text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                )
                assert epoch == before + 1
                assert not await db.scalar(
                    text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                )
                await db.execute(text("UPDATE enterprise_config SET value='90' WHERE key='data.retention_days'"))
                await db.commit()
                assert (
                    await db.scalar(
                        text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == epoch
                )
                await db.execute(text("UPDATE enterprise_config SET value='7' WHERE key='data.retention_days'"))
                await db.commit()
                assert (
                    await db.scalar(
                        text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == epoch + 1
                )
                # Simulate CH verification only in this disposable PG fixture;
                # a real API may set ready only after applying and checking TTL.
                await db.execute(
                    text("UPDATE mobile_read_controls SET source_policy_ready=true WHERE project_id='default'")
                )
                await db.commit()
                async with sessionmaker() as reader, sessionmaker() as writer:
                    from services.mobile_read_control import readable

                    assert not await readable(reader, "default")  # barrier still closed after revoke
                    task = asyncio.create_task(
                        writer.execute(text("UPDATE enterprise_config SET value='90' WHERE key='data.retention_days'"))
                    )
                    await asyncio.sleep(0.05)
                    assert not task.done(), "TTL setting change waits for the reader's project lock"
                    await reader.commit()
                    await asyncio.wait_for(task, timeout=3)
                    await writer.commit()
                assert not await db.scalar(
                    text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                )
                refusal = subprocess.run(
                    [sys.executable, "-m", "alembic", "downgrade", "066_mobile_scope_retention_clock"],
                    env=env,
                    capture_output=True,
                    timeout=50,
                )
                assert (
                    refusal.returncode != 0
                    and b"Cannot restore untrusted historic mobile publication timestamps" in refusal.stderr
                )
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
