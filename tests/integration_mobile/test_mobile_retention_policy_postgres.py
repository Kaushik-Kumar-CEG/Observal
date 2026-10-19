# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Disposable 067 PostgreSQL + ClickHouse TTL and durable recovery proof."""

import asyncio
import inspect
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.skipif(
    os.getenv("MOBILE_MIGRATION_SCRATCH") != "1" or os.getenv("MOBILE_RETENTION_CH_SCRATCH") != "1",
    reason="disposable loopback PG and ClickHouse only",
)


@pytest.mark.asyncio(loop_scope="session")
async def test_policy_recovery_rechecks_real_clickhouse_ttl_and_quarantines_legacy(monkeypatch):
    from jobs.mobile_evidence import _source_retained_until
    from models import Base
    from services.clickhouse import client, schema
    from services.mobile_read_control import readable

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    assert os.getenv("MOBILE_RETENTION_CH_SCRATCH") == "1"
    name = "mobile_ttl_scratch_" + uuid.uuid4().hex[:10]
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
                    [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=110
                )
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            monkeypatch.setattr("database.async_session", sessions)
            monkeypatch.setattr(schema, "_materialize_if_needed", AsyncMock())
            monkeypatch.setattr(schema, "apply_resource_settings", AsyncMock())
            monkeypatch.setattr(client, "CLICKHOUSE_HTTP", "http://127.0.0.1:18139")
            monkeypatch.setattr(client, "CLICKHOUSE_DB", "default")
            monkeypatch.setattr(client, "CLICKHOUSE_USER", "observal")
            monkeypatch.setattr(client, "CLICKHOUSE_PASSWORD", "mobile067-ch-scratch")
            # Real local-only ClickHouse table with the production raw-line TTL.
            response = await client._query(
                "CREATE TABLE IF NOT EXISTS session_events "
                "(timestamp DateTime64(3, 'UTC'), raw_line String "
                "TTL timestamp + INTERVAL 30 DAY) ENGINE=MergeTree ORDER BY timestamp"
            )
            response.raise_for_status()
            async with sessions() as db:
                user = uuid.uuid4()
                await db.execute(
                    text(
                        "INSERT INTO users(id,email,username,name,role,created_at) "
                        "VALUES (:id,:email,:name,'Synthetic','user'::userrole,now())"
                    ),
                    {"id": user, "email": "ttl-" + user.hex + "@example.invalid", "name": "ttl_" + user.hex[:12]},
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_session_publications "
                        "(project_id,user_id,harness,session_id,source_revision,status,source_retained_until) "
                        "VALUES ('default',:user,'pi','old-no-proof',:hash,'complete',now()+interval '29 days')"
                    ),
                    {"user": user, "hash": "a" * 64},
                )
                await db.commit()
                assert not await readable(db, "default")
                await db.commit()
            await schema.init_clickhouse()
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                    )
                    is True
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT source_policy_epoch FROM mobile_session_publications "
                            "WHERE session_id='old-no-proof'"
                        )
                    )
                    == 0
                )
                assert (
                    await db.scalar(text("SELECT count(*) FROM mobile_source_policy_audit WHERE event='ttl_verified'"))
                    == 1
                )
                verified_since = await db.scalar(
                    text("SELECT source_policy_since FROM mobile_read_controls WHERE project_id='default'")
                )
                assert verified_since is not None
                await db.execute(
                    text(
                        "INSERT INTO mobile_source_final_receipts "
                        "(project_id,user_id,harness,session_id,final_line,source_hash) "
                        "VALUES ('default',:user,'pi','old-no-proof',2,:hash)"
                    ),
                    {"user": user, "hash": "b" * 64},
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_source_line_highwater "
                        "(project_id,user_id,harness,session_id,max_line) "
                        "VALUES ('default',:user,'pi','old-no-proof',2)"
                    ),
                    {"user": user},
                )
                await db.commit()
                first_epoch = await db.scalar(
                    text(
                        "SELECT epoch FROM mobile_scope_epochs "
                        "WHERE project_id='default' AND subject_id=:user "
                        "AND scope='user'"
                    ),
                    {"user": user},
                )
                await db.execute(
                    text(
                        "UPDATE mobile_source_line_highwater SET max_line=2 "
                        "WHERE user_id=:user AND session_id='old-no-proof'"
                    ),
                    {"user": user},
                )
                await db.commit()
                assert (
                    await db.scalar(
                        text("SELECT epoch FROM mobile_scope_epochs WHERE subject_id=:user AND scope='user'"),
                        {"user": user},
                    )
                    == first_epoch
                )
                await db.execute(
                    text(
                        "UPDATE mobile_source_line_highwater SET max_line=3 "
                        "WHERE user_id=:user AND session_id='old-no-proof'"
                    ),
                    {"user": user},
                )
                await db.commit()
                assert (
                    await db.scalar(
                        text("SELECT epoch FROM mobile_scope_epochs WHERE subject_id=:user AND scope='user'"),
                        {"user": user},
                    )
                    == first_epoch + 1
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT max_line FROM mobile_source_line_highwater "
                            "WHERE user_id=:user AND session_id='old-no-proof'"
                        ),
                        {"user": user},
                    )
                    == 3
                )
                with pytest.raises(DBAPIError, match="Mobile source high-water cannot decrease"):
                    await db.execute(
                        text(
                            "UPDATE mobile_source_line_highwater SET max_line=2 "
                            "WHERE user_id=:user AND session_id='old-no-proof'"
                        ),
                        {"user": user},
                    )
                await db.rollback()
                assert (
                    await db.scalar(
                        text(
                            "SELECT max_line FROM mobile_source_line_highwater "
                            "WHERE user_id=:user AND session_id='old-no-proof'"
                        ),
                        {"user": user},
                    )
                    == 3
                )
                # A queued worker must not acquire its shared project lock
                # between the committed pre-CH deny and the final high-water
                # and durable projection work item. Verify with real PG locks.
                from api.routes import ingest as ingest_route
                from services import session_ingest

                monkeypatch.setattr(ingest_route, "async_session", sessions)
                monkeypatch.setattr("services.mobile_run_identity.admit_pi_run", AsyncMock())
                entered, release = asyncio.Event(), asyncio.Event()

                async def delayed_repaired_source(**_):
                    entered.set()
                    await release.wait()
                    return session_ingest.IngestResult(ingested=0, skipped=1, errors=0)

                monkeypatch.setattr(session_ingest, "ingest_session_lines", delayed_repaired_source)
                monkeypatch.setattr(session_ingest, "advance_session_checkpoint", AsyncMock(return_value=(3, 42)))
                request = ingest_route.SessionIngestRequest(
                    session_id="old-no-proof", harness="pi", start_offset=3, lines=['{"type":"unknown"}']
                )
                pending = asyncio.create_task(
                    inspect.unwrap(ingest_route.ingest_session)(
                        request, None, current_user=SimpleNamespace(id=user), auth_db=db
                    )
                )
                try:
                    await asyncio.wait_for(entered.wait(), timeout=10)
                    async with sessions() as check:
                        assert (
                            await check.scalar(
                                text(
                                    "SELECT status FROM mobile_session_publications "
                                    "WHERE user_id=:user AND session_id='old-no-proof'"
                                ),
                                {"user": user},
                            )
                            == "pending_source"
                        )
                        assert (
                            await check.scalar(
                                text("SELECT pg_try_advisory_lock_shared(hashtextextended('mobile-read:default',0))")
                            )
                            is False
                        )
                finally:
                    release.set()
                assert (await asyncio.wait_for(pending, timeout=10)).ingested == 0
                async with sessions() as check:
                    assert (
                        await check.scalar(
                            text("SELECT pg_try_advisory_lock_shared(hashtextextended('mobile-read:default',0))")
                        )
                        is True
                    )
                    assert (
                        await check.scalar(
                            text("SELECT pg_advisory_unlock_shared(hashtextextended('mobile-read:default',0))")
                        )
                        is True
                    )
                    await check.commit()
                assert (
                    await db.scalar(
                        text(
                            "SELECT max_line FROM mobile_source_line_highwater "
                            "WHERE user_id=:user AND session_id='old-no-proof'"
                        ),
                        {"user": user},
                    )
                    == 3
                )
                await db.execute(
                    text(
                        "INSERT INTO enterprise_config(id,key,value,updated_at) "
                        "VALUES (:id,'data.retention_days','7',now())"
                    ),
                    {"id": uuid.uuid4()},
                )
                await db.commit()
                assert not await readable(db, "default")
                await db.commit()
            # Read denial commits before changing the independent CH TTL.
            await schema.init_clickhouse()
            async with sessions() as db:
                short_since = await db.scalar(
                    text("SELECT source_policy_since FROM mobile_read_controls WHERE project_id='default'")
                )
                assert short_since > verified_since
            await schema.init_clickhouse()
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_since FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == short_since
                )
            ts = datetime(2026, 1, 1, 23, 59, tzinfo=UTC)
            rows = [{"line_offset": 0, "timestamp": ts.isoformat()}]
            assert _source_retained_until(rows, "nonempty", retention_days=7) == datetime(2026, 1, 8, tzinfo=UTC)
            assert _source_retained_until(rows, "nonempty", retention_days=90) == ts + timedelta(days=29)
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                    )
                    is True
                )
                assert (
                    await db.scalar(
                        text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == 2
                )
                await db.execute(text("UPDATE enterprise_config SET value='90' WHERE key='data.retention_days'"))
                await db.commit()
                assert not await readable(db, "default")
                await db.commit()
            await schema.init_clickhouse()
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == 3
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT source_policy_epoch FROM mobile_session_publications "
                            "WHERE session_id='old-no-proof'"
                        )
                    )
                    == 0
                )
                await db.execute(text("UPDATE enterprise_config SET value='0' WHERE key='data.retention_days'"))
                await db.commit()
            await schema.init_clickhouse()  # Remove whole-row TTL; raw-line 30-day TTL stays.
            assert _source_retained_until(rows, "nonempty", retention_days=0) == ts + timedelta(days=29)
            # A failed metadata recheck MUST leave the grant gate closed and
            # must not write a false audit receipt. A worker retry can recover.
            real_query = client._query

            async def failed_readback(sql, *args, **kwargs):
                if sql.startswith("SELECT create_table_query"):
                    raise RuntimeError("isolated readback failure")
                return await real_query(sql, *args, **kwargs)

            monkeypatch.setattr(client, "_query", failed_readback)
            async with sessions() as db:
                count = await db.scalar(
                    text("SELECT count(*) FROM mobile_source_policy_audit WHERE event='ttl_verified'")
                )
            with pytest.raises(RuntimeError, match="isolated readback failure"):
                await schema.init_clickhouse()
            async with sessions() as db:
                assert not await db.scalar(
                    text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                )
                assert (
                    await db.scalar(text("SELECT count(*) FROM mobile_source_policy_audit WHERE event='ttl_verified'"))
                    == count
                )
            monkeypatch.setattr(client, "_query", real_query)
            await schema.init_clickhouse()
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id='default'")
                    )
                    is True
                )
                assert (
                    await db.scalar(text("SELECT count(*) FROM mobile_source_policy_audit WHERE event='ttl_verified'"))
                    == count + 1
                )
                await db.execute(text("DELETE FROM enterprise_config WHERE key='data.retention_days'"))
                await db.commit()
                assert not await readable(db, "default")
                await db.commit()
            await schema.init_clickhouse()  # Restore default 90 through the same audited fence.
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text("SELECT source_policy_epoch FROM mobile_read_controls WHERE project_id='default'")
                    )
                    == 5
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT retention_days FROM mobile_source_policy_audit "
                            "WHERE event='ttl_verified' ORDER BY id DESC LIMIT 1"
                        )
                    )
                    == 90
                )
                assert (
                    await db.scalar(
                        text(
                            "SELECT source_policy_epoch FROM mobile_session_publications "
                            "WHERE session_id='old-no-proof'"
                        )
                    )
                    == 0
                )
            # A verified existing populated instance remains usable for NEW
            # publication epochs. Historical receipts cannot gain the new epoch
            # by settings changes/startup alone; only a full-source worker
            # recheck can publish that epoch.
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + name + " WITH (FORCE)"))
        await admin.dispose()
