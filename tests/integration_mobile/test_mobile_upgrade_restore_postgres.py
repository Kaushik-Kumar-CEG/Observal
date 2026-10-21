# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in restored-backup 068 -> 069 rehearsal on isolated local PostgreSQL 18.

Use only the disposable instance from the publication-clock scratch script;
requires Docker's postgres:18 client. Never run against a shared database.
"""

import os
import subprocess
import sys
import time
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from models import Base

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_populated_068_backup_restores_and_quarantines_older_approvals():
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    # Deliberately bounded synthetic sizes, never an implicit live-instance probe.
    row_count = int(os.getenv("MOBILE_MIGRATION_ROWS", "1000"))
    assert 1_000 <= row_count <= 100_000, "scratch-only synthetic row range"
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    name = "mobile_backup_" + uuid.uuid4().hex[:10]
    restored_name = "mobile_restore_" + uuid.uuid4().hex[:10]
    source = create_async_engine(base.set(database=name))
    restored = create_async_engine(base.set(database=restored_name))
    created: list[str] = []
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + name))
            created.append(name)
        env = {**os.environ, "DATABASE_URL": base.set(database=name).render_as_string(hide_password=False)}
        async with source.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.run_sync(Base.metadata.create_all)
        for action in (("stamp", "044_review_orphan_authors"), ("upgrade", "068_mobile_erasure_epoch_guard")):
            subprocess.run(
                [sys.executable, "-m", "alembic", *action], env=env, check=True, capture_output=True, timeout=150
            )
        async with source.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO mobile_publication_events(kind,listing_id,version_id,status,recorded_at) "
                    "SELECT 'mcp', gen_random_uuid(), gen_random_uuid(), 'approved', "
                    "TIMESTAMPTZ '2020-01-01 00:00:00+00' FROM generate_series(1,:row_count)"
                ),
                {"row_count": row_count},
            )
            assert await conn.scalar(text("SELECT count(*) FROM mobile_publication_events")) == row_count
        # The physical dump is created before irreversible migration and then
        # restored into a new database. Never use mock backup APIs as proof.
        client = ["docker", "run", "--rm", "--network=host", "-e", "PGPASSWORD=mobile070-scratch", "postgres:18"]
        backup = subprocess.run(
            [*client, "pg_dump", "-Fc", "-h", "127.0.0.1", "-p", "15440", "-U", "observal", "-d", name],
            check=True,
            capture_output=True,
            timeout=90,
        ).stdout
        assert backup.startswith(b"PGDMP") and len(backup) > 1024
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + restored_name))
            created.append(restored_name)
        restore = subprocess.run(
            [
                *client[:2],
                "-i",
                *client[2:],
                "pg_restore",
                "-h",
                "127.0.0.1",
                "-p",
                "15440",
                "-U",
                "observal",
                "-d",
                restored_name,
            ],
            input=backup,
            capture_output=True,
            timeout=140,
        )
        assert restore.returncode == 0, restore.stderr[-400:]
        async with restored.connect() as conn:
            assert (
                await conn.scalar(text("SELECT version_num FROM alembic_version")) == "068_mobile_erasure_epoch_guard"
            )
            assert await conn.scalar(text("SELECT count(*) FROM mobile_publication_events")) == row_count
            before_size = await conn.scalar(text("SELECT pg_total_relation_size('mobile_publication_events')"))
        restore_env = {**env, "DATABASE_URL": base.set(database=restored_name).render_as_string(hide_password=False)}
        before = subprocess.run(
            [sys.executable, "-m", "services.mobile_boot_preflight", "--require-schema"],
            env=restore_env,
            capture_output=True,
            timeout=30,
        )
        assert before.returncode == 2 and b"OLD_OR_INCOMPATIBLE_SCHEMA" in before.stdout
        # The per-process Compose shell gate must refuse to exec an API/worker
        # even if its old init container is still marked successful.
        shell_gate = f'{sys.executable} -m services.mobile_boot_preflight --require-schema && exec "$@"'
        blocked_boot = subprocess.run(
            ["/bin/sh", "-ec", shell_gate, "--", sys.executable, "-c", "print('BOOT_STARTED')"],
            env=restore_env,
            capture_output=True,
            timeout=30,
        )
        assert blocked_boot.returncode == 2 and b"BOOT_STARTED" not in blocked_boot.stdout
        start = time.monotonic()
        migrated = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=restore_env,
            capture_output=True,
            timeout=150,
        )
        assert migrated.returncode == 0, migrated.stderr[-500:]
        elapsed = time.monotonic() - start
        async with restored.connect() as conn:
            assert await conn.scalar(text("SELECT version_num FROM alembic_version")) == "070_mobile_follow_sync_state"
            assert await conn.scalar(text("SELECT current_setting('track_commit_timestamp')")) == "on"
            assert await conn.scalar(text("SELECT count(*) FROM mobile_publication_events")) == row_count
            after_size = await conn.scalar(text("SELECT pg_total_relation_size('mobile_publication_events')"))
            assert (
                await conn.scalar(
                    text("SELECT count(*) FROM mobile_publication_events WHERE recorded_at > TIMESTAMPTZ '2020-01-01'")
                )
                == row_count
            )
        after = subprocess.run(
            [sys.executable, "-m", "services.mobile_boot_preflight", "--require-schema"],
            env=restore_env,
            capture_output=True,
            timeout=30,
        )
        assert after.returncode == 0, after.stdout[-400:] + after.stderr[-400:]
        allowed_boot = subprocess.run(
            ["/bin/sh", "-ec", shell_gate, "--", sys.executable, "-c", "print('BOOT_STARTED')"],
            env=restore_env,
            capture_output=True,
            timeout=30,
        )
        assert allowed_boot.returncode == 0 and b"BOOT_STARTED" in allowed_boot.stdout
        print(
            f"RESTORED_POPULATED_068_TO_070_ROWS={row_count} MIGRATION_SECONDS={elapsed:.3f} "
            f"PUBLICATION_RELATION_BYTES_BEFORE={before_size} AFTER={after_size}"
        )
    finally:
        await source.dispose()
        await restored.dispose()
        for db_name in reversed(created):
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE IF EXISTS " + db_name + " WITH (FORCE)"))
        await admin.dispose()
