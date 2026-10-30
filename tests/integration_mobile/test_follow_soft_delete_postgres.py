# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Physical regression: upstream soft deletion must erase both Follow owners and subjects."""

import os
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.mark.asyncio
async def test_deleted_shell_erases_follow_owner_and_subject_partitions():
    configured = os.getenv("OBSERVAL_TEST_POSTGRES_URL")
    if not configured:
        pytest.skip("Set OBSERVAL_TEST_POSTGRES_URL to an isolated disposable PostgreSQL database")
    url = make_url(configured)
    assert url.host == "127.0.0.1" and url.database.startswith("observal_rebase")
    admin = create_async_engine(url, isolation_level="AUTOCOMMIT")
    database = "observal_rebase_soft_" + uuid.uuid4().hex[:12]
    target = url.set(database=database)
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + database))
            created = True
        env = os.environ | {"DATABASE_URL": target.render_as_string(hide_password=False)}
        server = os.path.join(os.path.dirname(__file__), "..", "..", "observal-server")
        for module in (
            ("services.schema_bootstrap", "init"),
            ("alembic", "stamp", "053_mcp_webhook_sync_timestamps"),
            ("alembic", "upgrade", "head"),
        ):
            subprocess.run(
                [sys.executable, "-m", *module], cwd=server, env=env, check=True, capture_output=True, timeout=180
            )
        engine = create_async_engine(target)
        owner, subject, second_owner, server_id = (uuid.uuid4() for _ in range(4))
        try:
            async with engine.begin() as conn:
                for user_id in (owner, subject, second_owner):
                    await conn.execute(
                        text(
                            "INSERT INTO users(id,email,username,name,role,created_at) "
                            "VALUES (:id,:email,:name,'Fixture','user',now())"
                        ),
                        {"id": user_id, "email": f"{user_id}@invalid.example", "name": user_id.hex[:24]},
                    )
                for partition_owner in (owner, second_owner):
                    await conn.execute(
                        text(
                            "INSERT INTO mobile_follow_partitions"
                            "(server_id,project_id,owner_id,cohort,subject_count) "
                            "VALUES (:server,'default',:owner,'live',1)"
                        ),
                        {"server": server_id, "owner": partition_owner},
                    )
                    await conn.execute(
                        text(
                            "INSERT INTO mobile_follow_subjects"
                            "(server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) "
                            "VALUES (:server,'default',:owner,'live',:subject,1,true,1)"
                        ),
                        {"server": server_id, "owner": partition_owner, "subject": subject},
                    )
                await conn.execute(
                    text("UPDATE users SET deleted_at=now(), auth_provider='deleted' WHERE id=:id"), {"id": subject}
                )
                assert await conn.scalar(text("SELECT count(*) FROM mobile_follow_subjects")) == 0
                assert (
                    await conn.scalar(text("SELECT count(*) FROM mobile_follow_partitions WHERE subject_count=0")) == 2
                )
                assert (
                    await conn.scalar(
                        text("SELECT count(*) FROM users WHERE id=:id AND deleted_at IS NOT NULL"), {"id": subject}
                    )
                    == 1
                )
                await conn.execute(
                    text("UPDATE users SET deleted_at=now(), auth_provider='deleted' WHERE id=:id"), {"id": owner}
                )
                assert await conn.scalar(text("SELECT count(*) FROM mobile_follow_partitions")) == 1
                assert (
                    await conn.scalar(
                        text("SELECT count(*) FROM mobile_follow_partitions WHERE owner_id=:id"), {"id": owner}
                    )
                    == 0
                )
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + database + " WITH (FORCE)"))
        await admin.dispose()
