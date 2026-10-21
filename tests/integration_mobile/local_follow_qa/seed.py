# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Seed only the newly created disposable database; never accept arbitrary credentials."""

import asyncio
import os
import uuid

from sqlalchemy import text

from database import async_session, engine
from models import Base
from models.user import User, UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.mobile_follow_store import Partition, locked_partition


async def schema():
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await conn.run_sync(
            lambda sync: Base.metadata.create_all(
                sync,
                tables=[table for table in Base.metadata.sorted_tables if not table.name.startswith("mobile_follow_")],
            )
        )
    await engine.dispose()


async def fixture():
    password = os.environ["QA_PASSWORD"]
    owner = User(
        id=uuid.uuid4(),
        email="owner@follow-qa.invalid",
        username="follow_qa_owner",
        name="Disposable Follow QA Owner",
        role=UserRole.super_admin,
    )
    owner.set_password(password)
    other = User(
        id=uuid.uuid4(),
        email="viewer@follow-qa.invalid",
        username="follow_qa_viewer",
        name="Disposable Follow QA Viewer",
        role=UserRole.user,
    )
    other.set_password(password)
    async with async_session.begin() as db:
        server = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
        assert server is not None, "migration 069 server identity missing"
        db.add_all([owner, other])
        await db.flush()
        await db.execute(
            text(
                "UPDATE mobile_read_controls SET blocked=false, source_policy_ready=true, "
                "synthetic_expires_at=clock_timestamp()+interval '1 hour' WHERE project_id=:project"
            ),
            {"project": str(DEFAULT_PROJECT_ID)},
        )
        values = {
            "mobile.auth_enabled": "true",
            "mobile.synthetic_test_enabled": "true",
            "mobile.synthetic_test_ack": "isolated-disposable-synthetic-only-v1",
            "mobile.synthetic_test_server_id": str(server),
            "mobile.synthetic_test_viewer_id": str(owner.id),
            "mobile.synthetic_test_self_user_viewer_id": str(other.id),
            "deployment.public_url": "https://localhost:18443",
            "deployment.frontend_url": "https://localhost:18443",
        }
        for key, value in values.items():
            await db.execute(
                text(
                    "INSERT INTO enterprise_config (id,key,value,updated_at) VALUES (:id,:key,:value,clock_timestamp())"
                ),
                {"id": uuid.uuid4(), "key": key, "value": value},
            )
        await locked_partition(
            db, Partition(server, str(DEFAULT_PROJECT_ID), owner.id, "synthetic-author"), create=True
        )
        await locked_partition(db, Partition(server, str(DEFAULT_PROJECT_ID), other.id, "synthetic-user"), create=True)
    await engine.dispose()


if __name__ == "__main__":
    import sys

    asyncio.run({"schema": schema, "fixture": fixture}[sys.argv[1]]())
