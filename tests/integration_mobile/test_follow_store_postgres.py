# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real PostgreSQL store tests; creates only disposable loopback scratch DBs."""

import asyncio
import hashlib
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from models import Base
from services.mobile_follow_store import (
    Partition,
    StoreFenceError,
    admit_lease,
    admit_operation,
    fence_owner,
    lease_page,
    locked_partition,
    operation_status,
)

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="loopback scratch PG only")
SERVER = Path(__file__).resolve().parents[2] / "observal-server"


@pytest.fixture(scope="module")
async def scratch():
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    name = "follow_store_" + uuid.uuid4().hex[:8]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text("CREATE DATABASE " + name))
    target = base.set(database=name)
    engine = create_async_engine(target)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.run_sync(
                lambda sync: Base.metadata.create_all(
                    sync, tables=[t for t in Base.metadata.sorted_tables if not t.name.startswith("mobile_follow_")]
                )
            )
        env = {**os.environ, "DATABASE_URL": target.render_as_string(hide_password=False)}
        for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "head")):
            result = subprocess.run(
                [sys.executable, "-m", "alembic", *args], cwd=SERVER, env=env, capture_output=True, timeout=180
            )
            assert result.returncode == 0, result.stderr.decode()[-3000:]
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"))
        await admin.dispose()


async def _users(sessions, *ids):
    async with sessions.begin() as db:
        for uid in ids:
            await db.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:id,:email,:username,'Scratch','user',clock_timestamp())"
                ),
                {"id": uid, "email": f"{uid}@scratch.invalid", "username": uid.hex[:20]},
            )


async def _ready(sessions, key):
    async with sessions.begin() as db:
        await locked_partition(db, key, create=True)
        await db.execute(
            text(
                "UPDATE mobile_follow_partitions SET consent_state='available' "
                "WHERE server_id=:server_id AND project_id=:project_id "
                "AND owner_id=:owner_id AND cohort=:cohort"
            ),
            key.params(),
        )


async def _edit(sessions, key, subject, base, action, *, ident=None, generation=1):
    ident = ident or uuid.uuid4()
    digest = hashlib.sha256(f"{ident}:{subject}:{generation}:{base}:{action}".encode()).digest()
    async with sessions.begin() as db:
        result = await admit_operation(
            db,
            key,
            operation_id=ident,
            subject_id=subject,
            owner_generation=generation,
            base_person_revision=base,
            action=action,
            body_digest=digest,
        )
    return ident, digest, result


@pytest.mark.asyncio(loop_scope="module")
async def test_two_owners_devices_race_dedup_and_privacy(scratch):
    sessions = scratch
    server, owner_a, owner_b, subject = (uuid.uuid4() for _ in range(4))
    a, b = (Partition(server, "project", owner, "real") for owner in (owner_a, owner_b))
    await _users(sessions, owner_a, owner_b, subject)
    await _ready(sessions, a)
    await _ready(sessions, b)

    async def race(key):
        return await _edit(sessions, key, subject, 0, "follow")

    results = await asyncio.gather(race(a), race(a))
    assert sorted(r[2][0] for r in results) == [200, 409]
    assert (await _edit(sessions, b, subject, 0, "follow"))[2][0] == 200
    loser = next(r for r in results if r[2][0] == 409)
    winner = next(r for r in results if r[2][0] == 200)
    assert set(winner[2][1]) == {
        "operation_id",
        "subject_id",
        "owner_generation",
        "revision",
        "person_revision",
        "status",
    }
    assert winner[2][1]["status"] == "applied"
    assert set(loser[2][1]) == {
        "error",
        "operation_id",
        "owner_generation",
        "revision",
        "person_revision",
        "current_following",
    }
    assert loser[2][1]["revision"] == winner[2][1]["revision"]
    assert loser[2][1]["error"] == "person_conflict"
    async with sessions.begin() as db:
        assert (
            await admit_operation(
                db,
                a,
                operation_id=loser[0],
                subject_id=subject,
                owner_generation=1,
                base_person_revision=0,
                action="follow",
                body_digest=loser[1],
            )
        ) == loser[2]
        assert (await operation_status(db, a, loser[0]))["effective"] is True
        image = await admit_lease(db, a, kind="image", min_revision=1)
        assert await admit_lease(db, a, kind="image", min_revision=1) == image
        ca = await admit_lease(db, a, kind="changes", device_id="phone-a", after_revision=0)
        cb = await admit_lease(db, a, kind="changes", device_id="phone-b", after_revision=1)
        assert ca != cb
        assert (await lease_page(db, a, ca, kind="changes", device_id="phone-a"))["complete"] is True
        with pytest.raises(StoreFenceError, match="snapshot_required"):
            await admit_lease(db, a, kind="changes", device_id="phone-c", after_revision=0)
    async with sessions.begin() as db:
        assert await fence_owner(db, a) == 2
    async with sessions.begin() as db:
        assert (await operation_status(db, a, loser[0]))["effective"] is False
        with pytest.raises(StoreFenceError, match="snapshot_required"):
            await lease_page(db, a, image, kind="image")
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_operation(
                db,
                a,
                operation_id=uuid.uuid4(),
                subject_id=subject,
                owner_generation=1,
                base_person_revision=0,
                action="follow",
                body_digest=bytes(32),
            )
        assert (await locked_partition(db, b))["subject_count"] == 1
    async with sessions.begin() as db:
        await db.execute(text("DELETE FROM users WHERE id=:subject"), {"subject": subject})
        assert (await locked_partition(db, b))["erasure_floor"] == 1


@pytest.mark.asyncio(loop_scope="module")
async def test_subject_erasure_in_middle_of_deltas_requires_snapshot(scratch):
    sessions = scratch
    server, owner, first, erased, last = (uuid.uuid4() for _ in range(5))
    key = Partition(server, "erased-middle", owner, "real")
    await _users(sessions, owner, first, erased, last)
    await _ready(sessions, key)
    for subject in (first, erased, last):
        assert (await _edit(sessions, key, subject, 0, "follow"))[2][0] == 200
    async with sessions.begin() as db:
        await db.execute(text("DELETE FROM users WHERE id=:subject"), {"subject": erased})
    async with sessions.begin() as db:
        with pytest.raises(StoreFenceError, match="snapshot_required"):
            await admit_lease(db, key, kind="changes", device_id="phone-a", after_revision=0)
        # Erasure is not a synthetic zero delta. A fresh full image proves
        # current state, then a later contiguous change may advance it.
        image = await admit_lease(db, key, kind="image", min_revision=3)
        assert (await lease_page(db, key, image, kind="image"))["complete"] is True
    assert (await _edit(sessions, key, first, 1, "unfollow"))[2][0] == 200
    async with sessions.begin() as db:
        assert await admit_lease(db, key, kind="changes", device_id="phone-a", after_revision=3)


@pytest.mark.asyncio(loop_scope="module")
async def test_quota_conflict_before_insert_reserved_unfollow_and_page_progress(scratch):
    sessions = scratch
    server, owner, subject = (uuid.uuid4() for _ in range(3))
    key = Partition(server, "quota", owner, "real")
    await _users(sessions, owner, subject)
    await _ready(sessions, key)
    await _edit(sessions, key, subject, 0, "follow")
    async with sessions.begin() as db:
        p = key.params()
        await db.execute(
            text(
                "UPDATE mobile_follow_partitions SET normal_outcomes=10000 WHERE "
                "server_id=:server_id AND project_id=:project_id "
                "AND owner_id=:owner_id AND cohort=:cohort"
            ),
            p,
        )
        # Fill quota with real bounded outcomes to exercise the store's recomputed counters.
        await db.execute(
            text("""INSERT INTO mobile_follow_operations
            (server_id,project_id,owner_id,cohort,operation_id,original_generation,subject_id,
             body_digest,original_http_status,outcome,lane,logical_bytes,admitted_at,expires_at)
            SELECT :server_id,:project_id,:owner_id,:cohort, md5(i::text)::uuid,1,:subject,
                   decode(repeat('ab',32),'hex'),409,'{}'::jsonb,'normal',128,
                   clock_timestamp(),clock_timestamp()+interval '91 days'
            FROM generate_series(1,9999) i"""),
            {**p, "subject": subject},
        )
    with pytest.raises(StoreFenceError, match="history_capacity_reached"):
        await _edit(sessions, key, subject, 0, "follow")
    assert (await _edit(sessions, key, subject, 1, "unfollow"))[2][0] == 200
    async with sessions.begin() as db:
        row = await locked_partition(db, key)
        assert (row["normal_outcomes"], row["reserved_outcomes"]) == (10000, 1)
        lease = await admit_lease(db, key, kind="image", min_revision=2)
        with pytest.raises(StoreFenceError, match="rate_limited"):
            # First page 429 state commits with the admission transaction.
            await lease_page(db, key, lease, kind="image", throttle=True)
    async with sessions.begin() as db:
        assert (await lease_page(db, key, lease, kind="image", throttle=True))["complete"]


@pytest.mark.asyncio(loop_scope="module")
async def test_distinct_high_water_and_fixed_image_pages(scratch):
    sessions = scratch
    server, owner, extra = (uuid.uuid4() for _ in range(3))
    key = Partition(server, "highwater", owner, "real")
    await _users(sessions, owner, extra)
    await _ready(sessions, key)
    async with sessions.begin() as db:
        p = key.params()
        await db.execute(
            text("""INSERT INTO users (id,email,username,name,role,created_at)
            SELECT md5(('highwater-'||i)::text)::uuid, 'hw'||i||'@scratch.invalid',
            'hw'||i, 'Scratch','user',clock_timestamp() FROM generate_series(1,1000) i""")
        )
        await db.execute(
            text("""INSERT INTO mobile_follow_subjects
            (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
            SELECT :server_id,:project_id,:owner_id,:cohort,md5(('highwater-'||i)::text)::uuid,
            1,i<=200,i FROM generate_series(1,1000) i"""),
            p,
        )
        await db.execute(
            text("""UPDATE mobile_follow_partitions SET subject_count=1000,current_revision=1000
            WHERE server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id AND cohort=:cohort"""),
            p,
        )
    with pytest.raises(StoreFenceError, match="capacity_reached"):
        await _edit(sessions, key, extra, 0, "follow")
    existing = uuid.UUID(bytes=hashlib.md5(b"highwater-201", usedforsecurity=False).digest())
    assert (await _edit(sessions, key, existing, 1, "follow"))[2][0] == 200
    async with sessions.begin() as db:
        first = await admit_lease(db, key, kind="image", min_revision=1001)
        page1 = await lease_page(db, key, first, kind="image")
        assert len(page1["items"]) == 100 and page1["complete"] is False
        page2 = await lease_page(db, key, first, kind="image", last_row=100)
        assert len(page2["items"]) == 100 and page2["complete"] is False
        page3 = await lease_page(db, key, first, kind="image", last_row=200)
        assert len(page3["items"]) == 1 and page3["complete"] is True
        assert (await locked_partition(db, key))["subject_count"] == 1000
