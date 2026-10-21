# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real PG migration test; only creates ephemeral databases on loopback scratch PG."""

import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

from models import Base

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="loopback scratch PG only")
SERVER = Path(__file__).resolve().parents[2] / "observal-server"


def migrate(url, *args):
    env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False)}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args], cwd=SERVER, env=env, capture_output=True, timeout=180
    )
    assert result.returncode == 0, result.stderr.decode()[-3000:]


@pytest.mark.asyncio(loop_scope="session")
async def test_fresh_and_populated_069_upgrade_owner_isolation_and_erasure():
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = []
    try:
        for stage in ("fresh", "populated"):
            name = "follow_070_" + stage + "_" + uuid.uuid4().hex[:8]
            async with admin.connect() as conn:
                await conn.execute(text("CREATE DATABASE " + name))
            created.append(name)
            target = base.set(database=name)
            engine = create_async_engine(target)
            try:
                async with engine.begin() as conn:
                    await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                    await conn.run_sync(
                        lambda sync: Base.metadata.create_all(
                            sync,
                            tables=[t for t in Base.metadata.sorted_tables if not t.name.startswith("mobile_follow_")],
                        )
                    )
                migrate(target, "stamp", "044_review_orphan_authors")
                migrate(target, "upgrade", "069_mobile_publication_clock" if stage == "populated" else "head")
                owner, other, subject = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
                async with engine.begin() as conn:
                    for uid in (owner, other, subject):
                        await conn.execute(
                            text(
                                "INSERT INTO users (id,email,username,name,role,created_at) VALUES (:id,:email,:username,'Scratch','user',clock_timestamp())"
                            ),
                            {"id": uid, "email": f"{uid}@scratch.invalid", "username": uid.hex[:20]},
                        )
                    if stage == "populated":
                        await conn.execute(
                            text(
                                "INSERT INTO mobile_publication_events (kind,listing_id,version_id,status) VALUES ('mcp',:a,:b,'approved')"
                            ),
                            {"a": uuid.uuid4(), "b": uuid.uuid4()},
                        )
                if stage == "populated":
                    migrate(target, "upgrade", "head")
                async with engine.begin() as conn:
                    assert (
                        await conn.scalar(text("SELECT version_num FROM alembic_version"))
                        == "070_mobile_follow_sync_state"
                    )
                    if stage == "populated":
                        assert await conn.scalar(text("SELECT count(*) FROM mobile_publication_events")) == 1
                    server = uuid.uuid4()
                    for uid in (owner, other):
                        await conn.execute(
                            text(
                                "INSERT INTO mobile_follow_partitions (server_id,project_id,owner_id,cohort,subject_count) VALUES (:server,'p',:owner,'real',1)"
                            ),
                            {"server": server, "owner": uid},
                        )
                        await conn.execute(
                            text(
                                "INSERT INTO mobile_follow_subjects (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) VALUES (:server,'p',:owner,'real',:subject,1,true,1)"
                            ),
                            {"server": server, "owner": uid, "subject": subject},
                        )
                    # A child cannot cross the owner partition even with a valid subject.
                    with pytest.raises(IntegrityError):
                        async with conn.begin_nested():
                            await conn.execute(
                                text(
                                    "INSERT INTO mobile_follow_subjects (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) VALUES (:server,'other',:owner,'real',:subject,1,true,1)"
                                ),
                                {"server": server, "owner": owner, "subject": subject},
                            )
                    # The 2+2 durable slot bounds and 15-minute expiry are DB-enforced.
                    for kind in ("image", "changes"):
                        for slot in (1, 2):
                            await conn.execute(
                                text(
                                    "INSERT INTO mobile_follow_leases (server_id,project_id,owner_id,cohort,"
                                    "lease_id,kind,slot,device_id,owner_generation,pinned_revision,erasure_floor,"
                                    "after_revision,upper_revision,logical_bytes,row_count,admitted_at,expires_at) "
                                    "VALUES (:server,'p',:owner,'real',:lease,:kind,:slot,:device,1,0,0,"
                                    ":after,:upper,0,0,statement_timestamp(),statement_timestamp()+interval '15 minutes')"
                                ),
                                {
                                    "server": server,
                                    "owner": owner,
                                    "lease": uuid.uuid4(),
                                    "kind": kind,
                                    "slot": slot,
                                    "device": f"{slot}" + "A" * 42 if kind == "changes" else None,
                                    "after": 0 if kind == "changes" else None,
                                    "upper": 0 if kind == "changes" else None,
                                },
                            )
                        with pytest.raises(IntegrityError):
                            async with conn.begin_nested():
                                await conn.execute(
                                    text(
                                        "INSERT INTO mobile_follow_leases (server_id,project_id,owner_id,cohort,lease_id,kind,slot,owner_generation,pinned_revision,erasure_floor,logical_bytes,row_count,admitted_at,expires_at) VALUES (:server,'p',:owner,'real',:lease,:kind,3,1,0,0,0,0,statement_timestamp(),statement_timestamp()+interval '15 minutes')"
                                    ),
                                    {"server": server, "owner": owner, "lease": uuid.uuid4(), "kind": kind},
                                )
                    op_id = uuid.uuid4()
                    await conn.execute(
                        text(
                            "INSERT INTO mobile_follow_operations (server_id,project_id,owner_id,cohort,operation_id,original_generation,subject_id,body_digest,original_http_status,outcome,lane,logical_bytes,expires_at) VALUES (:server,'p',:owner,'real',:op,1,:subject,:digest,200,'{}','normal',128,:expiry)"
                        ),
                        {
                            "server": server,
                            "owner": owner,
                            "op": op_id,
                            "subject": subject,
                            "digest": bytes(32),
                            "expiry": datetime.now(UTC) + timedelta(days=91),
                        },
                    )
                    device_id = "opaque_device_token_urlsafe32_synthetic_12345678901"
                    await conn.execute(
                        text(
                            "INSERT INTO mobile_follow_approvals "
                            "(server_id,project_id,owner_id,cohort,device_id,challenge_digest,owner_generation,expires_at) "
                            "VALUES (:server,'p',:owner,'real',:device,:digest,1,clock_timestamp()+interval '300 seconds')"
                        ),
                        {"server": server, "owner": owner, "device": device_id, "digest": bytes(32)},
                    )
                    assert (
                        await conn.scalar(
                            text("SELECT device_id FROM mobile_follow_approvals WHERE owner_id=:owner"),
                            {"owner": owner},
                        )
                        == device_id
                    )
                    # PostgreSQL CHECK must reject NULL expiry on a 90-day indexed receipt,
                    # not silently accept UNKNOWN from a nullable date comparison.
                    with pytest.raises(IntegrityError):
                        async with conn.begin_nested():
                            await conn.execute(
                                text(
                                    "INSERT INTO mobile_follow_privacy_actions "
                                    "(server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,"
                                    "original_generation,fenced_generation,expires_at) "
                                    "VALUES (:server,'p',:owner,'real',:action,'withdrawal','nonce_lookup_90d',1,2,NULL)"
                                ),
                                {"server": server, "owner": owner, "action": uuid.uuid4()},
                            )
                    # Both fresh install and upgrade require a 32-byte withdrawal binding;
                    # removal has no withdrawal body and must remain nullable.
                    privacy_insert = text(
                        "INSERT INTO mobile_follow_privacy_actions "
                        "(server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,"
                        "original_generation,fenced_generation,body_digest,device_id,nonce_digest) "
                        "VALUES (:server,'p',:owner,'real',:action,:kind,'state_only',1,2,:digest,:device,:nonce)"
                    )
                    for kind, digest in (("withdrawal", None), ("withdrawal", bytes(31)), ("removal", bytes(32))):
                        with pytest.raises(IntegrityError):
                            async with conn.begin_nested():
                                await conn.execute(
                                    privacy_insert,
                                    {
                                        "server": server,
                                        "owner": owner,
                                        "action": uuid.uuid4(),
                                        "kind": kind,
                                        "digest": digest,
                                        "device": "phone" if kind == "removal" else None,
                                        "nonce": bytes(32) if kind == "removal" else None,
                                    },
                                )
                    withdrawal = uuid.uuid4()
                    await conn.execute(
                        privacy_insert,
                        {
                            "server": server,
                            "owner": owner,
                            "action": withdrawal,
                            "kind": "withdrawal",
                            "digest": bytes(32),
                            "device": None,
                            "nonce": None,
                        },
                    )
                    assert (
                        await conn.scalar(
                            text(
                                "SELECT octet_length(body_digest) FROM mobile_follow_privacy_actions WHERE action_id=:id"
                            ),
                            {"id": withdrawal},
                        )
                        == 32
                    )
                    await conn.execute(
                        text("DELETE FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": withdrawal}
                    )
                    await conn.execute(
                        privacy_insert,
                        {
                            "server": server,
                            "owner": owner,
                            "action": uuid.uuid4(),
                            "kind": "removal",
                            "digest": None,
                            "device": "phone",
                            "nonce": bytes(32),
                        },
                    )
                    await conn.execute(text("DELETE FROM users WHERE id=:subject"), {"subject": subject})
                    assert await conn.scalar(text("SELECT count(*) FROM mobile_follow_subjects")) == 0
                    assert (
                        await conn.scalar(
                            text("SELECT count(*) FROM mobile_follow_leases WHERE owner_id=:owner"), {"owner": owner}
                        )
                        == 0
                    )
                    assert (
                        await conn.scalar(
                            text("SELECT effective FROM mobile_follow_operations WHERE operation_id=:op"), {"op": op_id}
                        )
                        is False
                    )
                    assert (
                        await conn.scalar(
                            text("SELECT erasure_floor FROM mobile_follow_partitions WHERE owner_id=:owner"),
                            {"owner": other},
                        )
                        == 1
                    )
                    await conn.execute(text("DELETE FROM users WHERE id=:owner"), {"owner": owner})
                    assert await conn.scalar(text("SELECT count(*) FROM mobile_follow_operations")) == 0
            finally:
                await engine.dispose()
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "069_mobile_publication_clock"],
            env={**os.environ, "DATABASE_URL": base.set(database=created[-1]).render_as_string(hide_password=False)},
            cwd=SERVER,
            capture_output=True,
            timeout=90,
        )
        assert result.returncode != 0 and b"Cannot discard follow-sync" in result.stderr
    finally:
        for name in reversed(created):
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"))
        await admin.dispose()
