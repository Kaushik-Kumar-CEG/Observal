# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in disposable PostgreSQL follow privacy tests (never a persistent instance)."""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_follow_store_postgres import _users

from models import Base
from services.mobile_follow_privacy import (
    accept_consent,
    admit_privacy_action,
    erase_batch,
    expire_privacy_records,
    privacy_status,
    removal_by_nonce,
    withdrawal_body_digest,
)
from services.mobile_follow_store import Partition, StoreFenceError, admit_operation, locked_partition, operation_status

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="loopback scratch PG only")
SERVER = Path(__file__).resolve().parents[2] / "observal-server"


@pytest.fixture(scope="module")
async def scratch():
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    name = "follow_privacy_" + uuid.uuid4().hex[:8]
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


async def _partition(sessions, project="privacy"):
    server, owner, subject = (uuid.uuid4() for _ in range(3))
    key = Partition(server, project, owner, "real")
    await _users(sessions, owner, subject)
    return key, subject


async def _consent(sessions, key, generation=1, ident=None):
    ident = ident or uuid.uuid4()
    async with sessions.begin() as db:
        result = await accept_consent(
            db,
            key,
            consent_id=ident,
            owner_generation=generation,
            body_digest=bytes(32),
            browser_owner_approved=True,
        )
    return ident, result


async def _nonce(sessions, key, device, generation, digest):
    async with sessions.begin() as db:
        p = key.params()
        await db.execute(
            text("""INSERT INTO mobile_follow_nonces
        (server_id,project_id,owner_id,cohort,device_id,nonce_digest,owner_generation,issued_at,expires_at)
        VALUES (:server_id,:project_id,:owner_id,:cohort,:device,:digest,:gen,statement_timestamp(),
        statement_timestamp()+interval '120 seconds')"""),
            {**p, "device": device, "digest": digest, "gen": generation},
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_consent_precondition_retries_and_generation_fence(scratch):
    key, subject = await _partition(scratch)
    cid = uuid.uuid4()
    async with scratch() as db:
        with pytest.raises(StoreFenceError, match="transaction_required"):
            await accept_consent(
                db, key, consent_id=cid, owner_generation=1, body_digest=bytes(32), browser_owner_approved=True
            )
    async with scratch.begin() as db:
        with pytest.raises(StoreFenceError, match="invalid_request"):
            await accept_consent(
                db, key, consent_id=cid, owner_generation=1, body_digest=bytes(32), browser_owner_approved=False
            )
    _, first = await _consent(scratch, key, ident=cid)
    assert first["owner_generation"] == 2
    assert (await _consent(scratch, key, ident=cid))[1] == first
    with pytest.raises(StoreFenceError, match="consent_already_available"):
        await _consent(scratch, key, generation=2)
    async with scratch.begin() as db:
        assert (await locked_partition(db, key))["consent_bindings"] == 1
        receipt = (
            await db.execute(
                text("""SELECT accepted_at,expires_at FROM mobile_follow_consents
        WHERE owner_id=:owner AND consent_id=:id"""),
                {"owner": key.owner_id, "id": cid},
            )
        ).one()
        assert receipt.expires_at - receipt.accepted_at == timedelta(days=90)
        assert (
            await admit_operation(
                db,
                key,
                operation_id=uuid.uuid4(),
                subject_id=subject,
                owner_generation=2,
                base_person_revision=0,
                action="follow",
                body_digest=bytes(32),
            )
        )[0] == 200


@pytest.mark.asyncio(loop_scope="module")
async def test_remove_barrier_restartable_batches_nonce_and_dsr(scratch):
    key, subject = await _partition(scratch, "remove")
    await _consent(scratch, key)
    op = uuid.uuid4()
    async with scratch.begin() as db:
        await admit_operation(
            db,
            key,
            operation_id=op,
            subject_id=subject,
            owner_generation=2,
            base_person_revision=0,
            action="follow",
            body_digest=bytes(32),
        )
    nonce = bytes.fromhex("ab" * 32)
    await _nonce(scratch, key, "phone-a", 2, nonce)
    action = uuid.uuid4()
    async with scratch.begin() as db:
        pending = await admit_privacy_action(
            db,
            key,
            kind="removal",
            action_id=action,
            owner_generation=2,
            confirmed_authorized=True,
            device_id="phone-a",
            nonce_digest=nonce,
        )
        assert pending["status"] == "pending"
    async with scratch.begin() as db:
        assert (
            await removal_by_nonce(db, key, device_id="phone-a", nonce_digest=nonce, original_generation=2)
        ) == pending
        assert (await operation_status(db, key, op))["effective"] is False
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_operation(
                db,
                key,
                operation_id=uuid.uuid4(),
                subject_id=subject,
                owner_generation=2,
                base_person_revision=0,
                action="follow",
                body_digest=bytes(32),
            )
    for _ in range(5):
        async with scratch.begin() as db:
            state = await erase_batch(db, key, action)
        if state["status"] == "completed":
            break
    assert state["status"] == "completed"
    async with scratch.begin() as db:
        assert (await privacy_status(db, key, action, kind="removal"))["status"] == "completed"
        receipt = (
            await db.execute(
                text("""SELECT admitted_at,expires_at FROM mobile_follow_privacy_actions
        WHERE owner_id=:owner AND action_id=:id"""),
                {"owner": key.owner_id, "id": action},
            )
        ).one()
        assert receipt.expires_at - receipt.admitted_at == timedelta(days=90)
        row = await locked_partition(db, key)
        assert row["consent_state"] == "available" and row["subject_count"] == 0
        assert row["consent_bindings"] == 1
        assert (
            await admit_privacy_action(
                db,
                key,
                kind="removal",
                action_id=action,
                owner_generation=2,
                confirmed_authorized=True,
                device_id="phone-a",
                nonce_digest=nonce,
            )
        )["status"] == "completed"
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_subjects WHERE owner_id=:owner"), {"owner": key.owner_id}
            )
        ) == 0
        await db.execute(text("DELETE FROM users WHERE id=:id"), {"id": subject})
    later_nonce = bytes.fromhex("cd" * 32)
    await _nonce(scratch, key, "phone-a", 3, later_nonce)
    later_id = uuid.uuid4()
    async with scratch.begin() as db:
        await admit_privacy_action(
            db,
            key,
            kind="removal",
            action_id=later_id,
            owner_generation=3,
            confirmed_authorized=True,
            device_id="phone-a",
            nonce_digest=later_nonce,
        )
    async with scratch.begin() as db:
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_privacy_action(
                db,
                key,
                kind="removal",
                action_id=action,
                owner_generation=2,
                confirmed_authorized=True,
                device_id="phone-a",
                nonce_digest=nonce,
            )
        # Historical status lookup is still available; it must not be treated
        # as fresh POST authorization for the subsequent generation.
        assert (await privacy_status(db, key, action, kind="removal"))["status"] == "completed"


@pytest.mark.asyncio(loop_scope="module")
async def test_withdraw_overflow_slot_90day_receipts_and_deadline(scratch):
    key, _ = await _partition(scratch, "withdraw")
    await _consent(scratch, key)
    async with scratch.begin() as db:
        p = key.params()
        await db.execute(
            text("""INSERT INTO mobile_follow_privacy_actions
        (server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,original_generation,
        fenced_generation,status,body_digest,admitted_at,expires_at)
        SELECT :server_id,:project_id,:owner_id,:cohort,md5(('receipt-'||i)::text)::uuid,
        'withdrawal','nonce_lookup_90d',1,2,'completed',decode(repeat('00',32),'hex'),statement_timestamp(),
        statement_timestamp()+interval '90 days' FROM generate_series(1,1000) i"""),
            p,
        )
    action = uuid.uuid4()
    async with scratch.begin() as db:
        pending = await admit_privacy_action(
            db,
            key,
            kind="withdrawal",
            action_id=action,
            owner_generation=2,
            confirmed_authorized=True,
            body_digest=withdrawal_body_digest(action, 2),
        )
        assert pending["recovery_mode"] == "state_only"
        assert (await locked_partition(db, key))["indexed_receipts"] == 1000
    async with scratch.begin() as db:
        assert (await privacy_status(db, key, action, kind="withdrawal")) == pending
        await db.execute(
            text("""UPDATE mobile_follow_privacy_actions
        SET admitted_at=clock_timestamp()-interval '25 hours'
        WHERE owner_id=:owner AND action_id=:id"""),
            {"owner": key.owner_id, "id": action},
        )
    async with scratch.begin() as db:
        assert (await erase_batch(db, key, action))["status"] == "needs_operator"
        assert (await locked_partition(db, key))["removal_state"] == "needs_operator"
    # Expired indexed receipts free slots, but never truncate a newly admitted receipt.
    async with scratch.begin() as db:
        await db.execute(
            text("""UPDATE mobile_follow_privacy_actions
        SET admitted_at=statement_timestamp()-interval '91 days',
            expires_at=statement_timestamp()-interval '1 day'
        WHERE owner_id=:owner AND recovery_mode='nonce_lookup_90d'"""),
            {"owner": key.owner_id},
        )
        await expire_privacy_records(db, key)
        assert (await locked_partition(db, key))["indexed_receipts"] == 0


@pytest.mark.asyncio(loop_scope="module")
async def test_batched_erasure_subject_dsr_and_state_only_supersession(scratch):
    key, _ = await _partition(scratch, "batch")
    await _consent(scratch, key)
    p = key.params()
    async with scratch.begin() as db:
        await db.execute(
            text("""INSERT INTO users (id,email,username,name,role,created_at)
        SELECT md5(('batch-'||i)::text)::uuid, 'batch-'||i||'@scratch.invalid',
        'batch-'||i, 'Scratch','user',statement_timestamp() FROM generate_series(1,205) i""")
        )
        await db.execute(
            text("""INSERT INTO mobile_follow_subjects
        (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
        SELECT :server_id,:project_id,:owner_id,:cohort,md5(('batch-'||i)::text)::uuid,1,true,1
        FROM generate_series(1,205) i"""),
            p,
        )
        await db.execute(
            text("""UPDATE mobile_follow_partitions SET subject_count=205
        WHERE server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id AND cohort=:cohort"""),
            p,
        )
        await db.execute(
            text("""INSERT INTO mobile_follow_privacy_actions
        (server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,original_generation,
        fenced_generation,status,body_digest,admitted_at,expires_at)
        SELECT :server_id,:project_id,:owner_id,:cohort,md5(('batch-receipt-'||i)::text)::uuid,
        'withdrawal','nonce_lookup_90d',1,2,'completed',decode(repeat('00',32),'hex'),statement_timestamp(),
        statement_timestamp()+interval '90 days' FROM generate_series(1,1000) i"""),
            p,
        )
    nonce = bytes.fromhex("ae" * 32)
    await _nonce(scratch, key, "phone", 2, nonce)
    first = uuid.uuid4()
    async with scratch.begin() as db:
        assert (
            await admit_privacy_action(
                db,
                key,
                kind="removal",
                action_id=first,
                owner_generation=2,
                confirmed_authorized=True,
                device_id="phone",
                nonce_digest=nonce,
            )
        )["recovery_mode"] == "state_only"
    # Subject DSR may run between batches; its trigger adjusts the partition count.
    async with scratch.begin() as db:
        await db.execute(text("DELETE FROM users WHERE id=md5('batch-205')::uuid"))
    counts = []
    for _ in range(7):
        async with scratch.begin() as db:
            state = await erase_batch(db, key, first)
            counts.append(
                await db.scalar(
                    text("""SELECT count(*) FROM mobile_follow_subjects
                WHERE server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id
                AND cohort=:cohort"""),
                    p,
                )
            )
        if state["status"] == "completed":
            break
    assert counts[0] == 104 and counts[1] == 4 and counts[-1] == 0
    nonce2 = bytes.fromhex("af" * 32)
    await _nonce(scratch, key, "phone", 3, nonce2)
    second = uuid.uuid4()
    async with scratch.begin() as db:
        assert (
            await admit_privacy_action(
                db,
                key,
                kind="removal",
                action_id=second,
                owner_generation=3,
                confirmed_authorized=True,
                device_id="phone",
                nonce_digest=nonce2,
            )
        )["recovery_mode"] == "state_only"
        with pytest.raises(StoreFenceError, match="unknown"):
            await privacy_status(db, key, first, kind="removal")
        with pytest.raises(StoreFenceError, match="unknown"):
            await removal_by_nonce(db, key, device_id="phone", nonce_digest=nonce, original_generation=2)
        assert (await privacy_status(db, key, second, kind="removal"))["status"] == "pending"
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_privacy_actions WHERE owner_id=:owner"),
                {"owner": key.owner_id},
            )
        ) == 1001


@pytest.mark.asyncio(loop_scope="module")
async def test_consent_quota_survives_withdrawal_and_expires(scratch):
    key, _ = await _partition(scratch, "consent-cap")
    cid, _ = await _consent(scratch, key)
    async with scratch.begin() as db:
        p = key.params()
        await db.execute(
            text("""INSERT INTO mobile_follow_consents
        (server_id,project_id,owner_id,cohort,consent_id,request_generation,accepted_generation,
         body_digest,accepted_at,expires_at)
        SELECT :server_id,:project_id,:owner_id,:cohort,md5(('consent-'||i)::text)::uuid,1,2,
        decode(repeat('00',32),'hex'),statement_timestamp(),statement_timestamp()+interval '90 days'
        FROM generate_series(1,999) i"""),
            p,
        )
    action = uuid.uuid4()
    async with scratch.begin() as db:
        assert (
            await admit_privacy_action(
                db,
                key,
                kind="withdrawal",
                action_id=action,
                owner_generation=2,
                confirmed_authorized=True,
                body_digest=withdrawal_body_digest(action, 2),
            )
        )["status"] == "pending"
    for _ in range(5):
        async with scratch.begin() as db:
            state = await erase_batch(db, key, action)
        if state["status"] == "completed":
            break
    assert state["status"] == "completed"
    async with scratch.begin() as db:
        assert (await locked_partition(db, key))["consent_bindings"] == 1000
    with pytest.raises(StoreFenceError, match="consent_capacity_reached"):
        await _consent(scratch, key, generation=3)
    async with scratch.begin() as db:
        await db.execute(
            text("""UPDATE mobile_follow_consents SET
        accepted_at=statement_timestamp()-interval '91 days',
        expires_at=statement_timestamp()-interval '1 day'
        WHERE owner_id=:owner AND consent_id<>:id"""),
            {"owner": key.owner_id, "id": cid},
        )
    _, admitted = await _consent(scratch, key, generation=3)
    assert admitted["owner_generation"] == 4


@pytest.mark.asyncio(loop_scope="module")
async def test_withdrawal_crash_rollback_lost_202_and_body_bound_replay(scratch):
    key, _ = await _partition(scratch, "withdraw-retry")
    await _consent(scratch, key)
    action = uuid.uuid4()
    digest = withdrawal_body_digest(action, 2)
    assert (
        digest
        == hashlib.sha256(
            json.dumps(
                {"confirm": True, "owner_generation": 2, "withdrawal_id": str(action)},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).digest()
    )
    assert digest != withdrawal_body_digest(action, 3)
    args = dict(kind="withdrawal", action_id=action, owner_generation=2, confirmed_authorized=True)

    # An exception after the INSERT/barrier but before commit must undo both.
    with pytest.raises(RuntimeError, match="injected crash"):
        async with scratch.begin() as db:
            await admit_privacy_action(db, key, **args, body_digest=digest)
            assert (
                await db.scalar(
                    text("SELECT count(*) FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": action}
                )
                == 1
            )
            assert (await locked_partition(db, key))["owner_generation"] == 3
            raise RuntimeError("injected crash")
    async with scratch.begin() as db:
        assert (await locked_partition(db, key))["owner_generation"] == 2
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": action}
            )
            == 0
        )
        for changed in (None, bytes(32), withdrawal_body_digest(action, 3)):
            with pytest.raises(StoreFenceError, match="invalid_request"):
                await admit_privacy_action(db, key, **args, body_digest=changed)
        assert (await locked_partition(db, key))["consent_state"] == "available"

    # The successful commit's response is lost; retry must return the same pending receipt.
    async with scratch.begin() as db:
        pending = await admit_privacy_action(db, key, **args, body_digest=digest)
    assert pending["status"] == "pending" and pending["owner_generation"] == 3
    async with scratch.begin() as db:
        assert await admit_privacy_action(db, key, **args, body_digest=digest) == pending
        assert (
            await db.scalar(
                text("SELECT body_digest FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": action}
            )
            == digest
        )
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_privacy_action(
                db,
                key,
                kind="withdrawal",
                action_id=action,
                owner_generation=3,
                confirmed_authorized=True,
                body_digest=withdrawal_body_digest(action, 3),
            )
        for changed in (None, bytes(32), withdrawal_body_digest(action, 3)):
            with pytest.raises(StoreFenceError, match="invalid_request"):
                await admit_privacy_action(db, key, **args, body_digest=changed)
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_privacy_action(
                db,
                key,
                kind="removal",
                action_id=action,
                owner_generation=2,
                confirmed_authorized=True,
                device_id="phone",
                nonce_digest=bytes(32),
            )
        assert (await privacy_status(db, key, action, kind="withdrawal")) == pending
        assert (await locked_partition(db, key))["owner_generation"] == 3
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": action}
            )
            == 1
        )

    async with scratch.begin() as db:
        assert (await erase_batch(db, key, action))["status"] == "completed"
        assert (await privacy_status(db, key, action, kind="withdrawal"))["status"] == "completed"
    await _consent(scratch, key, generation=3)
    async with scratch.begin() as db:
        with pytest.raises(StoreFenceError, match="generation_conflict"):
            await admit_privacy_action(db, key, **args, body_digest=digest)
        # The indexed historical receipt remains queryable, but not replay-admissible.
        assert (await privacy_status(db, key, action, kind="withdrawal"))["status"] == "completed"


@pytest.mark.asyncio(loop_scope="module")
async def test_concurrent_consent_single_generation(scratch):
    key, _ = await _partition(scratch, "concurrent")

    async def accept(ident):
        try:
            return await _consent(scratch, key, ident=ident)
        except StoreFenceError as exc:
            return exc.reason

    result = await asyncio.gather(accept(uuid.uuid4()), accept(uuid.uuid4()))
    assert sum(isinstance(item, tuple) for item in result) == 1
    assert "generation_conflict" in result
