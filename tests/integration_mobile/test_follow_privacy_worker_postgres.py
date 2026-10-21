# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, disposable loopback PostgreSQL checks for the 070 privacy poller."""

import os
import time
import uuid

import pytest
from sqlalchemy import text
from test_follow_privacy_postgres import _consent, _partition
from test_follow_privacy_postgres import scratch as _scratch_fixture

from jobs import mobile_follow_privacy as job
from services.mobile_follow_enablement import WORKER_KEY
from services.mobile_follow_privacy import admit_privacy_action, withdrawal_body_digest

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="loopback scratch PG only")


@pytest.fixture(name="scratch", scope="module")
async def scratch_fixture():
    async for sessions in _scratch_fixture.__wrapped__():
        yield sessions


async def _pending(scratch, project):
    key, _ = await _partition(scratch, project)
    await _consent(scratch, key)
    ident = uuid.uuid4()
    async with scratch.begin() as db:
        await admit_privacy_action(
            db,
            key,
            kind="withdrawal",
            action_id=ident,
            owner_generation=2,
            confirmed_authorized=True,
            body_digest=withdrawal_body_digest(ident, 2),
        )
    return key, ident


async def _status(scratch, ident):
    async with scratch() as db:
        return await db.scalar(
            text("SELECT status FROM mobile_follow_privacy_actions WHERE action_id=:id"), {"id": ident}
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_restart_and_owner_fairness_are_bounded(scratch, monkeypatch):
    monkeypatch.setattr(job, "async_session", scratch)
    monkeypatch.setattr(job, "BATCH_PARTITIONS", 1)
    first, a = await _pending(scratch, "worker-fair-a")
    second, b = await _pending(scratch, "worker-fair-b")
    # Every transaction erases at most 100, even when there is more work.
    async with scratch.begin() as db:
        for key in (first, second):
            await db.execute(
                text("""INSERT INTO mobile_follow_changes
                (server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,
                 person_revision,following,admitted_at,expires_at,logical_bytes)
                SELECT :server_id,:project_id,:owner_id,:cohort,2,i,0,:owner_id,1,true,
                    statement_timestamp(),statement_timestamp()+interval '90 days',1 FROM generate_series(1,205) i"""),
                key.params(),
            )
    ctx = {}
    assert await job.run_mobile_follow_privacy(ctx) == 1
    assert await job.run_mobile_follow_privacy(ctx) == 1
    async with scratch() as db:
        assert (
            await db.scalar(
                text(
                    "SELECT value='running' AND updated_at>clock_timestamp()-interval '90 seconds' "
                    "FROM enterprise_config WHERE key=:key"
                ),
                {"key": WORKER_KEY},
            )
            is True
        )
        for key in (first, second):
            assert (
                await db.scalar(
                    text("SELECT count(*) FROM mobile_follow_changes WHERE owner_id=:owner"), {"owner": key.owner_id}
                )
                == 105
            )
    # Fresh worker process has no scan cursor; committed progress is still durable.
    restarted = {}
    for _ in range(10):
        await job.run_mobile_follow_privacy(restarted)
        if await _status(scratch, a) == await _status(scratch, b) == "completed":
            break
    assert await _status(scratch, a) == await _status(scratch, b) == "completed"
    async with scratch() as db:
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_changes WHERE owner_id IN (:a,:b)"),
                {"a": first.owner_id, "b": second.owner_id},
            )
            == 0
        )


@pytest.mark.asyncio(loop_scope="module")
async def test_default_burst_budget_rotates_without_marking_pending_complete(scratch, monkeypatch):
    monkeypatch.setattr(job, "async_session", scratch)
    assert job.BATCH_PARTITIONS == 128
    # 129 distinct owners force a cursor wrap; this small zero-row fixture
    # measures polling overhead only, NOT 11K rows/owner or 24h capacity.
    actions = [await _pending(scratch, f"worker-burst-{i}") for i in range(129)]
    begin = time.monotonic()
    ctx = {}
    await job.run_mobile_follow_privacy(ctx)
    first_tick = time.monotonic() - begin
    first_statuses = [await _status(scratch, ident) for _, ident in actions]
    assert first_statuses.count("completed") <= 128
    assert first_statuses.count("pending") >= 1
    await job.run_mobile_follow_privacy(ctx)
    final_statuses = [await _status(scratch, ident) for _, ident in actions]
    assert all(status == "completed" for status in final_statuses)
    print(f"local_zero_row_128_partition_tick_seconds={first_tick:.4f}; not_capacity_proof")


@pytest.mark.asyncio(loop_scope="module")
async def test_deadline_failure_and_operator_fence_never_auto_resume(scratch, monkeypatch):
    monkeypatch.setattr(job, "async_session", scratch)
    key, ident = await _pending(scratch, "worker-deadline")
    async with scratch.begin() as db:
        await db.execute(
            text(
                "UPDATE mobile_follow_privacy_actions SET admitted_at=clock_timestamp()-interval '25 hours' WHERE action_id=:id"
            ),
            {"id": ident},
        )
    assert await job.run_mobile_follow_privacy({}) == 0
    assert await _status(scratch, ident) == "needs_operator"
    async with scratch() as db:
        assert (
            await db.scalar(
                text("SELECT removal_state FROM mobile_follow_partitions WHERE owner_id=:owner"),
                {"owner": key.owner_id},
            )
            == "needs_operator"
        )
    assert await job.run_mobile_follow_privacy({}) == 0
    assert await _status(scratch, ident) == "needs_operator"

    other, failed = await _pending(scratch, "worker-sql-failure")
    real = job.erase_batch

    async def interrupted(db, part, action):
        if action == failed:
            await db.execute(
                text("UPDATE mobile_follow_partitions SET subject_count=7 WHERE owner_id=:owner"),
                {"owner": part.owner_id},
            )
            raise RuntimeError("simulated failed transaction")
        return await real(db, part, action)

    monkeypatch.setattr(job, "erase_batch", interrupted)
    await job.run_mobile_follow_privacy({})
    assert await _status(scratch, failed) == "needs_operator"
    async with scratch() as db:
        row = (
            await db.execute(
                text("SELECT subject_count,removal_state FROM mobile_follow_partitions WHERE owner_id=:owner"),
                {"owner": other.owner_id},
            )
        ).one()
        assert row == (0, "needs_operator")  # failed transaction was rolled back
    monkeypatch.setattr(job, "erase_batch", real)
    await job.run_mobile_follow_privacy({})
    assert await _status(scratch, failed) == "needs_operator"


@pytest.mark.asyncio(loop_scope="module")
async def test_scan_cost_uses_partition_key_and_never_mutates_unrelated_users(scratch, monkeypatch):
    monkeypatch.setattr(job, "async_session", scratch)
    key, ident = await _pending(scratch, "worker-cost")
    async with scratch.begin() as db:
        # Historical receipts may be numerous; only the current generation is eligible.
        await db.execute(
            text("""INSERT INTO mobile_follow_privacy_actions
            (server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,original_generation,
             fenced_generation,status,body_digest,admitted_at,expires_at)
            SELECT :server_id,:project_id,:owner_id,:cohort,gen_random_uuid(),'withdrawal',
            'nonce_lookup_90d',1,2,'completed',decode(repeat('00',32),'hex'),statement_timestamp(),
            statement_timestamp()+interval '90 days' FROM generate_series(1,500)"""),
            key.params(),
        )
        plan = "\n".join(
            row[0]
            for row in (
                await db.execute(
                    text("EXPLAIN " + job._CANDIDATES.text),
                    {
                        "has_cursor": False,
                        "owner_id": None,
                        "server_id": None,
                        "project_id": None,
                        "cohort": None,
                        "limit": 16,
                    },
                )
            ).all()
        )
        assert "Limit" in plan and "mobile_follow_partitions" in plan
        assert "mobile_follow_privacy_actions" in plan
        assert await db.scalar(text("SELECT count(*) FROM users WHERE id=:owner"), {"owner": key.owner_id}) == 1
    await job.run_mobile_follow_privacy({})
    assert await _status(scratch, ident) == "completed"
    async with scratch() as db:
        assert await db.scalar(text("SELECT count(*) FROM users WHERE id=:owner"), {"owner": key.owner_id}) == 1
        assert (
            await db.scalar(
                text("SELECT count(*) FROM mobile_follow_privacy_actions WHERE owner_id=:owner"),
                {"owner": key.owner_id},
            )
            == 501
        )
