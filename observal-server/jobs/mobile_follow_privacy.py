# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Bounded 070 follow privacy erasure poller; never an account/DSR eraser.

One partition gets one committed erase_batch step per tick. The keyset rotates
across active partitions even when an owner has many rows or needs operator
attention. Progress is the committed rows, not this process-local scan cursor.
"""

from loguru import logger as optic
from sqlalchemy import text

from database import async_session
from services.mobile_follow_privacy import erase_batch
from services.mobile_follow_store import Partition

BATCH_PARTITIONS = 16
# No schema/index change in 070: root state prunes idle partitions; the
# per-partition action lookup uses its full composite PK prefix (up to the
# bounded 1,000 retained receipts + one current slot).
_CANDIDATES = text("""
    SELECT p.server_id, p.project_id, p.owner_id, p.cohort,
           a.action_id, a.status
    FROM mobile_follow_partitions p
    JOIN LATERAL (
        SELECT action_id, status
        FROM mobile_follow_privacy_actions a
        WHERE a.server_id=p.server_id AND a.project_id=p.project_id
          AND a.owner_id=p.owner_id AND a.cohort=p.cohort
          AND a.fenced_generation=p.owner_generation
          AND a.status IN ('pending','needs_operator')
        LIMIT 1
    ) a ON true
    WHERE p.removal_state IN ('pending','needs_operator')
      AND (NOT :has_cursor OR (p.owner_id, p.server_id, p.project_id, p.cohort)
           > (:owner_id, :server_id, :project_id, :cohort))
    ORDER BY p.owner_id, p.server_id, p.project_id, p.cohort
    LIMIT :limit
""")


async def _candidates(cursor):
    params = {
        "has_cursor": bool(cursor),
        "owner_id": None,
        "server_id": None,
        "project_id": None,
        "cohort": None,
        "limit": BATCH_PARTITIONS,
    }
    if cursor:
        params.update(zip(("owner_id", "server_id", "project_id", "cohort"), cursor, strict=True))
    async with async_session() as db:
        rows = (await db.execute(_CANDIDATES, params)).mappings().all()
        if not rows and cursor:
            params["has_cursor"] = False
            rows = (await db.execute(_CANDIDATES, params)).mappings().all()
    return rows


async def _operator_failure(key: Partition, action_id, *, reason: str) -> None:
    """After a failed step rolls back, keep the fence closed for audited repair."""
    try:
        async with async_session.begin() as db:
            p = {**key.params(), "id": action_id}
            # Serialize with admission/account deletion and never recreate a missing root.
            row = (
                await db.execute(
                    text("""SELECT owner_generation FROM mobile_follow_partitions
                WHERE server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id
                AND cohort=:cohort FOR UPDATE"""),
                    p,
                )
            ).first()
            if row is None:
                return
            updated = await db.execute(
                text("""UPDATE mobile_follow_privacy_actions
                SET status='needs_operator' WHERE server_id=:server_id AND project_id=:project_id
                AND owner_id=:owner_id AND cohort=:cohort AND action_id=:id
                AND fenced_generation=:generation AND status='pending' RETURNING action_id"""),
                {**p, "generation": row.owner_generation},
            )
            if updated.first():
                await db.execute(
                    text("""UPDATE mobile_follow_partitions SET removal_state='needs_operator'
                    WHERE server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id
                    AND cohort=:cohort AND removal_state='pending'"""),
                    p,
                )
                optic.error("mobile follow privacy action {} needs operator: {}", action_id, reason)
    except Exception:
        # Never report success or swallow a failed operator transition.
        optic.exception("mobile follow privacy operator transition failed for action {}", action_id)
        raise


async def run_mobile_follow_privacy(ctx: dict) -> int:
    """Poll at most 16 owner partitions; ≤100 erased rows per transaction.

    needs_operator is observed but never automatically resumed. A restart loses
    only the fairness cursor: each committed erase_batch step remains durable.
    """
    cursor = ctx.get("mobile_follow_privacy_cursor")
    rows = await _candidates(cursor)
    progressed = 0
    for row in rows:
        key = Partition(row["server_id"], row["project_id"], row["owner_id"], row["cohort"])
        ctx["mobile_follow_privacy_cursor"] = (key.owner_id, key.server_id, key.project_id, key.cohort)
        if row["status"] == "needs_operator":
            optic.warning("mobile follow privacy action {} awaits audited operator repair", row["action_id"])
            continue
        try:
            async with async_session.begin() as db:
                result = await erase_batch(db, key, row["action_id"])
        except Exception:
            optic.exception("mobile follow privacy erasure failed for action {}", row["action_id"])
            await _operator_failure(key, row["action_id"], reason="erase_failed")
            continue
        if result["status"] == "needs_operator":
            optic.error("mobile follow privacy action {} missed 24h deadline; needs operator", row["action_id"])
        elif result["status"] == "pending":
            progressed += 1
    return progressed
