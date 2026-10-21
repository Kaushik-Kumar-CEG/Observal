# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant follow privacy persistence. No route imports this module.

The caller owns an explicit transaction and independently verifies owner, current
browser/desktop approval or write authority, confirmation, revocation and Redis.
A boolean passed here is NOT evidence of human presence or an authorization grant.
Commit the transaction before sending a 200/202. Never serialize refusal text.
"""

import hashlib
import json
import uuid
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from models.mobile_follow_sync import SAFE
from services.mobile_follow_store import COLS, KEY, VALUES, Partition, StoreFenceError, locked_partition


def _transaction(db: AsyncSession):
    if not db.in_transaction():
        raise StoreFenceError("transaction_required")


async def _now(db: AsyncSession):
    return await db.scalar(text("SELECT clock_timestamp()"))


async def _expire(db: AsyncSession, p: dict, now):
    await db.execute(text(f"DELETE FROM mobile_follow_consents WHERE {KEY} AND expires_at<=:now"), {**p, "now": now})
    await db.execute(
        text(f"DELETE FROM mobile_follow_privacy_actions WHERE {KEY} AND expires_at<=:now"), {**p, "now": now}
    )
    consents = await db.scalar(text(f"SELECT count(*) FROM mobile_follow_consents WHERE {KEY}"), p)
    receipts = await db.scalar(
        text(f"SELECT count(*) FROM mobile_follow_privacy_actions WHERE {KEY} AND recovery_mode='nonce_lookup_90d'"), p
    )
    await db.execute(
        text(f"UPDATE mobile_follow_partitions SET consent_bindings=:consents,indexed_receipts=:receipts WHERE {KEY}"),
        {**p, "consents": consents, "receipts": receipts},
    )
    return consents, receipts


async def accept_consent(
    db: AsyncSession,
    key: Partition,
    *,
    consent_id: uuid.UUID,
    owner_generation: int,
    body_digest: bytes,
    browser_owner_approved: bool,
) -> dict:
    """Persist a browser-owner-authorized, explicitly confirmed opt-in.

    browser_owner_approved is a precondition supplied by a trusted caller, not
    verified here. No mobile read token may supply that precondition.
    """
    _transaction(db)
    if not browser_owner_approved or not isinstance(consent_id, uuid.UUID) or len(body_digest) != 32:
        raise StoreFenceError("invalid_request")
    row = await locked_partition(db, key, create=True)
    p = key.params()
    now = await _now(db)
    count, _ = await _expire(db, p, now)
    old = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_consents WHERE {KEY} AND consent_id=:id"), {**p, "id": consent_id}
            )
        )
        .mappings()
        .first()
    )
    if old:
        if (
            old["request_generation"] == owner_generation
            and old["body_digest"] == body_digest
            and old["accepted_generation"] == row["owner_generation"]
            and row["consent_state"] == "available"
            and row["removal_state"] == "none"
        ):
            return {
                "consent_id": str(consent_id),
                "owner_generation": old["accepted_generation"],
                "status": "available",
            }
        raise StoreFenceError("generation_conflict")
    if row["owner_generation"] != owner_generation:
        raise StoreFenceError("generation_conflict")
    if row["removal_state"] != "none" or row["consent_state"] != "consent_required":
        raise StoreFenceError("consent_already_available" if row["consent_state"] == "available" else "restricted")
    if count >= 1000:
        raise StoreFenceError("consent_capacity_reached")
    if owner_generation >= SAFE:
        raise StoreFenceError("revision_exhausted")
    await db.execute(
        text(f"""INSERT INTO mobile_follow_consents ({COLS},consent_id,request_generation,
        accepted_generation,body_digest,accepted_at,expires_at)
        VALUES ({VALUES},:id,:gen,:next,:digest,:now,CAST(:now AS timestamptz)+interval '90 days')"""),
        {
            **p,
            "id": consent_id,
            "gen": owner_generation,
            "next": owner_generation + 1,
            "digest": body_digest,
            "now": now,
        },
    )
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET owner_generation=:next,consent_state='available',
        consent_bindings=:count,updated_at=:now WHERE {KEY}"""),
        {**p, "next": owner_generation + 1, "count": count + 1, "now": now},
    )
    return {"consent_id": str(consent_id), "owner_generation": owner_generation + 1, "status": "available"}


def withdrawal_body_digest(withdrawal_id: uuid.UUID, owner_generation: int) -> bytes:
    """SHA256 of the exact confirmed withdrawal fields in canonical JSON form."""
    payload = {"confirm": True, "owner_generation": owner_generation, "withdrawal_id": str(withdrawal_id)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()


def _state(action):
    return {
        "action_id": str(action["action_id"]),
        "owner_generation": action["fenced_generation"],
        "status": action["status"],
        "recovery_mode": action["recovery_mode"],
    }


async def admit_privacy_action(
    db: AsyncSession,
    key: Partition,
    *,
    kind: str,
    action_id: uuid.UUID,
    owner_generation: int,
    confirmed_authorized: bool,
    device_id: str | None = None,
    nonce_digest: bytes | None = None,
    body_digest: bytes | None = None,
) -> dict:
    """Atomically fence all old generations and admit a durable 202 action.

    For removal, the caller must validate/consume the <=120s owner/device nonce
    and current browser-approved write grant before invoking this method. For
    withdrawal it must verify either such a grant or same-owner browser bearer.
    """
    _transaction(db)
    if (
        not confirmed_authorized
        or kind not in ("removal", "withdrawal")
        or not isinstance(action_id, uuid.UUID)
        or (
            kind == "removal"
            and (not device_id or len(device_id) > 128 or nonce_digest is None or len(nonce_digest) != 32)
        )
        or (kind == "removal" and body_digest is not None)
        or (
            kind == "withdrawal"
            and (
                nonce_digest is not None
                or device_id is not None
                or not isinstance(body_digest, bytes)
                or body_digest != withdrawal_body_digest(action_id, owner_generation)
            )
        )
    ):
        raise StoreFenceError("invalid_request")
    row = await locked_partition(db, key)
    p = key.params()
    now = await _now(db)
    _, count = await _expire(db, p, now)
    old = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_privacy_actions WHERE {KEY} AND action_id=:id"),
                {**p, "id": action_id},
            )
        )
        .mappings()
        .first()
    )
    if old:
        if (
            old["kind"] == kind
            and old["original_generation"] == owner_generation
            and old["device_id"] == device_id
            and old["nonce_digest"] == nonce_digest
            and old["body_digest"] == body_digest
            and old["fenced_generation"] == row["owner_generation"]
        ):
            return _state(old)
        raise StoreFenceError("generation_conflict")
    if row["owner_generation"] != owner_generation:
        raise StoreFenceError("generation_conflict")
    if row["removal_state"] != "none" or row["consent_state"] in ("withdrawal_pending", "restricted", "disabled"):
        raise StoreFenceError("restricted")
    if row["owner_generation"] >= SAFE or row["erasure_floor"] >= SAFE:
        raise StoreFenceError("revision_exhausted")
    if kind == "removal":
        nonce = (
            (
                await db.execute(
                    text(f"""SELECT owner_generation,expires_at FROM mobile_follow_nonces WHERE {KEY}
            AND device_id=:device AND nonce_digest=:nonce"""),
                    {**p, "device": device_id, "nonce": nonce_digest},
                )
            )
            .mappings()
            .first()
        )
        if nonce is None or nonce["owner_generation"] != owner_generation or nonce["expires_at"] <= now:
            raise StoreFenceError("invalid_nonce")
    mode = "nonce_lookup_90d" if count < 1000 else "state_only"
    # The partial unique index ensures at most ONE overflow slot, even across kinds.
    await db.execute(text(f"DELETE FROM mobile_follow_privacy_actions WHERE {KEY} AND recovery_mode='state_only'"), p)
    # This synchronous barrier executes before the 202 commits: no old payload,
    # approval or pinned page can escape while the remaining rows are batched.
    await db.execute(
        text(
            f"UPDATE mobile_follow_operations SET effective=false,subject_id=NULL,body_digest=NULL,outcome=NULL WHERE {KEY}"
        ),
        p,
    )
    for table in ("mobile_follow_leases", "mobile_follow_approvals", "mobile_follow_nonces"):
        await db.execute(text(f"DELETE FROM {table} WHERE {KEY}"), p)
    await db.execute(
        text(f"""INSERT INTO mobile_follow_privacy_actions ({COLS},action_id,kind,recovery_mode,
        device_id,nonce_digest,body_digest,original_generation,fenced_generation,status,admitted_at,expires_at)
        VALUES ({VALUES},:id,:kind,:mode,:device,:nonce,:digest,:gen,:next,'pending',:now,
        CASE WHEN CAST(:mode AS varchar)='state_only' THEN NULL ELSE CAST(:now AS timestamptz)+interval '90 days' END)"""),
        {
            **p,
            "id": action_id,
            "kind": kind,
            "mode": mode,
            "device": device_id,
            "nonce": nonce_digest,
            "digest": body_digest,
            "gen": owner_generation,
            "next": owner_generation + 1,
            "now": now,
        },
    )
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET owner_generation=:next,erasure_floor=erasure_floor+1,
        removal_state='pending',consent_state=:state,pin_bytes=0,indexed_receipts=:count,updated_at=:now WHERE {KEY}"""),
        {
            **p,
            "next": owner_generation + 1,
            "state": "withdrawal_pending" if kind == "withdrawal" else "restricted",
            "count": count + (mode == "nonce_lookup_90d"),
            "now": now,
        },
    )
    return {
        "action_id": str(action_id),
        "owner_generation": owner_generation + 1,
        "status": "pending",
        "recovery_mode": mode,
    }


async def privacy_status(db: AsyncSession, key: Partition, action_id: uuid.UUID, *, kind: str) -> dict:
    """Caller must reauthorize owner read or same-owner browser access."""
    _transaction(db)
    row = await locked_partition(db, key)
    p = {**key.params(), "id": action_id, "kind": kind}
    action = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_privacy_actions WHERE {KEY} AND action_id=:id AND kind=:kind"), p
            )
        )
        .mappings()
        .first()
    )
    if action is None or (action["expires_at"] is not None and action["expires_at"] <= await _now(db)):
        raise StoreFenceError("unknown")
    if action["recovery_mode"] == "state_only" and action["fenced_generation"] != row["owner_generation"]:
        raise StoreFenceError("unknown")
    return _state(action)


async def removal_by_nonce(
    db: AsyncSession, key: Partition, *, device_id: str, nonce_digest: bytes, original_generation: int
) -> dict:
    """Caller independently verifies fresh same-owner/device mobile:read first."""
    _transaction(db)
    if not device_id or len(device_id) > 128 or len(nonce_digest) != 32:
        raise StoreFenceError("invalid_request")
    row = await locked_partition(db, key)
    action = (
        (
            await db.execute(
                text(f"""SELECT * FROM mobile_follow_privacy_actions WHERE {KEY}
        AND kind='removal' AND device_id=:device AND nonce_digest=:nonce AND original_generation=:gen"""),
                {**key.params(), "device": device_id, "nonce": nonce_digest, "gen": original_generation},
            )
        )
        .mappings()
        .first()
    )
    if action is None or (action["expires_at"] is not None and action["expires_at"] <= await _now(db)):
        raise StoreFenceError("unknown")
    if action["recovery_mode"] == "state_only" and action["fenced_generation"] != row["owner_generation"]:
        raise StoreFenceError("unknown")
    return _state(action)


async def erase_batch(db: AsyncSession, key: Partition, action_id: uuid.UUID) -> dict:
    """Restartable one-table <=100-row erasure step; commit each step.

    Call again while pending. A 24h missed deadline or SQL failure requires
    audited operator intervention; never claim completion on a failed transaction.
    """
    _transaction(db)
    row = await locked_partition(db, key)
    p = {**key.params(), "id": action_id}
    action = (
        (await db.execute(text(f"SELECT * FROM mobile_follow_privacy_actions WHERE {KEY} AND action_id=:id"), p))
        .mappings()
        .first()
    )
    if action is None or row["owner_generation"] != action["fenced_generation"]:
        raise StoreFenceError("generation_conflict")
    if action["status"] != "pending":
        return _state(action)
    now = await _now(db)
    if now >= action["admitted_at"] + timedelta(hours=24):
        await db.execute(
            text(f"UPDATE mobile_follow_privacy_actions SET status='needs_operator' WHERE {KEY} AND action_id=:id"), p
        )
        await db.execute(text(f"UPDATE mobile_follow_partitions SET removal_state='needs_operator' WHERE {KEY}"), p)
        return {**_state(action), "status": "needs_operator"}
    # Use indexed full-partition PK keys (no OFFSET). Cascades of leases were
    # already purged by the synchronous barrier. A crash only repeats this step.
    tables = [("mobile_follow_changes", "owner_generation,revision,ordinal"), ("mobile_follow_subjects", "subject_id")]
    # Accepted ID/digest bindings remain 90 days even after withdrawal; they
    # never authorize a new generation, but still consume the separate quota.
    for table, column in tables:
        deleted = await db.execute(
            text(f"""DELETE FROM {table} WHERE ctid IN
            (SELECT ctid FROM {table} WHERE {KEY} ORDER BY {column} LIMIT 100) RETURNING 1"""),
            p,
        )
        if deleted.first() is not None:
            # Committed deletions mark progress; reselect the first 100 on restart.
            return _state(action)
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET subject_count=0,current_revision=0,
        history_bytes=coalesce((SELECT sum(logical_bytes) FROM mobile_follow_operations WHERE {KEY}),0),
        removal_state='none',consent_state=:state,updated_at=:now WHERE {KEY}"""),
        {**p, "state": "consent_required" if action["kind"] == "withdrawal" else "available", "now": now},
    )
    await db.execute(
        text(
            f"UPDATE mobile_follow_privacy_actions SET status='completed',worker_cursor=NULL WHERE {KEY} AND action_id=:id"
        ),
        p,
    )
    return {**_state(action), "status": "completed"}


async def expire_privacy_records(db: AsyncSession, key: Partition) -> None:
    """Partition-scoped 90-day GC; caller owns scheduling and transaction."""
    _transaction(db)
    await locked_partition(db, key)
    await _expire(db, key.params(), await _now(db))
