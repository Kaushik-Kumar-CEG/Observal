# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Dormant PostgreSQL follow store. Caller owns the transaction and MUST authenticate first.

No route imports this module. All mutations serialize on the full owner partition;
no method here grants consent, checks JWT/Redis, or signs a read cursor.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from models.mobile_follow_sync import SAFE

KEY = "server_id=:server_id AND project_id=:project_id AND owner_id=:owner_id AND cohort=:cohort"
COLS = "server_id, project_id, owner_id, cohort"
VALUES = ":server_id, :project_id, :owner_id, :cohort"


@dataclass(frozen=True)
class Partition:
    server_id: uuid.UUID
    project_id: str
    owner_id: uuid.UUID
    cohort: str

    def params(self) -> dict:
        return vars(self).copy()


class StoreFenceError(Exception):
    """Typed internal refusal; never expose exception text directly to clients."""

    def __init__(self, reason: str, *, owner_generation: int | None = None):
        self.reason = reason
        self.owner_generation = owner_generation
        super().__init__(reason)


async def locked_partition(db: AsyncSession, key: Partition, *, create: bool = False):
    """Call inside a transaction. Concurrent first admissions serialize on the PK."""
    p = key.params()
    if create:
        await db.execute(
            text(f"INSERT INTO mobile_follow_partitions ({COLS}) VALUES ({VALUES}) ON CONFLICT DO NOTHING"), p
        )
    row = (
        (await db.execute(text(f"SELECT * FROM mobile_follow_partitions WHERE {KEY} FOR UPDATE"), p)).mappings().first()
    )
    if row is None:
        raise StoreFenceError("unavailable")
    return row


async def _clock(db: AsyncSession):
    return await db.scalar(text("SELECT clock_timestamp()"))


async def _expire(db: AsyncSession, p: dict, now):
    # Expiry is strictly after the whole 90 days; never shorten an admitted status.
    await db.execute(text(f"DELETE FROM mobile_follow_operations WHERE {KEY} AND expires_at<=:now"), {**p, "now": now})
    await db.execute(text(f"DELETE FROM mobile_follow_changes WHERE {KEY} AND expires_at<=:now"), {**p, "now": now})
    await db.execute(text(f"DELETE FROM mobile_follow_leases WHERE {KEY} AND expires_at<=:now"), {**p, "now": now})
    normal, reserved, history, pins = (
        await db.execute(
            text(f"""
        SELECT (SELECT count(*) FROM mobile_follow_operations WHERE {KEY} AND lane='normal'),
               (SELECT count(*) FROM mobile_follow_operations WHERE {KEY} AND lane='reserved'),
               (SELECT coalesce(sum(logical_bytes),0) FROM mobile_follow_operations WHERE {KEY}) +
               (SELECT coalesce(sum(logical_bytes),0) FROM mobile_follow_changes WHERE {KEY}),
               (SELECT coalesce(sum(logical_bytes),0) FROM mobile_follow_leases WHERE {KEY}) +
               (SELECT coalesce(sum(logical_bytes),0) FROM mobile_follow_pins WHERE {KEY})
    """),
            p,
        )
    ).one()
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET normal_outcomes=:normal,
        reserved_outcomes=:reserved, history_bytes=:history, pin_bytes=:pins WHERE {KEY}"""),
        {**p, "normal": normal, "reserved": reserved, "history": history, "pins": pins},
    )
    return normal, reserved, history, pins


async def admit_operation(
    db: AsyncSession,
    key: Partition,
    *,
    operation_id: uuid.UUID,
    subject_id: uuid.UUID,
    owner_generation: int,
    base_person_revision: int,
    action: str,
    body_digest: bytes,
) -> tuple[int, dict]:
    """Admit exactly one edit or durable conflict. Requires caller-verified write authority.

    All writes, quota checks, and returned outcomes commit/rollback with caller transaction.
    A store refusal is NOT a wire response. Only the caller can validate the grant.
    """
    if action not in ("follow", "unfollow") or len(body_digest) != 32 or not 0 <= base_person_revision <= SAFE:
        raise StoreFenceError("invalid_request")
    # The users DELETE trigger holds the subject row before locking affected
    # partitions. Take the subject KEY SHARE lock first, or owner -> subject
    # against DELETE's subject -> owner order can deadlock. Callers that already
    # locked the owner must release and re-prove authority after this lock.
    provider = await db.scalar(
        text("SELECT auth_provider FROM users WHERE id=:subject FOR KEY SHARE"), {"subject": subject_id}
    )
    row = await locked_partition(db, key)
    p = key.params()
    if owner_generation != row["owner_generation"]:
        raise StoreFenceError("generation_conflict", owner_generation=row["owner_generation"])
    if row["consent_state"] != "available" or row["removal_state"] != "none":
        raise StoreFenceError("restricted")
    now = await _clock(db)
    normal, reserved, history, _ = await _expire(db, p, now)
    old = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_operations WHERE {KEY} AND operation_id=:id"),
                {**p, "id": operation_id},
            )
        )
        .mappings()
        .first()
    )
    if old:
        if not old["effective"]:
            raise StoreFenceError(
                "subject_erased" if old["original_generation"] == owner_generation else "generation_conflict"
            )
        if old["body_digest"] != body_digest or old["subject_id"] != subject_id:
            raise StoreFenceError("operation_id_reused")
        return old["original_http_status"], old["outcome"]
    # KEY SHARE blocks deletion through commit; the DELETE trigger subsequently
    # redacts the committed result and invalidates leases.
    if provider is None:
        raise StoreFenceError("subject_unavailable")
    subject = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_subjects WHERE {KEY} AND subject_id=:subject"),
                {**p, "subject": subject_id},
            )
        )
        .mappings()
        .first()
    )
    person = subject["person_revision"] if subject else 0
    following = subject["following"] if subject else False
    if action == "follow" and provider == "deactivated":
        raise StoreFenceError("subject_unavailable")
    # The reserved lane only admits a first successful unfollow of an extant follow.
    lane = "normal" if normal < 10000 else "reserved"
    if lane == "reserved" and not (
        action == "unfollow" and following and base_person_revision == person and reserved < 1000
    ):
        raise StoreFenceError("history_capacity_reached")
    if history + 1024 > 16777216:
        raise StoreFenceError("history_capacity_reached")
    if base_person_revision != person:
        status = 409
        result = {
            "error": "person_conflict",
            "operation_id": str(operation_id),
            "owner_generation": owner_generation,
            "revision": row["current_revision"],
            "person_revision": person,
            "current_following": following,
        }
    elif subject is None and row["subject_count"] >= 1000:
        # Capacity refusal is pre-admission, not an unbounded collection of conflict IDs.
        raise StoreFenceError("capacity_reached")
    else:
        if person == SAFE or row["current_revision"] == SAFE:
            raise StoreFenceError("revision_exhausted")
        status = 200
        person += 1
        revision = row["current_revision"] + 1
        following = action == "follow"
        result = {
            "operation_id": str(operation_id),
            "owner_generation": owner_generation,
            "revision": revision,
            "person_revision": person,
            "status": "applied",
            "subject_id": str(subject_id),
        }
        await db.execute(
            text(f"""INSERT INTO mobile_follow_subjects ({COLS},subject_id,person_revision,following,changed_revision)
            VALUES ({VALUES},:subject,:person,:following,:revision) ON CONFLICT ({COLS},subject_id)
            DO UPDATE SET person_revision=EXCLUDED.person_revision,following=EXCLUDED.following,
                          changed_revision=EXCLUDED.changed_revision"""),
            {**p, "subject": subject_id, "person": person, "following": following, "revision": revision},
        )
        await db.execute(
            text(f"""INSERT INTO mobile_follow_changes ({COLS},owner_generation,revision,ordinal,
            subject_id,person_revision,following,logical_bytes,admitted_at,expires_at)
            VALUES ({VALUES},:generation,:revision,0,:subject,:person,:following,256,:now,CAST(:now AS timestamptz)+interval '90 days')"""),
            {
                **p,
                "generation": owner_generation,
                "revision": revision,
                "subject": subject_id,
                "person": person,
                "following": following,
                "now": now,
            },
        )
        await db.execute(
            text(
                f"UPDATE mobile_follow_partitions SET current_revision=:revision, subject_count=subject_count+:new WHERE {KEY}"
            ),
            {**p, "revision": revision, "new": int(subject is None)},
        )
    await db.execute(
        text(f"""INSERT INTO mobile_follow_operations ({COLS},operation_id,original_generation,
        subject_id,body_digest,original_http_status,outcome,lane,logical_bytes,admitted_at,expires_at)
        VALUES ({VALUES},:id,:generation,:subject,:digest,:status,CAST(:result AS jsonb),:lane,512,:now,CAST(:now AS timestamptz)+interval '90 days')"""),
        {
            **p,
            "id": operation_id,
            "generation": owner_generation,
            "subject": subject_id,
            "digest": body_digest,
            "status": status,
            "result": json.dumps(result),
            "lane": lane,
            "now": now,
        },
    )
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET normal_outcomes=:normal, reserved_outcomes=:reserved,
        history_bytes=:history, updated_at=:now WHERE {KEY}"""),
        {
            **p,
            "normal": normal + (lane == "normal"),
            "reserved": reserved + (lane == "reserved"),
            "history": history + 512 + (256 if status == 200 else 0),
            "now": now,
        },
    )
    return status, result


async def operation_status(db: AsyncSession, key: Partition, operation_id: uuid.UUID):
    """Only for an independently read-authorized caller; never return erased payloads."""
    row = await locked_partition(db, key)
    p = {**key.params(), "id": operation_id}
    old = (
        (await db.execute(text(f"SELECT * FROM mobile_follow_operations WHERE {KEY} AND operation_id=:id"), p))
        .mappings()
        .first()
    )
    if old is None:
        raise StoreFenceError("unknown")
    if old["expires_at"] <= await _clock(db):
        raise StoreFenceError("expired")
    effective = (
        old["effective"]
        and old["original_generation"] == row["owner_generation"]
        and row["consent_state"] == "available"
        and row["removal_state"] == "none"
    )
    return {
        "operation_id": str(operation_id),
        "owner_generation": row["owner_generation"],
        "original_http_status": old["original_http_status"],
        "effective": effective,
        "result": old["outcome"]
        if effective
        else {
            "status": "superseded",
            "reason": "owner_reset" if old["original_generation"] != row["owner_generation"] else "subject_erased",
            "original_owner_generation": old["original_generation"],
            "owner_generation": row["owner_generation"],
        },
    }


async def fence_owner(db: AsyncSession, key: Partition, *, withdrawal: bool = False):
    """Synchronous privacy barrier; no receipt/worker orchestration is supplied here."""
    row = await locked_partition(db, key)
    if row["owner_generation"] >= SAFE or row["erasure_floor"] >= SAFE:
        raise StoreFenceError("revision_exhausted")
    p = key.params()
    await db.execute(
        text(
            f"UPDATE mobile_follow_operations SET effective=false,subject_id=NULL,body_digest=NULL,outcome=NULL WHERE {KEY}"
        ),
        p,
    )
    for table in (
        "mobile_follow_leases",
        "mobile_follow_changes",
        "mobile_follow_subjects",
        "mobile_follow_approvals",
        "mobile_follow_nonces",
    ):
        await db.execute(text(f"DELETE FROM {table} WHERE {KEY}"), p)
    await db.execute(
        text(f"""UPDATE mobile_follow_partitions SET owner_generation=owner_generation+1,
        erasure_floor=erasure_floor+1, subject_count=0, current_revision=0, pin_bytes=0,
        history_bytes=coalesce((SELECT sum(logical_bytes) FROM mobile_follow_operations WHERE {KEY}),0),
        consent_state=:state, updated_at=clock_timestamp() WHERE {KEY}"""),
        {**p, "state": "consent_required" if withdrawal else "restricted"},
    )
    return row["owner_generation"] + 1


async def admit_lease(
    db: AsyncSession,
    key: Partition,
    *,
    kind: str,
    device_id: str | None = None,
    after_revision: int | None = None,
    min_revision: int = 0,
):
    """Pin a bounded image or fixed-upper change stream under the owner lock.

    Caller supplies authenticated device identity and must sign/validate page cursors.
    Returned lease IDs alone are not bearer capabilities.
    """
    if kind not in ("image", "changes") or not 0 <= min_revision <= SAFE:
        raise StoreFenceError("invalid_request")
    if kind == "changes" and (
        not device_id or len(device_id) > 128 or after_revision is None or not 0 <= after_revision <= SAFE
    ):
        raise StoreFenceError("invalid_request")
    if kind == "image" and (device_id is not None or after_revision is not None):
        raise StoreFenceError("invalid_request")
    row = await locked_partition(db, key)
    if row["consent_state"] != "available" or row["removal_state"] != "none":
        raise StoreFenceError("restricted")
    if kind == "image" and row["current_revision"] < min_revision:
        raise StoreFenceError("snapshot_required")
    if kind == "changes" and after_revision > row["current_revision"]:
        raise StoreFenceError("snapshot_required")
    p = key.params()
    now = await _clock(db)
    await _expire(db, p, now)
    leases = (
        (
            await db.execute(
                text(f"SELECT * FROM mobile_follow_leases WHERE {KEY} AND kind=:kind ORDER BY slot"),
                {**p, "kind": kind},
            )
        )
        .mappings()
        .all()
    )
    for lease in leases:
        if lease["owner_generation"] != row["owner_generation"] or lease["erasure_floor"] != row["erasure_floor"]:
            continue
        if kind == "image" and lease["pinned_revision"] >= min_revision:
            return lease["lease_id"]
        if kind == "changes" and lease["device_id"] == device_id:
            if lease["after_revision"] == after_revision:
                return lease["lease_id"]
            raise StoreFenceError("snapshot_required")
    slot = next((i for i in (1, 2) if all(lease["slot"] != i for lease in leases)), None)
    if slot is None:
        raise StoreFenceError("unavailable" if kind == "image" else "snapshot_required")
    if kind == "image":
        items = (
            (
                await db.execute(
                    text(f"""SELECT subject_id,person_revision,following FROM mobile_follow_subjects
            WHERE {KEY} AND following=true ORDER BY subject_id LIMIT 1001"""),
                    p,
                )
            )
            .mappings()
            .all()
        )
    else:
        items = (
            (
                await db.execute(
                    text(f"""SELECT subject_id,person_revision,following,revision,ordinal,admitted_at
            FROM mobile_follow_changes WHERE {KEY} AND owner_generation=:gen
            AND revision>:after AND revision<=:upper ORDER BY revision,ordinal LIMIT 1001"""),
                    {**p, "gen": row["owner_generation"], "after": after_revision, "upper": row["current_revision"]},
                )
            )
            .mappings()
            .all()
        )
        if row["current_revision"] > after_revision and (
            not items
            or items[0]["revision"] != after_revision + 1
            or items[0]["admitted_at"] < now - timedelta(days=89)
        ):
            raise StoreFenceError("snapshot_required")
    if len(items) > 1000:
        raise StoreFenceError("snapshot_required")
    if kind == "changes" and len({item["revision"] for item in items}) != row["current_revision"] - after_revision:
        # A subject erasure can remove a revision BETWEEN two retained rows.
        # A first-row check alone would falsely certify a complete checkpoint.
        raise StoreFenceError("snapshot_required")
    size = 128 + len(items) * 256
    if row["pin_bytes"] + size > 2097152:
        raise StoreFenceError("unavailable")
    lease_id = uuid.uuid4()
    await db.execute(
        text(f"""INSERT INTO mobile_follow_leases ({COLS},lease_id,kind,slot,device_id,
        owner_generation,pinned_revision,erasure_floor,after_revision,upper_revision,logical_bytes,row_count,admitted_at,expires_at)
        VALUES ({VALUES},:lease,:kind,:slot,:device,:gen,:revision,:floor,:after,:upper,128,:count,
                :now,CAST(:now AS timestamptz)+interval '15 minutes')"""),
        {
            **p,
            "lease": lease_id,
            "kind": kind,
            "slot": slot,
            "device": device_id,
            "gen": row["owner_generation"],
            "revision": row["current_revision"],
            "floor": row["erasure_floor"],
            "after": after_revision,
            "upper": row["current_revision"] if kind == "changes" else None,
            "count": len(items),
            "now": now,
        },
    )
    for index, item in enumerate(items, 1):
        await db.execute(
            text(f"""INSERT INTO mobile_follow_pins ({COLS},lease_id,row_number,subject_id,
            person_revision,following,revision,ordinal,logical_bytes)
            VALUES ({VALUES},:lease,:index,:subject,:person,:following,:revision,:ordinal,256)"""),
            {
                **p,
                "lease": lease_id,
                "index": index,
                "subject": item["subject_id"],
                "person": item["person_revision"],
                "following": item["following"],
                "revision": item["revision"] if kind == "changes" else None,
                "ordinal": item["ordinal"] if kind == "changes" else None,
            },
        )
    await db.execute(
        text(f"UPDATE mobile_follow_partitions SET pin_bytes=pin_bytes+:size WHERE {KEY}"), {**p, "size": size}
    )
    return lease_id


async def lease_page(
    db: AsyncSession,
    key: Partition,
    lease_id: uuid.UUID,
    *,
    kind: str,
    last_row: int = 0,
    device_id: str | None = None,
    throttle: bool = False,
):
    """Read a fixed 100-row keyset; caller authenticates and validates signed position."""
    if kind not in ("image", "changes") or not 0 <= last_row <= 1000 or last_row % 100:
        raise StoreFenceError("invalid_request")
    row = await locked_partition(db, key)
    p = {**key.params(), "lease": lease_id}
    lease = (
        (await db.execute(text(f"SELECT * FROM mobile_follow_leases WHERE {KEY} AND lease_id=:lease"), p))
        .mappings()
        .first()
    )
    if lease is None or lease["kind"] != kind or (kind == "changes" and lease["device_id"] != device_id):
        raise StoreFenceError("snapshot_required")
    if row["consent_state"] != "available" or row["removal_state"] != "none":
        raise StoreFenceError("restricted")
    if lease["owner_generation"] != row["owner_generation"] or lease["erasure_floor"] != row["erasure_floor"]:
        raise StoreFenceError("snapshot_required")
    if lease["expires_at"] <= await _clock(db):
        raise StoreFenceError("snapshot_required")
    if last_row > lease["row_count"]:
        raise StoreFenceError("invalid_request")
    page_key = last_row // 100
    if throttle:
        inserted = (
            await db.execute(
                text(f"""INSERT INTO mobile_follow_page_throttles
            ({COLS},lease_id,page_key,rate_limited) VALUES ({VALUES},:lease,:page,true)
            ON CONFLICT DO NOTHING RETURNING page_key"""),
                {**p, "page": page_key},
            )
        ).first()
        if inserted:
            raise StoreFenceError("rate_limited")  # caller must COMMIT the durable throttle before responding
    items = (
        (
            await db.execute(
                text(f"""SELECT row_number,subject_id,person_revision,following,revision,ordinal
        FROM mobile_follow_pins WHERE {KEY} AND lease_id=:lease AND row_number>:last
        ORDER BY row_number LIMIT 100"""),
                {**p, "last": last_row},
            )
        )
        .mappings()
        .all()
    )
    end = last_row + len(items)
    return {
        "lease_id": lease_id,
        "owner_generation": lease["owner_generation"],
        "revision": lease["pinned_revision"],
        "erasure_floor": lease["erasure_floor"],
        "upper_revision": lease["upper_revision"],
        "items": [dict(i) for i in items],
        "last_row": end,
        "complete": end == lease["row_count"],
    }
