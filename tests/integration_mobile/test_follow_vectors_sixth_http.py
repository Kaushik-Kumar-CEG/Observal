# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Independent 101-change and free snapshot slot: genuine signed HTTP reads."""

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_follow_http_postgres_redis import bearer, browser
from test_follow_http_postgres_redis import scratch as scratch
from test_follow_vectors_fifth_http import Live
from test_follow_vectors_http_postgres_redis import BY_NAME, GAPS, REPLAYED_SIXTH
from test_follow_vectors_third_http import compare, seed_thousand

from models.user import UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.jwt_service import create_access_token
from services.mobile_follow_privacy import erase_batch
from services.mobile_follow_store import Partition

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="owned PG18/Redis7 required")


def test_sixth_names_accounted():
    assert len(REPLAYED_SIXTH) == len(set(REPLAYED_SIXTH)) == 5
    assert set(REPLAYED_SIXTH) <= BY_NAME.keys()
    assert not set(REPLAYED_SIXTH) & set(GAPS)


async def consent(live, mobile, desktop):
    await live.ready(mobile)
    response = await live.post(
        "/consent", browser(desktop), {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
    )
    assert response.status_code == 200 and response.json() == {"state": "available", "owner_generation": 2}


@pytest.mark.asyncio
async def test_independent_101_changes_in_two_real_pages(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    phone, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    try:
        await consent(live, phone, desktop)
        # Populate durable history with the exact frozen distinct-subject ordering;
        # only the read is exercised over HTTP (not a claim of 103 HTTP writes).
        first = BY_NAME[REPLAYED_SIXTH[0]]["body"]["changes"]
        last = BY_NAME[REPLAYED_SIXTH[1]]["body"]["changes"]
        left, right = first[0]["subject_id"], last[0]["subject_id"]
        async with engine.begin() as conn:
            server = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
            ids = [left, right] + [row["subject_id"] for row in first[1:]]
            for index, subject in enumerate(ids):
                await conn.execute(
                    text(
                        "INSERT INTO users (id,email,username,name,role,created_at) "
                        "VALUES (:id,:email,:username,'Fixture','user',clock_timestamp())"
                    ),
                    {"id": subject, "email": f"sixth-{index}@scratch.invalid", "username": f"sixth-{index}"},
                )
            p = {"server": server, "owner": owner}
            await conn.execute(
                text(
                    "UPDATE mobile_follow_partitions SET current_revision=103,subject_count=99 "
                    "WHERE server_id=:server AND project_id='default' AND owner_id=:owner "
                    "AND cohort='synthetic-author'"
                ),
                p,
            )
            for revision, subject in enumerate(ids, 1):
                following = 3 <= revision <= 101
                await conn.execute(
                    text(
                        "INSERT INTO mobile_follow_subjects "
                        "(server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) "
                        "VALUES (:server,'default',:owner,'synthetic-author',:subject,:person,:following,:changed)"
                    ),
                    {
                        **p,
                        "subject": subject,
                        "person": 2 if revision <= 2 else 1,
                        "following": following,
                        "changed": (3 if revision == 1 else 103 if revision == 2 else revision + 1),
                    },
                )
            for revision, subject in ((1, left), (2, right)):
                await conn.execute(
                    text(
                        "INSERT INTO mobile_follow_changes "
                        "(server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,person_revision,following,logical_bytes,admitted_at,expires_at) "
                        "VALUES (:server,'default',:owner,'synthetic-author',2,:revision,0,:subject,1,true,256,clock_timestamp(),clock_timestamp()+interval '90 days')"
                    ),
                    {**p, "revision": revision, "subject": subject},
                )
            for row in first + last:
                await conn.execute(
                    text(
                        "INSERT INTO mobile_follow_changes "
                        "(server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,person_revision,following,logical_bytes,admitted_at,expires_at) "
                        "VALUES (:server,'default',:owner,'synthetic-author',2,:revision,0,:subject,:person,:following,256,clock_timestamp(),clock_timestamp()+interval '90 days')"
                    ),
                    {
                        **p,
                        "revision": row["revision"],
                        "subject": row["subject_id"],
                        "person": row["person_revision"],
                        "following": row["action"] == "follow",
                    },
                )
        path = "/changes?owner_generation=2&after_revision=2&limit=100"
        admitted = await live.get(path, bearer(phone))
        assert admitted.status_code == 429 and admitted.json()["error"] == "rate_limited"
        assert 0 < int(admitted.headers["Retry-After"]) <= 60
        response = await live.get(path + "&cursor=" + admitted.json()["retry_cursor"], bearer(phone))
        page = compare(REPLAYED_SIXTH[0], response, owner, server, lease=admitted.json()["read_lease_id"], generation=2)
        print("REAL_HTTP_VECTOR_PASS", REPLAYED_SIXTH[0])
        cursor = page["next_cursor"]
        assert cursor and "." in cursor and uuid.UUID(page["read_lease_id"])
        response = await live.get(path + "&cursor=" + cursor, bearer(phone))
        if response.status_code == 429:
            assert response.json()["read_lease_id"] == page["read_lease_id"]
            assert 0 < int(response.headers["Retry-After"]) <= 60
            response = await live.get(path + "&cursor=" + cursor, bearer(phone))
        compare(REPLAYED_SIXTH[1], response, owner, server, lease=page["read_lease_id"], generation=2)
        print("REAL_HTTP_VECTOR_PASS", REPLAYED_SIXTH[1])
    finally:
        await live.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_second_snapshot_slot_pins_new_revision(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    b, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    subject = BY_NAME["phone_b_min_rev2_uses_second_free_snapshot_slot_immediately"]["body"]["items"]
    try:
        await consent(live, a, desktop)
        async with engine.begin() as conn:
            server = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
            followed = "55555555-5555-4555-8555-555555555555"
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:subject,'sixth-slot@scratch.invalid','sixth-slot','Fixture','user',clock_timestamp())"
                ),
                {"subject": followed},
            )
            p = {"server": server, "owner": owner, "subject": followed}
            await conn.execute(
                text(
                    "UPDATE mobile_follow_partitions SET current_revision=1,subject_count=1 "
                    "WHERE server_id=:server AND project_id='default' AND owner_id=:owner "
                    "AND cohort='synthetic-author'"
                ),
                p,
            )
            await conn.execute(
                text(
                    "INSERT INTO mobile_follow_subjects "
                    "(server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) "
                    "VALUES (:server,'default',:owner,'synthetic-author',:subject,1,true,1)"
                ),
                p,
            )
            await conn.execute(
                text(
                    "INSERT INTO mobile_follow_changes "
                    "(server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,person_revision,following,logical_bytes,admitted_at,expires_at) "
                    "VALUES (:server,'default',:owner,'synthetic-author',2,1,0,:subject,1,true,256,clock_timestamp(),clock_timestamp()+interval '90 days')"
                ),
                p,
            )
        admitted = await live.get("/snapshot?limit=100", bearer(a))
        assert admitted.status_code == 429 and admitted.json()["error"] == "rate_limited"
        assert 0 < int(admitted.headers["Retry-After"]) <= 60
        pinned = await live.get("/snapshot?limit=100&cursor=" + admitted.json()["retry_cursor"], bearer(a))
        assert pinned.status_code == 200 and pinned.json()["revision"] == 1
        assert pinned.json()["items"] == [{"subject_id": followed, "person_revision": 1}]
        old_lease = pinned.json()["read_lease_id"]
        # Advance durable revision while retaining A's actual pinned rev1 image.
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE mobile_follow_partitions SET current_revision=2,subject_count=0 "
                    "WHERE server_id=:server AND project_id='default' AND owner_id=:owner "
                    "AND cohort='synthetic-author'"
                ),
                p,
            )
            await conn.execute(
                text(
                    "UPDATE mobile_follow_subjects SET person_revision=2,following=false,changed_revision=2 "
                    "WHERE server_id=:server AND project_id='default' AND owner_id=:owner AND subject_id=:subject"
                ),
                p,
            )
            await conn.execute(
                text(
                    "INSERT INTO mobile_follow_changes "
                    "(server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,person_revision,following,logical_bytes,admitted_at,expires_at) "
                    "VALUES (:server,'default',:owner,'synthetic-author',2,2,0,:subject,2,false,256,clock_timestamp(),clock_timestamp()+interval '90 days')"
                ),
                p,
            )
        name = REPLAYED_SIXTH[2]
        path = "/snapshot?limit=100&min_revision=2"
        response = await live.get(path, bearer(b))
        if response.status_code == 429:
            assert response.json()["error"] == "rate_limited"
            assert 0 < int(response.headers["Retry-After"]) <= 60
            new_lease = response.json()["read_lease_id"]
            assert new_lease != old_lease
            response = await live.get(path + "&cursor=" + response.json()["retry_cursor"], bearer(b))
        result = compare(name, response, owner, server, generation=2)
        assert result["items"] == subject == []
        assert result["read_lease_id"] != old_lease
        async with engine.connect() as conn:
            slots = (
                await conn.execute(
                    text(
                        "SELECT slot,pinned_revision FROM mobile_follow_leases "
                        "WHERE owner_id=:owner AND kind='image' ORDER BY slot"
                    ),
                    {"owner": owner},
                )
            ).all()
            assert slots == [(1, 1), (2, 2)]
        print("REAL_HTTP_VECTOR_PASS", name)
    finally:
        await live.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_owner_budget_admits_fresh_first_request(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    try:
        await consent(live, a, desktop)
        server = await seed_thousand(engine, owner)
        initial = await live.get("/snapshot?limit=100", bearer(a))
        assert initial.status_code == 429 and 0 < int(initial.headers["Retry-After"]) <= 60
        old = initial.json()["read_lease_id"]
        assert uuid.UUID(old)
        # Age only the lease in this scratch DB; the production expiration path
        # performs cleanup under the owner lock on the next HTTP request.
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE mobile_follow_leases SET admitted_at=statement_timestamp()-interval '901 seconds', "
                    "expires_at=statement_timestamp()-interval '1 second' WHERE lease_id=:lease"
                ),
                {"lease": old},
            )
        fresh = await live.get("/snapshot?limit=100", bearer(a))
        assert fresh.status_code == 429 and fresh.json()["error"] == "rate_limited"
        assert 0 < int(fresh.headers["Retry-After"]) <= 60
        new = fresh.json()["read_lease_id"]
        assert uuid.UUID(new) and new != old
        name = "owner_budget_released_at_15min_next_first_request_recovers"
        response = await live.get("/snapshot?limit=100&cursor=" + fresh.json()["retry_cursor"], bearer(a))
        result = compare(name, response, owner, server, lease=new, generation=2)
        assert result["revision"] == 1000 and len(result["items"]) == 100
        async with engine.connect() as conn:
            leases = (
                (
                    await conn.execute(
                        text("SELECT lease_id FROM mobile_follow_leases WHERE owner_id=:owner"), {"owner": owner}
                    )
                )
                .scalars()
                .all()
            )
            assert leases == [uuid.UUID(new)]
        print("REAL_HTTP_VECTOR_PASS", name)
    finally:
        await live.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_new_generation_has_own_thousand_subject_cap(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    try:
        await consent(live, a, desktop)
        server = await seed_thousand(engine, owner)
        challenge = await live.post("/write-authorization", bearer(a))
        assert challenge.status_code == 200
        approval = await live.post(
            "/write-approval", browser(desktop), {"user_code": challenge.json()["user_code"], "approve": True}
        )
        assert approval.status_code == 200
        grant = await live.post("/write-grant", bearer(a))
        assert grant.status_code == 200
        prepared = await live.post("/removals/prepare", bearer(grant.json()["access_token"]))
        assert prepared.status_code == 200
        removed = await live.post(
            "/removals",
            bearer(grant.json()["access_token"]),
            {"nonce": prepared.json()["nonce"], "confirm": True, "owner_generation": 2},
        )
        assert removed.status_code == 202 and removed.json()["owner_generation"] == 3
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        key = Partition(server, str(DEFAULT_PROJECT_ID), owner, "synthetic-author")
        completion = None
        for _ in range(40):
            async with sessions.begin() as db:
                completion = await erase_batch(db, key, uuid.UUID(removed.json()["removal_id"]))
            if completion["status"] == "completed":
                break
        assert completion["status"] == "completed", completion
        state = await live.get("/consent/state", browser(desktop))
        assert state.status_code == 200 and state.json()["owner_generation"] == 3
        assert state.json()["state"] == "available"
        # Prove the new generation permits a real HTTP write even though the
        # previous one had 1000 subjects, before filling its own cap.
        first_subject = "66666666-6666-4666-8666-666666666666"
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:subject,'sixth-first@scratch.invalid','sixth-first','Fixture','user',clock_timestamp())"
                ),
                {"subject": first_subject},
            )
        challenge = await live.post("/write-authorization", bearer(a))
        assert challenge.status_code == 200
        assert (
            await live.post(
                "/write-approval", browser(desktop), {"user_code": challenge.json()["user_code"], "approve": True}
            )
        ).status_code == 200
        grant = await live.post("/write-grant", bearer(a))
        assert grant.status_code == 200
        fresh_write = await live.post(
            "/operations",
            bearer(grant.json()["access_token"]),
            {
                "operation_id": str(uuid.uuid4()),
                "subject_id": first_subject,
                "owner_generation": 3,
                "base_person_revision": 0,
                "action": "follow",
            },
        )
        assert fresh_write.status_code == 200 and fresh_write.json()["revision"] == 1
        # Fill the remaining 999 using existing real users, then attempt 1001.
        async with engine.begin() as conn:
            p = {"server": server, "owner": owner}
            await conn.execute(
                text(
                    "UPDATE mobile_follow_partitions SET current_revision=1000,subject_count=1000 "
                    "WHERE server_id=:server AND project_id='default' AND owner_id=:owner "
                    "AND cohort='synthetic-author'"
                ),
                p,
            )
            await conn.execute(
                text(
                    "INSERT INTO mobile_follow_subjects "
                    "(server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision) "
                    "SELECT :server,'default',:owner,'synthetic-author', "
                    "('00000000-0000-4000-8000-' || lpad(to_hex(i),12,'0'))::uuid,1,true,i "
                    "FROM generate_series(1,999) i"
                ),
                p,
            )
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:subject,'sixth-cap@scratch.invalid','sixth-cap','Fixture','user',clock_timestamp())"
                ),
                {"subject": BY_NAME["draft_1000_per_generation_cap_not_lifetime"]["request"]["subject_id"]},
            )
        name = "draft_1000_per_generation_cap_not_lifetime"
        request = {**BY_NAME[name]["request"], "owner_generation": 3}
        response = await live.post("/operations", bearer(grant.json()["access_token"]), request)
        assert response.status_code == BY_NAME[name]["status"], (response.status_code, response.text)
        assert response.json() == {**BY_NAME[name]["body"], "owner_generation": 3}
        for header, value in BY_NAME[name].get("headers", {}).items():
            assert response.headers[header] == value
        print("REAL_HTTP_VECTOR_PASS", name)
    finally:
        await live.close()
        await engine.dispose()
