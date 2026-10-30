# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Two independent server-owned frozen responses over real scratch HTTP/PG18/Redis7.

The client's handling of the replies is not covered. Synthetic generation 8/11
is mapped to fresh generation 2; identities come from the frozen requests.
"""

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from test_follow_http_postgres_redis import bearer, browser
from test_follow_http_postgres_redis import scratch as scratch
from test_follow_vectors_fifth_http import Live, exact
from test_follow_vectors_http_postgres_redis import BY_NAME, GAPS, REPLAYED_SEVENTH
from test_follow_vectors_third_http import seed_thousand

from models.user import UserRole
from services.jwt_service import create_access_token

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="owned PG18/Redis7 required")


def test_seventh_names_accounted():
    assert len(REPLAYED_SEVENTH) == len(set(REPLAYED_SEVENTH)) == 2
    assert set(REPLAYED_SEVENTH) <= BY_NAME.keys()
    assert not set(REPLAYED_SEVENTH) & set(GAPS)


async def authorized(live, owner):
    phone, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    await live.ready(phone)
    consent = await live.post(
        "/consent", browser(desktop), {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
    )
    assert consent.status_code == 200 and consent.json() == {"state": "available", "owner_generation": 2}
    challenge = await live.post("/write-authorization", bearer(phone))
    assert challenge.status_code == 200 and challenge.json()["user_code"]
    approval = await live.post(
        "/write-approval", browser(desktop), {"user_code": challenge.json()["user_code"], "approve": True}
    )
    assert approval.status_code == 200 and approval.json() == {"state": "approved"}
    grant = await live.post("/write-grant", bearer(phone))
    assert grant.status_code == 200 and grant.json()["access_token"]
    return grant.json()["access_token"]


@pytest.mark.asyncio
async def test_generation_conflict_redacts_person_state(scratch):
    url, keys, _, owner, other = scratch
    live = Live(url, keys)
    name = "generation_conflict_409_redacted_no_person_fields"
    try:
        grant = await authorized(live, owner)
        # A valid *current* browser-approved grant, but an intent composed before
        # the owner's generation advanced. The frozen vector omits its request.
        response = await live.post(
            "/operations",
            bearer(grant),
            {
                "operation_id": BY_NAME[name]["body"]["operation_id"],
                "subject_id": str(other),  # a real, extant user in the owned scratch DB
                "owner_generation": 1,
                "base_person_revision": 0,
                "action": "follow",
            },
        )
        exact(name, response, generation=2)
    finally:
        await live.close()


@pytest.mark.asyncio
async def test_thousand_distinct_subjects_refuse_new_import(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    name = "local_1001st_import_is_denied_without_deleting_local"
    try:
        grant = await authorized(live, owner)
        server = await seed_thousand(engine, owner)  # durable quota fixture: exactly 1000 real subjects
        request = {**BY_NAME[name]["request"], "owner_generation": 2}
        async with engine.begin() as conn:
            assert (
                await conn.scalar(
                    text(
                        "SELECT subject_count FROM mobile_follow_partitions WHERE server_id=:server AND owner_id=:owner"
                    ),
                    {"server": server, "owner": owner},
                )
                == 1000
            )
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:id,'seventh-new@scratch.invalid','seventh-new','Fixture','user',clock_timestamp())"
                ),
                {"id": request["subject_id"]},
            )
        response = await live.post("/operations", bearer(grant), request)
        exact(name, response, generation=2)
        async with engine.connect() as conn:
            assert (
                await conn.scalar(
                    text(
                        "SELECT subject_count FROM mobile_follow_partitions WHERE server_id=:server AND owner_id=:owner"
                    ),
                    {"server": server, "owner": owner},
                )
                == 1000
            )
            assert (
                await conn.scalar(
                    text("SELECT count(*) FROM mobile_follow_operations WHERE owner_id=:owner AND operation_id=:id"),
                    {"owner": owner, "id": request["operation_id"]},
                )
                == 0
            )
    finally:
        await live.close()
        await engine.dispose()
