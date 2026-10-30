# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Third-wave frozen v105 cases: real socket/HTTP, migrated scratch PG18 and Redis7.

Only names printed after an exact schema, status, body and header comparison count.
Synthetic generation 12 maps to the fresh owner's generation 2. Signed cursors,
lease IDs and server identity are learned from the real response, never fabricated.
"""

import asyncio
import multiprocessing
import os
import socket
import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from test_follow_http_postgres_redis import REDIS_URL, ROOT, _serve, bearer, browser, validate_contract
from test_follow_http_postgres_redis import scratch as scratch  # real disposable fixture
from test_follow_vectors_http_postgres_redis import BY_NAME, REPLAYED_THIRD

from models.user import UserRole
from services.jwt_service import create_access_token

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="requires owned PG18/Redis7")

# Every entry must be exercised through its own request and strict comparison.
THIRD_WAVE = (
    "owner_initial_429_lost_retries_cursorless_without_new_pinned_image",
    "phone_b_cursorless_after_phone_a_lost_first_429_reuses_exact_image",
    "capacity_snapshot_page_1_not_authoritative",
    "capacity_snapshot_page_5_after_restart",
    "capacity_snapshot_page_10_after_one_retry",
    "capacity_export_page_1_is_not_full_export",
    "phone_b_concurrent_export_reuses_phone_a_image",
    "capacity_export_page_10_after_restart_and_429",
    "capacity_changes_first_page_pins_fixed_upper",
    "capacity_changes_page_10_fixed_upper_after_restart_and_new_writes",
    "third_device_after_two_distinct_change_slots_uses_snapshot_fallback",
    "delta_older_than_89_days_falls_back_before_admission",
    "two_checkpoint_phone_a_changes_pins_upper_1000",
    "two_checkpoint_phone_b_changes_pins_newer_upper_1001",
    "two_checkpoint_phone_a_completes_without_b_starvation",
    "two_checkpoint_phone_b_completes_at_newer_upper",
    "over_1000_change_window_falls_back_before_first_page",
    "capacity_page_at_899_seconds_remains_valid",
    "capacity_lease_at_900_seconds_never_promotes_partial",
    "partial_snapshot_after_24h_must_restart_without_implicit_write",
    "max_safe_json_revision_accepted",
    "revision_increment_at_safe_limit_fails_closed",
)


def test_third_wave_names_are_exactly_accounted():
    assert len(THIRD_WAVE) == len(set(THIRD_WAVE)) == len(REPLAYED_THIRD) == 22
    assert set(THIRD_WAVE) == set(REPLAYED_THIRD) <= BY_NAME.keys()


async def ready(client, token, worker):
    for _ in range(100):
        try:
            if (await client.get(ROOT + "/availability", headers=bearer(token))).status_code == 200:
                return
        except httpx.TransportError:
            pass
        assert worker.is_alive(), worker.exitcode
        await asyncio.sleep(0.1)
    pytest.fail("scratch HTTP worker did not start")


def compare(name, response, owner, server, *, lease=None, cursor=None, generation=2):
    case = BY_NAME[name]
    assert response.status_code == case["status"], (name, response.status_code, response.text[:500])
    actual = response.json()
    expected = dict(case["body"])
    if "owner_generation" in expected:
        expected["owner_generation"] = generation
    if "server_id" in expected:
        expected.update(server_id=str(server), viewer_id=str(owner), cohort="synthetic")
    if "read_lease_id" in expected:
        assert uuid.UUID(actual["read_lease_id"])
        if lease is not None:
            assert actual["read_lease_id"] == lease, name
        expected["read_lease_id"] = actual["read_lease_id"]
    if "retry_cursor" in expected:
        assert actual["retry_cursor"] and "." in actual["retry_cursor"]
        if cursor is not None:
            assert actual["retry_cursor"] == cursor, name
        expected["retry_cursor"] = actual["retry_cursor"]
    if expected.get("next_cursor") is not None:
        assert actual["next_cursor"] and "." in actual["next_cursor"]
        expected["next_cursor"] = actual["next_cursor"]
    assert actual == expected, (name, actual, expected)
    for header, value in case.get("headers", {}).items():
        assert response.headers[header] == value, name
    return actual


async def seed_thousand(engine, owner):
    """One actual owner cohort: 1000 distinct real users, follows and retained changes."""
    async with engine.begin() as conn:
        server = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
        identity = "('00000000-0000-4000-8000-' || lpad(to_hex(i),12,'0'))::uuid"
        await conn.execute(
            text(f"""INSERT INTO users (id,email,username,name,role,created_at)
            SELECT {identity},'third-'||i||'@scratch.invalid','third-'||i,'Third wave','user',clock_timestamp()
            FROM generate_series(1,1000) i""")
        )
        p = {"server": server, "owner": owner}
        await conn.execute(
            text("""UPDATE mobile_follow_partitions SET current_revision=1000,subject_count=1000
            WHERE server_id=:server AND project_id='default' AND owner_id=:owner AND cohort='synthetic-author'"""),
            p,
        )
        await conn.execute(
            text(f"""INSERT INTO mobile_follow_subjects
            (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
            SELECT :server,'default',:owner,'synthetic-author',{identity},1,true,i
            FROM generate_series(1,1000) i"""),
            p,
        )
        await conn.execute(
            text(f"""INSERT INTO mobile_follow_changes
            (server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,
             subject_id,person_revision,following,logical_bytes,admitted_at,expires_at)
            SELECT :server,'default',:owner,'synthetic-author',2,i,0,{identity},1,true,256,
            clock_timestamp(),clock_timestamp()+interval '90 days' FROM generate_series(1,1000) i"""),
            p,
        )
    return server


@pytest.mark.asyncio
async def test_thousand_row_pinned_images_and_change_slots(scratch):
    url, key_dir, _, owner, _ = scratch
    engine = create_async_engine(url)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = multiprocessing.get_context("spawn").Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
    worker.start()
    seen = []
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
            timeout=40,
            event_hooks={"response": [validate_contract]},
        ) as client:
            a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
            b, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b")
            c, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-c")
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
            await ready(client, a, worker)
            consent = await client.post(
                ROOT + "/consent",
                headers=browser(desktop),
                json={
                    "consent": True,
                    "consent_id": str(uuid.uuid4()),
                    "owner_generation": 1,
                },
            )
            assert consent.status_code == 200 and consent.json() == {"state": "available", "owner_generation": 2}
            server = await seed_thousand(engine, owner)

            async def restart():
                nonlocal worker
                worker.terminate()
                worker.join(timeout=10)
                assert not worker.is_alive(), "old HTTP worker must exit before restart"
                worker = multiprocessing.get_context("spawn").Process(
                    target=_serve, args=(sock, url, REDIS_URL, key_dir)
                )
                worker.start()
                await ready(client, a, worker)

            async def check(name, phone, path, *, lease=None, cursor=None):
                response = await client.get(ROOT + path, headers=bearer(phone))
                result = compare(name, response, owner, server, lease=lease, cursor=cursor)
                seen.append(name)
                return result

            first_response = await client.get(ROOT + "/snapshot?limit=100", headers=bearer(a))
            assert first_response.status_code == 429 and 0 < int(first_response.headers["Retry-After"]) <= 60
            first = first_response.json()
            assert first["error"] == "rate_limited" and uuid.UUID(first["read_lease_id"])
            image = first["read_lease_id"]
            retry = first["retry_cursor"]
            # The first 429 body is treated as lost: cursorless retries must reuse the pinned image.
            page = await check(
                "owner_initial_429_lost_retries_cursorless_without_new_pinned_image",
                a,
                "/snapshot?limit=100",
                lease=image,
            )
            await check(
                "phone_b_cursorless_after_phone_a_lost_first_429_reuses_exact_image",
                b,
                "/snapshot?limit=100",
                lease=image,
            )
            await check(
                "capacity_snapshot_page_1_not_authoritative", a, "/snapshot?limit=100&cursor=" + retry, lease=image
            )
            cursor = page["next_cursor"]

            async def page_once(path, phone, *, expected_lease):
                response = await client.get(ROOT + path, headers=bearer(phone))
                if response.status_code == 429:
                    assert response.json()["read_lease_id"] == expected_lease
                    assert 0 < int(response.headers["Retry-After"]) <= 60
                    response = await client.get(ROOT + path, headers=bearer(phone))
                return response

            for index in range(2, 11):
                if index == 5:
                    await restart()
                response = await page_once("/snapshot?limit=100&cursor=" + cursor, a, expected_lease=image)
                assert response.status_code == 200, (index, response.text)
                if index == 10:
                    snapshot_last_cursor = cursor
                if index in (5, 10):
                    name = (
                        "capacity_snapshot_page_5_after_restart"
                        if index == 5
                        else "capacity_snapshot_page_10_after_one_retry"
                    )
                    compare(name, response, owner, server, lease=image)
                    seen.append(name)
                else:
                    assert response.json()["read_lease_id"] == image
                    assert len(response.json()["items"]) == 100
                if index < 10:
                    assert not response.json()["complete"]
                    cursor = response.json()["next_cursor"]

            # Export uses the same durable pinned image with a purpose-specific cursor.
            export = await check("capacity_export_page_1_is_not_full_export", b, "/export?limit=100", lease=image)
            await check("phone_b_concurrent_export_reuses_phone_a_image", b, "/export?limit=100", lease=image)
            cursor = export["next_cursor"]
            for index in range(2, 11):
                if index == 10:
                    await restart()
                response = await page_once("/export?limit=100&cursor=" + cursor, b, expected_lease=image)
                assert response.status_code == 200, (index, response.text)
                if index == 10:
                    compare("capacity_export_page_10_after_restart_and_429", response, owner, server, lease=image)
                    seen.append("capacity_export_page_10_after_restart_and_429")
                else:
                    assert len(response.json()["items"]) == 100 and not response.json()["complete"]
                    cursor = response.json()["next_cursor"]

            # Advance only this scratch lease's database clock, not wall time or other tenants.
            async with engine.begin() as conn:
                await conn.execute(
                    text("""UPDATE mobile_follow_leases SET admitted_at=statement_timestamp()-interval '899 seconds',
                    expires_at=statement_timestamp()+interval '1 second' WHERE lease_id=:lease"""),
                    {"lease": image},
                )
            await check(
                "capacity_page_at_899_seconds_remains_valid",
                a,
                "/snapshot?limit=100&cursor=" + snapshot_last_cursor,
                lease=image,
            )
            async with engine.begin() as conn:
                await conn.execute(
                    text("""UPDATE mobile_follow_leases SET admitted_at=statement_timestamp()-interval '901 seconds',
                    expires_at=statement_timestamp()-interval '1 second' WHERE lease_id=:lease"""),
                    {"lease": image},
                )
            await check(
                "capacity_lease_at_900_seconds_never_promotes_partial",
                a,
                "/snapshot?limit=100&cursor=" + snapshot_last_cursor,
            )
            async with engine.begin() as conn:
                await conn.execute(
                    text("""UPDATE mobile_follow_leases SET admitted_at=statement_timestamp()-interval '24 hours',
                    expires_at=statement_timestamp()-interval '23 hours 45 minutes' WHERE lease_id=:lease"""),
                    {"lease": image},
                )
            await restart()
            await check(
                "partial_snapshot_after_24h_must_restart_without_implicit_write",
                a,
                "/snapshot?limit=100&cursor=" + snapshot_last_cursor,
            )
            # Change streams are separate fixed-upper, device-bound leases.
            change_path = "/changes?owner_generation=2&after_revision=0&limit=100"
            initial = await client.get(ROOT + change_path, headers=bearer(a))
            assert initial.status_code == 429 and 0 < int(initial.headers["Retry-After"]) <= 60
            change = await check(
                "capacity_changes_first_page_pins_fixed_upper",
                a,
                change_path + "&cursor=" + initial.json()["retry_cursor"],
            )
            change_lease = change["read_lease_id"]
            cursor = change["next_cursor"]

            async def append_new_change():
                # A fixed lease exists; B later sees one more committed history row.
                async with engine.begin() as conn:
                    await conn.execute(
                        text("""UPDATE mobile_follow_partitions SET current_revision=1001
                        WHERE owner_id=:owner AND cohort='synthetic-author'"""),
                        {"owner": owner},
                    )
                    await conn.execute(
                        text("""INSERT INTO users (id,email,username,name,role,created_at)
                        VALUES ('00000000-0000-4000-8000-0000000003e9','third-1001@scratch.invalid',
                        'third-1001','Third wave','user',clock_timestamp())""")
                    )
                    await conn.execute(
                        text("""DELETE FROM mobile_follow_subjects WHERE owner_id=:owner
                        AND subject_id='00000000-0000-4000-8000-000000000001'"""),
                        {"owner": owner},
                    )
                    await conn.execute(
                        text("""INSERT INTO mobile_follow_subjects
                        (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
                        VALUES (:server,'default',:owner,'synthetic-author',
                        '00000000-0000-4000-8000-0000000003e9',1,true,1001)"""),
                        {"owner": owner, "server": server},
                    )
                    await conn.execute(
                        text("""INSERT INTO mobile_follow_changes
                        (server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,subject_id,
                         person_revision,following,logical_bytes,admitted_at,expires_at)
                        VALUES (:server,'default',:owner,'synthetic-author',2,1001,0,
                         '00000000-0000-4000-8000-0000000003e9',1,true,256,clock_timestamp(),
                         clock_timestamp()+interval '90 days')"""),
                        {"owner": owner, "server": server},
                    )

            a_last_cursor = None
            for index in range(2, 11):
                if index == 10:
                    await append_new_change()
                    await restart()
                response = await page_once(change_path + "&cursor=" + cursor, a, expected_lease=change_lease)
                assert response.status_code == 200, (index, response.text)
                if index == 10:
                    a_last_cursor = cursor
                    compare(
                        "capacity_changes_page_10_fixed_upper_after_restart_and_new_writes",
                        response,
                        owner,
                        server,
                        lease=change_lease,
                    )
                    seen.append("capacity_changes_page_10_fixed_upper_after_restart_and_new_writes")
                else:
                    assert len(response.json()["changes"]) == 100 and not response.json()["complete"]
                    cursor = response.json()["next_cursor"]
            await check("two_checkpoint_phone_a_changes_pins_upper_1000", a, change_path, lease=change_lease)
            # A's upper stays 1000 while newly admitted B pins revision 1001.
            b_path = "/changes?owner_generation=2&after_revision=500&limit=100"
            second = await client.get(ROOT + b_path, headers=bearer(b))
            assert second.status_code == 429 and second.json()["read_lease_id"] != change_lease
            b_lease = second.json()["read_lease_id"]
            b_page = await check(
                "two_checkpoint_phone_b_changes_pins_newer_upper_1001",
                b,
                b_path + "&cursor=" + second.json()["retry_cursor"],
                lease=b_lease,
            )
            b_cursor = b_page["next_cursor"]
            await check(
                "two_checkpoint_phone_a_completes_without_b_starvation",
                a,
                change_path + "&cursor=" + a_last_cursor,
                lease=change_lease,
            )
            for index in range(2, 7):
                response = await page_once(b_path + "&cursor=" + b_cursor, b, expected_lease=b_lease)
                assert response.status_code == 200, (index, response.text)
                if index == 6:
                    compare("two_checkpoint_phone_b_completes_at_newer_upper", response, owner, server, lease=b_lease)
                    seen.append("two_checkpoint_phone_b_completes_at_newer_upper")
                else:
                    assert len(response.json()["changes"]) == 100
                    b_cursor = response.json()["next_cursor"]
            await check(
                "third_device_after_two_distinct_change_slots_uses_snapshot_fallback",
                c,
                "/changes?owner_generation=2&after_revision=100&limit=100",
            )
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM mobile_follow_leases WHERE owner_id=:owner AND kind='changes'"), {"owner": owner}
                )
            await check("over_1000_change_window_falls_back_before_first_page", c, change_path)
            async with engine.begin() as conn:
                await conn.execute(
                    text("DELETE FROM mobile_follow_changes WHERE owner_id=:owner AND revision=1001"), {"owner": owner}
                )
                await conn.execute(
                    text("""UPDATE mobile_follow_partitions SET current_revision=1000
                    WHERE owner_id=:owner AND cohort='synthetic-author'"""),
                    {"owner": owner},
                )
                await conn.execute(
                    text("""UPDATE mobile_follow_changes SET admitted_at=clock_timestamp()-interval '90 days'
                    WHERE owner_id=:owner AND cohort='synthetic-author' AND revision=1"""),
                    {"owner": owner},
                )
            await check("delta_older_than_89_days_falls_back_before_admission", b, change_path)
            assert set(seen) == set(THIRD_WAVE[:-2]) and len(seen) == len(THIRD_WAVE) - 2
            print("REAL_HTTP_VECTOR_PASS", ",".join(seen))
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        sock.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_safe_integer_conflict_and_increment_fence(scratch):
    url, key_dir, _, owner, _ = scratch
    engine = create_async_engine(url)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = multiprocessing.get_context("spawn").Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
    worker.start()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
            timeout=20,
            event_hooks={"response": [validate_contract]},
        ) as client:
            a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
            await ready(client, a, worker)
            result = await client.post(
                ROOT + "/consent",
                headers=browser(desktop),
                json={
                    "consent": True,
                    "consent_id": str(uuid.uuid4()),
                    "owner_generation": 1,
                },
            )
            assert result.status_code == 200
            challenge = await client.post(ROOT + "/write-authorization", headers=bearer(a))
            assert challenge.status_code == 200
            approval = await client.post(
                ROOT + "/write-approval",
                headers=browser(desktop),
                json={
                    "user_code": challenge.json()["user_code"],
                    "approve": True,
                },
            )
            assert approval.status_code == 200
            grant = await client.post(ROOT + "/write-grant", headers=bearer(a))
            assert grant.status_code == 200
            subject = BY_NAME["max_safe_json_revision_accepted"]["request"]["subject_id"]
            async with engine.begin() as conn:
                server = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
                await conn.execute(
                    text("""INSERT INTO users (id,email,username,name,role,created_at)
                    VALUES (:id,'safe@scratch.invalid','safe-subject','Safe limit','user',clock_timestamp())"""),
                    {"id": subject},
                )
                await conn.execute(
                    text("""UPDATE mobile_follow_partitions SET current_revision=9007199254740991,
                    subject_count=1 WHERE owner_id=:owner AND cohort='synthetic-author'"""),
                    {"owner": owner},
                )
                await conn.execute(
                    text("""INSERT INTO mobile_follow_subjects
                    (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
                    VALUES (:server,'default',:owner,'synthetic-author',:subject,9007199254740991,false,9007199254740991)"""),
                    {"server": server, "owner": owner, "subject": subject},
                )
            seen = []
            for name in THIRD_WAVE[-2:]:
                case = BY_NAME[name]
                payload = dict(case["request"], owner_generation=2)
                response = await client.post(
                    ROOT + "/operations", headers=bearer(grant.json()["access_token"]), json=payload
                )
                compare(name, response, owner, server)
                seen.append(name)
            assert seen == list(THIRD_WAVE[-2:])
            print("REAL_HTTP_VECTOR_PASS", ",".join(seen))
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        sock.close()
        await engine.dispose()
