# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Frozen capacity 429s, not ordinary per-page throttles, over owned PG18/Redis7."""

import multiprocessing
import os
import socket
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from test_follow_http_postgres_redis import REDIS_URL, ROOT, _serve, bearer, browser, validate_contract
from test_follow_http_postgres_redis import scratch as scratch
from test_follow_vectors_http_postgres_redis import REPLAYED_CAPACITY_429
from test_follow_vectors_third_http import compare, ready, seed_thousand

from models.user import UserRole
from services.jwt_service import create_access_token

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="requires owned PG18/Redis7")


@pytest.mark.asyncio
async def test_frozen_capacity_first_and_tenth_page_429(scratch):
    url, key_dir, _, owner, other = scratch
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
            phone, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a"
            )
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
            await ready(client, phone, worker)
            consent = await client.post(
                ROOT + "/consent",
                headers=browser(desktop),
                json={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1},
            )
            assert consent.status_code == 200
            other_phone, _ = create_access_token(
                other, UserRole.user, client_id="observal-mobile", device_id="other-phone"
            )
            other_desktop, _ = create_access_token(other, UserRole.user, browser_verified=True)
            other_consent = await client.post(
                ROOT + "/consent",
                headers=browser(other_desktop),
                json={"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1},
            )
            assert other_consent.status_code == 200
            ordinary = await client.get(ROOT + "/snapshot?limit=100", headers=bearer(other_phone))
            assert ordinary.status_code == 429 and ordinary.headers["Retry-After"] == "1"
            assert ordinary.json()["error"] == "rate_limited"
            ordinary_retry = await client.get(
                ROOT + "/snapshot?limit=100&cursor=" + ordinary.json()["retry_cursor"],
                headers=bearer(other_phone),
            )
            assert ordinary_retry.status_code == 200 and ordinary_retry.json()["items"] == []
            assert ordinary_retry.json()["read_lease_id"] == ordinary.json()["read_lease_id"]
            server = await seed_thousand(engine, owner)
            first = await client.get(ROOT + "/snapshot?limit=100", headers=bearer(phone))
            result = compare(REPLAYED_CAPACITY_429[0], first, owner, server)
            seen.append(REPLAYED_CAPACITY_429[0])
            lease = result["read_lease_id"]
            cursor = result["retry_cursor"]
            for page_number in range(1, 10):
                if page_number == 5:
                    worker.terminate()
                    worker.join(timeout=10)
                    assert not worker.is_alive()
                    worker = multiprocessing.get_context("spawn").Process(
                        target=_serve, args=(sock, url, REDIS_URL, key_dir)
                    )
                    worker.start()
                    await ready(client, phone, worker)
                path = ROOT + "/snapshot?limit=100&cursor=" + cursor
                page = await client.get(path, headers=bearer(phone))
                if page_number > 1:
                    assert page.status_code == 429 and page.headers["Retry-After"] == "60"
                    assert page.json() == {"error": "rate_limited", "read_lease_id": lease, "retry_cursor": cursor}
                    page = await client.get(path, headers=bearer(phone))
                assert page.status_code == 200, (page_number, page.text)
                assert page.json()["read_lease_id"] == lease
                assert len(page.json()["items"]) == 100 and not page.json()["complete"]
                cursor = page.json()["next_cursor"]
            tenth = await client.get(ROOT + "/snapshot?limit=100&cursor=" + cursor, headers=bearer(phone))
            compare(REPLAYED_CAPACITY_429[1], tenth, owner, server, lease=lease, cursor=cursor)
            seen.append(REPLAYED_CAPACITY_429[1])
            assert tuple(seen) == REPLAYED_CAPACITY_429
            print("REAL_HTTP_VECTOR_PASS", ",".join(seen))
    finally:
        worker.terminate()
        worker.join(timeout=10)
        sock.close()
        await engine.dispose()
        assert not worker.is_alive()
