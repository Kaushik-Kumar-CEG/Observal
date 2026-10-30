# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Signed image cursors must not satisfy a newer minimum on owned PG18/Redis7."""

import multiprocessing
import os
import socket
import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from test_follow_http_postgres_redis import REDIS_URL, ROOT, _serve, bearer, browser, validate_contract
from test_follow_http_postgres_redis import scratch as scratch
from test_follow_vectors_third_http import ready

from models.user import UserRole
from services.jwt_service import create_access_token

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="owned PG18/Redis7 required")


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", ("snapshot", "export"))
async def test_signed_image_cursor_cannot_serve_below_minimum(scratch, purpose):
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
            assert consent.status_code == 200, consent.text
            # Real 101-row image at revision N, to obtain a genuine signed page cursor.
            async with engine.begin() as db:
                server = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
                identity = "('00000000-0000-4000-8000-' || lpad(to_hex(i),12,'0'))::uuid"
                await db.execute(
                    text(f"""INSERT INTO users (id,email,username,name,role,created_at)
                    SELECT {identity},'minimum-'||i||'@scratch.invalid','minimum-'||i,'Minimum','user',clock_timestamp()
                    FROM generate_series(1,101) i""")
                )
                await db.execute(
                    text("""UPDATE mobile_follow_partitions SET current_revision=101,subject_count=101
                    WHERE server_id=:server AND project_id='default' AND owner_id=:owner AND cohort='synthetic-author'"""),
                    {"server": server, "owner": owner},
                )
                await db.execute(
                    text(f"""INSERT INTO mobile_follow_subjects
                    (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
                    SELECT :server,'default',:owner,'synthetic-author',{identity},1,true,i
                    FROM generate_series(1,101) i"""),
                    {"server": server, "owner": owner},
                )

            path = ROOT + f"/{purpose}?limit=100"
            first = await client.get(path, headers=bearer(phone))
            assert first.status_code == 429, first.text
            retry = first.json()["retry_cursor"]
            page = await client.get(path + "&cursor=" + retry, headers=bearer(phone))
            assert page.status_code == 200 and len(page.json()["items"]) == 100, page.text
            assert page.json()["revision"] == 101 and not page.json()["complete"]
            signed = page.json()["next_cursor"]
            assert signed and signed != retry
            assert (await client.get(path + "&cursor=" + signed, headers=bearer(phone))).status_code == 429
            # Revision 102 is not yet committed: same response as a cursorless minimum.
            for suffix in ("", "&cursor=" + signed):
                pending = await client.get(path + "&min_revision=102" + suffix, headers=bearer(phone))
                assert pending.status_code == 503 and pending.json() == {"error": "unavailable"}, pending.text
                assert pending.headers["Retry-After"] == "1"
            async with engine.begin() as db:
                await db.execute(
                    text("""UPDATE mobile_follow_partitions SET current_revision=102
                    WHERE server_id=:server AND project_id='default' AND owner_id=:owner AND cohort='synthetic-author'"""),
                    {"server": server, "owner": owner},
                )
            stale = await client.get(path + "&min_revision=102&cursor=" + signed, headers=bearer(phone))
            assert stale.status_code == 409 and stale.json() == {"error": "snapshot_required"}, stale.text
            assert "items" not in stale.json() and "retry_cursor" not in stale.json()
            # Old cursor still works for its own minimum; the newer minimum must get a new image.
            old = await client.get(path + "&cursor=" + signed, headers=bearer(phone))
            assert old.status_code == 200 and old.json()["revision"] == 101 and len(old.json()["items"]) == 1
            fresh = await client.get(path + "&min_revision=102", headers=bearer(phone))
            assert fresh.status_code == 429 and fresh.json()["read_lease_id"] != first.json()["read_lease_id"]
            fresh_page = await client.get(
                path + "&min_revision=102&cursor=" + fresh.json()["retry_cursor"], headers=bearer(phone)
            )
            assert fresh_page.status_code == 200 and fresh_page.json()["revision"] == 102
            withdrawal = await client.post(
                ROOT + "/consent/withdraw",
                headers=browser(desktop),
                json={"withdrawal_id": str(uuid.uuid4()), "owner_generation": 2, "confirm": True},
            )
            assert withdrawal.status_code == 202, withdrawal.text
            fenced = await client.get(path + "&min_revision=102&cursor=" + signed, headers=bearer(phone))
            assert fenced.status_code == 409 and fenced.json() == {"error": "generation_conflict"}, fenced.text
            assert "items" not in fenced.json() and "retry_cursor" not in fenced.json()
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        sock.close()
        await engine.dispose()
        assert not worker.is_alive()
