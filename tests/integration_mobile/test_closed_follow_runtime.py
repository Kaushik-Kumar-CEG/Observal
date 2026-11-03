# SPDX-FileCopyrightText: 2026 Kaushik Kumar
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Normal JWT/Redis HTTP rollback refuses retained enabled configuration."""

import asyncio
import multiprocessing
import os
import socket

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from tests.integration_mobile.test_follow_http_postgres_redis import REDIS_URL, ROOT, _serve, bearer
from tests.integration_mobile.test_follow_http_postgres_redis import scratch as scratch_fixture

from models.user import UserRole
from services import mobile_follow_enablement as gate
from services.jwt_service import create_access_token

scratch = scratch_fixture
pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="opt-in scratch PG/Redis only")


@pytest.mark.asyncio
async def test_closed_bridge_real_http_cannot_reopen_from_retained_settings(scratch):
    url, key_dir, _redis, owner, other = scratch
    engine = create_async_engine(url)
    async with engine.begin() as db:
        await db.execute(
            text("UPDATE enterprise_config SET value='true' WHERE key=:key"), {"key": gate.AVAILABILITY_KEY}
        )
        for key, value in ((gate.ACK_KEY, gate.ACK_VALUE), (gate.ENABLE_KEY, "true"), (gate.WORKER_KEY, "running")):
            await db.execute(
                text(
                    "INSERT INTO enterprise_config(id,key,value,updated_at) VALUES(gen_random_uuid(),:key,:value,clock_timestamp())"
                ),
                {"key": key, "value": value},
            )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    worker = multiprocessing.get_context("spawn").Process(
        target=_serve,
        args=(sock, url, REDIS_URL, key_dir),
        kwargs={"production": True, "operator_event_sink_stub": True},
    )
    worker.start()
    desktop, _ = create_access_token(owner, UserRole.super_admin)
    phone, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{sock.getsockname()[1]}", timeout=15) as client:
            for _ in range(100):
                try:
                    if (await client.get("/api/v1/config/public")).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert worker.is_alive()
                await asyncio.sleep(0.1)
            else:
                pytest.fail("closed bridge startup failed")
            result = await client.get("/api/v1/admin/mobile-test/status", headers=bearer(desktop))
            assert result.status_code == 200
            state = result.json()
            assert state["follow_sync_runtime_closed"] and state["follow_sync_available"]
            assert (await client.get(ROOT + "/availability", headers=bearer(phone))).status_code == 404
            assert (
                await client.post(
                    "/api/v1/admin/mobile-test/configure",
                    headers=bearer(desktop),
                    json={
                        "server_id": state["installed_server_id"],
                        "available": True,
                    },
                )
            ).status_code == 409
            assert (
                await client.post(
                    "/api/v1/admin/mobile-test/follow-sync",
                    headers=bearer(desktop),
                    json={
                        "server_id": state["server_id"],
                        "author_viewer_id": str(owner),
                        "user_viewer_id": str(other),
                        "cohort_generation": state["generation"],
                        "enabled": True,
                        "acknowledgement": "isolated-disposable-synthetic-only-v1",
                        "owner_decisions_acknowledgement": gate.ACK_VALUE,
                        "review_receipt_sha256": "a" * 64,
                    },
                )
            ).status_code == 409
            disabled = await client.post(
                "/api/v1/admin/mobile-test/configure",
                headers=bearer(desktop),
                json={
                    "server_id": state["installed_server_id"],
                    "available": False,
                },
            )
            assert disabled.status_code == 200
            assert not disabled.json()["follow_sync_available"] and not disabled.json()["follow_sync_operator_enabled"]
            assert (await client.post("/api/v1/admin/mobile-test/revoke", headers=bearer(desktop))).status_code == 200
    finally:
        if worker.is_alive():
            worker.terminate()
        worker.join(timeout=10)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=5)
        sock.close()
        await engine.dispose()
