# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fifth-wave frozen cases, replayed only through real socket HTTP and migrated PG18/Redis7."""

import asyncio
import multiprocessing
import os
import socket
import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_follow_http_postgres_redis import REDIS_URL, ROOT, _serve, bearer, browser, validate_contract
from test_follow_http_postgres_redis import scratch as scratch
from test_follow_vectors_http_postgres_redis import BY_NAME, GAPS, REPLAYED_FIFTH

from models.user import UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.jwt_service import create_access_token
from services.mobile_follow_privacy import erase_batch
from services.mobile_follow_store import Partition

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="owned PG18/Redis7 required")

FIFTH = (
    "phone_b_browser_withdraws_after_last_phone_unlinked",
    "phone_b_browser_checks_erasure_after_last_phone_lost",
    "withdrawal_needs_operator_keeps_fence",
    "conflict_same_person_in_new_generation",
)
DELETION_GAPS = (
    "erased_subject_cannot_recreate_in_any_generation",
    "phone_a_same_generation_subject_erasure_denies_original_post_replay",
    "subject_erasure_redacts_same_generation_operation_status",
    "capacity_lease_subject_erasure_revokes_all_versions",
)


def test_fifth_names_accounted():
    assert len(FIFTH) == len(set(FIFTH)) == len(REPLAYED_FIFTH) == 4
    assert set(FIFTH) == set(REPLAYED_FIFTH) <= BY_NAME.keys()
    assert set(DELETION_GAPS) <= GAPS.keys()


def exact(name, response, *, generation=None):
    case = BY_NAME[name]
    assert response.status_code == case["status"], (name, response.status_code, response.text)
    expected = dict(case["body"])
    if generation is not None:
        if "owner_generation" in expected:
            expected["owner_generation"] = generation
        if "owner_generation" in expected.get("result", {}):
            expected["result"] = dict(
                expected["result"], owner_generation=generation, original_owner_generation=generation
            )
    assert response.json() == expected, (name, response.json(), expected)
    for header, value in case.get("headers", {}).items():
        assert response.headers[header] == value, name
    print("REAL_HTTP_VECTOR_PASS", name)


class Live:
    def __init__(self, url, key_dir):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.worker = multiprocessing.get_context("spawn").Process(
            target=_serve, args=(self.sock, url, REDIS_URL, key_dir)
        )
        self.worker.start()
        self.client = httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{self.sock.getsockname()[1]}",
            timeout=30,
            event_hooks={"response": [validate_contract]},
        )

    async def ready(self, token):
        for _ in range(100):
            try:
                if (await self.get("/availability", bearer(token))).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            assert self.worker.is_alive(), self.worker.exitcode
            await asyncio.sleep(0.1)
        pytest.fail("scratch worker not ready")

    async def request(self, method, path, auth, payload=None):
        return await self.client.request(method, ROOT + path, headers=auth, json=payload)

    async def get(self, path, auth):
        return await self.request("GET", path, auth)

    async def post(self, path, auth, payload=None):
        return await self.request("POST", path, auth, payload)

    async def close(self):
        await self.client.aclose()
        if self.worker.is_alive():
            self.worker.terminate()
        self.worker.join(timeout=10)
        if self.worker.is_alive():
            self.worker.kill()
            self.worker.join(timeout=5)
        self.sock.close()


async def finish(engine, owner, action):
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.connect() as conn:
        server = await conn.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
    key = Partition(server, str(DEFAULT_PROJECT_ID), owner, "synthetic-author")
    for _ in range(10):
        async with sessions.begin() as db:
            result = await erase_batch(db, key, uuid.UUID(action))
        if result["status"] in ("completed", "needs_operator"):
            return result["status"]
    pytest.fail("privacy worker never finished")


@pytest.mark.asyncio
async def test_browser_withdrawal_survives_last_phone_loss(scratch):
    url, keys, redis, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    try:
        await live.ready(a)
        consent = await live.post(
            "/consent", browser(desktop), {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
        )
        assert consent.status_code == 200 and consent.json() == {"state": "available", "owner_generation": 2}
        # Unlink the last phone credential; browser authority remains independently verified.
        await redis.set("revoked_mobile_device:phone-a", "1", ex=3600)
        assert (await live.get("/availability", bearer(a))).status_code == 401
        name = FIFTH[0]
        response = await live.post(
            "/consent/withdraw", browser(desktop), {**BY_NAME[name]["request"], "owner_generation": 2}
        )
        exact(name, response, generation=3)
        assert await finish(engine, owner, response.json()["withdrawal_id"]) == "completed"
        name = FIFTH[1]
        exact(
            name,
            await live.get(BY_NAME[name]["path"].removeprefix("/mobile-follow-sync/v1"), browser(desktop)),
            generation=3,
        )
        async with engine.connect() as conn:
            assert (
                await conn.execute(
                    text("SELECT consent_state,removal_state FROM mobile_follow_partitions WHERE owner_id=:owner"),
                    {"owner": owner},
                )
            ).one() == ("consent_required", "none")
    finally:
        await live.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_operator_receipt_retains_privacy_fence(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    try:
        await live.ready(a)
        assert (
            await live.post(
                "/consent", browser(desktop), {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
            )
        ).status_code == 200
        ident = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        response = await live.post(
            "/consent/withdraw", browser(desktop), {"withdrawal_id": ident, "owner_generation": 2, "confirm": True}
        )
        assert response.status_code == 202 and response.json()["state"] == "pending"
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE mobile_follow_privacy_actions SET admitted_at=clock_timestamp()-interval '25 hours' "
                    "WHERE action_id=:id AND owner_id=:owner"
                ),
                {"id": ident, "owner": owner},
            )
        assert await finish(engine, owner, ident) == "needs_operator"
        exact(FIFTH[2], await live.get("/consent/withdrawals/" + ident, bearer(a)), generation=3)
        async with engine.connect() as conn:
            assert (
                await conn.execute(
                    text("SELECT consent_state,removal_state FROM mobile_follow_partitions WHERE owner_id=:owner"),
                    {"owner": owner},
                )
            ).one() == ("withdrawal_pending", "needs_operator")
    finally:
        await live.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_subject_deletion_closes_global_gate_without_claiming_follow_replay(scratch):
    url, keys, _, owner, _ = scratch
    engine = create_async_engine(url)
    live = Live(url, keys)
    a, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
    b, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b")
    desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
    subject = BY_NAME[FIFTH[3]]["request"]["subject_id"]
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO users (id,email,username,name,role,created_at) "
                    "VALUES (:id,'fifth-subject@scratch.invalid','fifth-subject','Subject','user',clock_timestamp())"
                ),
                {"id": subject},
            )
        await live.ready(a)
        assert (
            await live.post(
                "/consent", browser(desktop), {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 1}
            )
        ).status_code == 200
        # Actually cross a privacy generation boundary before creating the
        # committed follow. A same-generation-only conflict is not this vector.
        withdrawn = await live.post(
            "/consent/withdraw",
            browser(desktop),
            {"withdrawal_id": str(uuid.uuid4()), "owner_generation": 2, "confirm": True},
        )
        assert withdrawn.status_code == 202 and withdrawn.json()["owner_generation"] == 3
        assert await finish(engine, owner, withdrawn.json()["withdrawal_id"]) == "completed"
        reconsent = await live.post(
            "/consent",
            browser(desktop),
            {"consent": True, "consent_id": str(uuid.uuid4()), "owner_generation": 3},
        )
        assert reconsent.status_code == 200 and reconsent.json()["owner_generation"] == 4

        async def grant(phone):
            challenge = await live.post("/write-authorization", bearer(phone))
            assert challenge.status_code == 200, challenge.text
            approval = await live.post(
                "/write-approval", browser(desktop), {"user_code": challenge.json()["user_code"], "approve": True}
            )
            assert approval.status_code == 200, approval.text
            issued = await live.post("/write-grant", bearer(phone))
            assert issued.status_code == 200, issued.text
            return bearer(issued.json()["access_token"])

        ga, gb = await grant(a), await grant(b)
        original = {**BY_NAME[DELETION_GAPS[1]]["request"], "owner_generation": 4}
        committed = await live.post("/operations", ga, original)
        assert committed.status_code == 200 and committed.json() == {
            "operation_id": original["operation_id"],
            "owner_generation": 4,
            "revision": 1,
            "person_revision": 1,
            "status": "applied",
            "subject_id": subject,
        }
        name = FIFTH[3]
        exact(
            name, await live.post("/operations", gb, {**BY_NAME[name]["request"], "owner_generation": 4}), generation=4
        )
        # Admit a real pinned snapshot, then prove deletion removes its lease versions.
        first = await live.get("/snapshot?limit=100", bearer(a))
        assert first.status_code == 429 and first.json()["retry_cursor"]
        cursor = first.json()["retry_cursor"]
        assert uuid.UUID(first.json()["read_lease_id"])
        page = await live.get("/snapshot?limit=100&cursor=" + cursor, bearer(a))
        assert page.status_code == 200 and page.json()["items"][0]["subject_id"] == subject
        assert page.json()["read_lease_id"] == first.json()["read_lease_id"]
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM users WHERE id=:id"), {"id": subject})
            assert (
                await conn.scalar(
                    text("SELECT count(*) FROM mobile_follow_leases WHERE owner_id=:owner"), {"owner": owner}
                )
                == 0
            )
        # User deletion closes the global project barrier. Without external purge and
        # operator requalification, follow-specific frozen replies are not reachable.
        async with engine.connect() as conn:
            assert (
                await conn.scalar(
                    text("SELECT blocked FROM mobile_read_controls WHERE project_id=:project"),
                    {"project": str(DEFAULT_PROJECT_ID)},
                )
                is True
            )
        for response in (
            await live.get("/availability", bearer(a)),
            await live.get("/snapshot?limit=100&cursor=" + cursor, bearer(a)),
            await live.post("/operations", ga, original),
            await live.get("/operations/" + original["operation_id"], bearer(a)),
            await live.post("/removals/prepare", ga),
        ):
            assert response.status_code == 403, response.text
        async with engine.connect() as conn:
            assert (
                await conn.scalar(
                    text("SELECT blocked FROM mobile_read_controls WHERE project_id=:project"),
                    {"project": str(DEFAULT_PROJECT_ID)},
                )
                is True
            )
    finally:
        await live.close()
        await engine.dispose()
