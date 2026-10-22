# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real HTTP follow journey; dormant routers are registered ONLY here.

Requires disposable PostgreSQL at 127.0.0.1:15440 and Redis DB 15 at
127.0.0.1:16380. Never calls Flare or registers the production router.
"""

import asyncio
import json
import multiprocessing
import os
import re
import socket
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import jsonschema
import pytest
import yaml
from fastapi import FastAPI
from redis.asyncio import Redis
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.deps import get_db
from api.routes import mobile_follow_browser, mobile_follow_read, mobile_follow_write
from models import Base
from models.user import UserRole
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services import dynamic_settings, mobile_follow_auth, mobile_follow_enablement
from services import redis as redis_service
from services.crypto import init_key_manager
from services.jwt_service import create_access_token
from services.mobile_follow_store import Partition, locked_partition

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_FOLLOW_HTTP_SCRATCH") != "1", reason="opt-in scratch PG/Redis only")
SERVER = Path(__file__).resolve().parents[2] / "observal-server"
ROOT = "/api/v1/mobile-follow-sync/v1"
ORIGIN = "https://127.0.0.1:19443"
REDIS_URL = "redis://127.0.0.1:16380/15"
SPEC_URI = "https://observal.example.test/mobile-follow-sync/1.0.5"
SPEC = yaml.safe_load((SERVER.parent / "contracts/mobile-activity-v1/follow-sync-v105-openapi.yaml").read_text())
REGISTRY = Registry().with_resource(SPEC_URI, Resource(contents=SPEC, specification=DRAFT202012))
OBSERVED = set()


async def validate_contract(response):
    """Validate every real HTTP JSON body against its exact method/path/status response schema."""
    await response.aread()
    path = response.request.url.path.removeprefix("/api/v1")
    for resource, parameter in (
        ("operations", "operation_id"),
        ("removals", "removal_id"),
        ("withdrawals", "withdrawal_id"),
    ):
        path = re.sub(rf"/{resource}/[0-9a-f-]{{36}}$", f"/{resource}/{{{parameter}}}", path)
    operation = SPEC["paths"][path][response.request.method.lower()]
    definition = operation["responses"][str(response.status_code)]
    if "$ref" in definition:
        definition = SPEC["components"]["responses"][definition["$ref"].split("/")[-1]]
    schema = definition["content"]["application/json"]["schema"]
    if "$ref" in schema:
        schema = {"$ref": SPEC_URI + schema["$ref"]}
    jsonschema.Draft202012Validator(schema, registry=REGISTRY, format_checker=jsonschema.FormatChecker()).validate(
        response.json()
    )
    OBSERVED.add((response.request.method, path, response.status_code))


SETTINGS = {
    "mobile.auth_enabled": "true",
    "mobile.synthetic_test_enabled": "true",
    "mobile.synthetic_test_ack": "isolated-disposable-synthetic-only-v1",
    "deployment.public_url": ORIGIN,
    "deployment.frontend_url": ORIGIN,
}


def _app(db_session):
    app = FastAPI()
    for router in (mobile_follow_read.router, mobile_follow_write.router, mobile_follow_browser.router):
        app.include_router(router)
    assert {(next(iter(r.methods)), r.path.removeprefix(ROOT)) for r in app.routes if r.path.startswith(ROOT)} == {
        ("GET", "/availability"),
        ("GET", "/consent/state"),
        ("GET", "/snapshot"),
        ("GET", "/export"),
        ("GET", "/changes"),
        ("GET", "/operations/{operation_id}"),
        ("POST", "/operations"),
        ("POST", "/consent"),
        ("POST", "/consent/withdraw"),
        ("GET", "/consent/withdrawals/{withdrawal_id}"),
        ("POST", "/removals/prepare"),
        ("POST", "/removals"),
        ("POST", "/removals/lookup"),
        ("GET", "/removals/{removal_id}"),
        ("POST", "/write-authorization"),
        ("POST", "/write-approval"),
        ("POST", "/write-grant"),
    }
    app.dependency_overrides[get_db] = db_session  # infrastructure only, not an auth override
    return app


def _serve(sock, url, redis_url, key_dir, *, production=False):
    """Each spawned process has an independent pool, engine and settings cache."""
    import uvicorn

    import database

    engine = create_async_engine(url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    redis = Redis.from_url(redis_url, decode_responses=True)
    database.async_session = sessions
    redis_service.get_redis = lambda: redis
    mobile_follow_auth.get_redis = lambda: redis
    init_key_manager(key_dir=key_dir, key_password=None)

    async def db_session():
        async with sessions() as db:
            yield db

    async def run():
        await dynamic_settings.load_sync_cache()
        if production:
            from routes import include_rest_routes

            os.environ[mobile_follow_enablement.ROUTE_INSTALL_ENV] = "1"
            app = FastAPI()
            include_rest_routes(app)
            app.dependency_overrides[get_db] = db_session
        else:
            app = _app(db_session)
        await uvicorn.Server(uvicorn.Config(app, log_level="warning")).serve(sockets=[sock])
        await redis.aclose()
        await engine.dispose()

    asyncio.run(run())


@pytest.fixture
async def scratch(tmp_path):
    base = make_url(os.environ["DATABASE_URL"])
    assert (base.drivername, base.host, base.port, base.database) == (
        "postgresql+asyncpg",
        "127.0.0.1",
        15440,
        "observal",
    )
    assert os.environ["MOBILE_FOLLOW_REDIS_URL"] == REDIS_URL
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    await redis.ping()
    assert await redis.dbsize() == 0, "Redis /15 must be an empty disposable scratch DB"
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    name = "follow_http_" + uuid.uuid4().hex[:12]
    async with admin.connect() as conn:
        await conn.execute(text("CREATE DATABASE " + name))
    target = base.set(database=name)
    engine = create_async_engine(target)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    owner, other = uuid.uuid4(), uuid.uuid4()
    values = {}
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.run_sync(
                lambda sync: Base.metadata.create_all(
                    sync, tables=[t for t in Base.metadata.sorted_tables if not t.name.startswith("mobile_follow_")]
                )
            )
        env = {**os.environ, "DATABASE_URL": target.render_as_string(hide_password=False)}
        for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "head")):
            result = subprocess.run(
                [sys.executable, "-m", "alembic", *args], cwd=SERVER, env=env, capture_output=True, timeout=180
            )
            assert result.returncode == 0, result.stderr.decode()[-3000:]
        async with sessions.begin() as db:
            server = await db.scalar(text("SELECT server_id FROM mobile_server_identity WHERE singleton=true"))
            assert server is not None
            for uid, role in ((owner, "super_admin"), (other, "user")):
                await db.execute(
                    text(
                        "INSERT INTO users (id,email,username,name,role,created_at) "
                        "VALUES (:id,:email,:username,'Scratch',:role,clock_timestamp())"
                    ),
                    {"id": uid, "email": f"{uid}@scratch.invalid", "username": uid.hex[:20], "role": role},
                )
            await db.execute(
                text(
                    "UPDATE mobile_read_controls SET blocked=false,source_policy_ready=true,"
                    "synthetic_expires_at=clock_timestamp()+interval '1 hour' WHERE project_id=:project"
                ),
                {"project": str(DEFAULT_PROJECT_ID)},
            )
            assert await db.scalar(
                text("SELECT source_policy_ready FROM mobile_read_controls WHERE project_id=:project"),
                {"project": str(DEFAULT_PROJECT_ID)},
            )
            values = {
                **SETTINGS,
                "mobile.synthetic_test_server_id": str(server),
                "mobile.synthetic_test_viewer_id": str(owner),
                "mobile.synthetic_test_self_user_viewer_id": str(other),
            }
            for key, value in values.items():
                await db.execute(
                    text(
                        "INSERT INTO enterprise_config (id,key,value,updated_at) "
                        "VALUES (:id,:key,:value,clock_timestamp())"
                    ),
                    {"id": uuid.uuid4(), "key": key, "value": value},
                )
            for uid, cohort in ((owner, "synthetic-author"), (other, "synthetic-user")):
                await locked_partition(db, Partition(server, str(DEFAULT_PROJECT_ID), uid, cohort), create=True)
        init_key_manager(key_dir=str(tmp_path / "jwt"), key_password=None)
        yield target.render_as_string(hide_password=False), str(tmp_path / "jwt"), redis, owner, other
    finally:
        # Only keys used by this test; never flush Redis or alter the base database.
        await redis.delete(*(f"revoked_user:{uid}" for uid in (owner, other)))
        await redis.delete("revoked_mobile_device:phone-a")
        if values:
            await redis.delete(*(f"settings:{key}" for key in values))
        await redis.aclose()
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"))
        await admin.dispose()


@pytest.mark.asyncio
async def test_production_route_install_stays_closed_until_fresh_owner_and_operator_decisions(scratch):
    url, key_dir, _redis, owner, _other = scratch
    ctx = multiprocessing.get_context("spawn")
    workers, sockets, ports = [], [], []
    try:
        for _ in range(2):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sock.listen(128)
            sockets.append(sock)
            ports.append(sock.getsockname()[1])
            worker = ctx.Process(target=_serve, args=(sock, url, REDIS_URL, key_dir), kwargs={"production": True})
            worker.start()
            workers.append(worker)
        phone, _ = create_access_token(owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a")
        desktop, _ = create_access_token(owner, UserRole.super_admin)
        async with (
            httpx.AsyncClient(base_url=f"http://127.0.0.1:{ports[0]}", timeout=15) as first,
            httpx.AsyncClient(base_url=f"http://127.0.0.1:{ports[1]}", timeout=15) as second,
        ):
            for _ in range(100):
                try:
                    if (await first.get("/api/v1/config/public")).status_code == 200 and (
                        await second.get("/api/v1/config/public")
                    ).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert all(worker.is_alive() for worker in workers), [worker.exitcode for worker in workers]
                await asyncio.sleep(0.1)
            else:
                pytest.fail("normal API worker startup failed")
            for client in (first, second):
                assert (await client.get(ROOT + "/availability", headers=bearer(phone))).status_code == 404
            engine = create_async_engine(url)
            try:
                async with engine.begin() as db:
                    for key, value in (
                        (mobile_follow_enablement.ACK_KEY, mobile_follow_enablement.ACK_VALUE),
                        (mobile_follow_enablement.ENABLE_KEY, "true"),
                        (mobile_follow_enablement.WORKER_KEY, "running"),
                    ):
                        await db.execute(
                            text(
                                "INSERT INTO enterprise_config (id,key,value,updated_at) "
                                "VALUES (:id,:key,:value,clock_timestamp())"
                            ),
                            {"id": uuid.uuid4(), "key": key, "value": value},
                        )
                for client in (first, second):
                    result = await client.get(ROOT + "/availability", headers=bearer(phone))
                    assert result.status_code == 200, (result.status_code, result.text[:200])
                    # A real owner/operator DB gate does not provide user-verifying
                    # browser approval. No normal write challenge or grant can issue.
                    for action in ("write-authorization", "write-approval", "write-grant", "operations", "consent"):
                        header = browser(desktop) if action in {"write-approval", "consent"} else bearer(phone)
                        denied = await client.post(ROOT + "/" + action, headers=header)
                        assert denied.status_code == 403, (action, denied.status_code)
                        assert denied.json() == {"error": "restricted"}
                async with engine.begin() as db:
                    await db.execute(
                        text(
                            "UPDATE enterprise_config SET updated_at=clock_timestamp()-interval '91 seconds' "
                            "WHERE key=:key"
                        ),
                        {"key": mobile_follow_enablement.WORKER_KEY},
                    )
                assert (await first.get(ROOT + "/availability", headers=bearer(phone))).status_code == 404
                async with engine.begin() as db:
                    await db.execute(
                        text("UPDATE enterprise_config SET updated_at=clock_timestamp() WHERE key=:key"),
                        {"key": mobile_follow_enablement.WORKER_KEY},
                    )
                assert (await second.get(ROOT + "/availability", headers=bearer(phone))).status_code == 200
                async with engine.connect() as admitted:
                    await mobile_follow_enablement.require_operator_approval(admitted)

                    async def disable_after_admitted_transaction():
                        async with engine.begin() as editor:
                            await editor.execute(
                                text("UPDATE enterprise_config SET value='false' WHERE key=:key"),
                                {"key": mobile_follow_enablement.ENABLE_KEY},
                            )

                    disable = asyncio.create_task(disable_after_admitted_transaction())
                    await asyncio.sleep(0.15)
                    assert not disable.done(), "operator revocation must wait for admitted transaction commit"
                    await admitted.commit()  # A protected write also commits with this same session.
                    await asyncio.wait_for(disable, 5)
                for client in (first, second):
                    assert (await client.get(ROOT + "/availability", headers=bearer(phone))).status_code == 404
                    assert (await client.post(ROOT + "/write-authorization", headers=bearer(phone))).status_code == 503
            finally:
                await engine.dispose()
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=10)
        for sock in sockets:
            sock.close()


def bearer(token):
    return {"Authorization": "Bearer " + token}


def browser(token):
    return {**bearer(token), "Origin": ORIGIN, "Content-Type": "application/json"}


async def expect(response, status):
    assert response.status_code == status, (response.status_code, response.text[:700])
    return response.json()


@pytest.mark.asyncio
async def test_seventeen_routes_two_real_http_processes(scratch):
    url, key_dir, redis, owner, other = scratch
    OBSERVED.clear()
    # Bind loopback sockets in parent, pass them to separate spawned API workers.
    ctx = multiprocessing.get_context("spawn")
    workers, sockets, ports = [], [], []
    try:
        for _ in range(2):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sock.listen(128)
            sockets.append(sock)
            ports.append(sock.getsockname()[1])
            worker = ctx.Process(target=_serve, args=(sock, url, REDIS_URL, key_dir))
            worker.start()
            workers.append(worker)
        async with (
            httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{ports[0]}", timeout=15, event_hooks={"response": [validate_contract]}
            ) as first,
            httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{ports[1]}", timeout=15, event_hooks={"response": [validate_contract]}
            ) as second,
        ):
            phone_a, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-a"
            )
            phone_b, _ = create_access_token(
                owner, UserRole.super_admin, client_id="observal-mobile", device_id="phone-b"
            )
            other_phone, _ = create_access_token(
                other, UserRole.user, client_id="observal-mobile", device_id="phone-other"
            )
            desktop, _ = create_access_token(owner, UserRole.super_admin, browser_verified=True)
            for _ in range(100):
                try:
                    if (await first.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 200 and (
                        await second.get(ROOT + "/availability", headers=bearer(phone_a))
                    ).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert all(worker.is_alive() for worker in workers), [worker.exitcode for worker in workers]
                await asyncio.sleep(0.1)
            else:
                pytest.fail("both isolated HTTP workers failed to become ready")
            assert (await expect(await first.get(ROOT + "/availability", headers=bearer(phone_a)), 200))[
                "state"
            ] == "consent_required"
            assert (await expect(await second.get(ROOT + "/consent/state", headers=bearer(desktop)), 200))[
                "state"
            ] == "consent_required"
            await expect(
                await first.post(
                    ROOT + "/consent",
                    headers=browser(desktop),
                    json={"consent_id": str(uuid.uuid4()), "owner_generation": 1, "consent": True},
                ),
                200,
            )
            await expect(await first.get(ROOT + "/availability", headers=bearer(other_phone)), 200)
            assert (
                await second.post(
                    ROOT + "/consent",
                    headers=browser(phone_b),
                    json={"consent_id": str(uuid.uuid4()), "owner_generation": 1, "consent": True},
                )
            ).status_code == 401
            challenge = await expect(await first.post(ROOT + "/write-authorization", headers=bearer(phone_a)), 200)
            assert challenge["verification_uri"].startswith(ORIGIN + "/follow/approve?code=")
            await expect(
                await second.post(
                    ROOT + "/write-approval",
                    headers=browser(desktop),
                    json={"user_code": challenge["user_code"], "approve": True},
                ),
                200,
            )
            grant = (await expect(await second.post(ROOT + "/write-grant", headers=bearer(phone_a)), 200))[
                "access_token"
            ]
            assert (await first.post(ROOT + "/write-grant", headers=bearer(phone_a))).status_code == 401
            assert (await first.post(ROOT + "/write-grant", headers=bearer(phone_b))).status_code == 403
            op = str(uuid.uuid4())
            await expect(
                await first.post(
                    ROOT + "/operations",
                    headers=bearer(grant),
                    json={
                        "operation_id": op,
                        "subject_id": str(other),
                        "owner_generation": 2,
                        "base_person_revision": 0,
                        "action": "follow",
                    },
                ),
                200,
            )
            assert (await expect(await second.get(ROOT + "/operations/" + op, headers=bearer(phone_a)), 200))[
                "effective"
            ]
            old_image = await expect(
                await first.get(ROOT + "/snapshot", headers=bearer(phone_a), params={"min_revision": 1}), 429
            )
            old_lease = old_image["read_lease_id"]  # Fixed revision 1 still held by phone A.
            # A separately approved device races on the same subject across processes.
            challenge_b = await expect(await second.post(ROOT + "/write-authorization", headers=bearer(phone_b)), 200)
            await expect(
                await first.post(
                    ROOT + "/write-approval",
                    headers=browser(desktop),
                    json={"user_code": challenge_b["user_code"], "approve": True},
                ),
                200,
            )
            grant_b = (await expect(await first.post(ROOT + "/write-grant", headers=bearer(phone_b)), 200))[
                "access_token"
            ]
            competing = [
                dict(
                    operation_id=str(uuid.uuid4()),
                    subject_id=str(other),
                    owner_generation=2,
                    base_person_revision=1,
                    action="unfollow",
                )
                for _ in range(2)
            ]
            responses = await asyncio.gather(
                first.post(ROOT + "/operations", headers=bearer(grant), json=competing[0]),
                second.post(ROOT + "/operations", headers=bearer(grant_b), json=competing[1]),
            )
            assert sorted(r.status_code for r in responses) == [200, 409]
            for client, token, body, original in zip(
                (second, first), (grant, grant_b), competing, responses, strict=True
            ):
                # Treat the first response as a lost ACK; the durable replay is byte-equivalent.
                replay = await client.post(ROOT + "/operations", headers=bearer(token), json=body)
                assert replay.status_code == original.status_code and replay.json() == original.json()
                historical = await expect(
                    await client.get(ROOT + "/operations/" + body["operation_id"], headers=bearer(phone_a)), 200
                )
                assert historical["effective"] and historical["original_http_status"] == original.status_code
            reused = await second.post(
                ROOT + "/operations", headers=bearer(grant_b), json={**competing[1], "action": "follow"}
            )
            assert (await expect(reused, 409))["error"] == "operation_id_reused"
            fresh_image = await expect(
                await second.get(ROOT + "/snapshot", headers=bearer(phone_b), params={"min_revision": 2}), 429
            )
            assert fresh_image["read_lease_id"] != old_lease
            fresh_page = await expect(
                await first.get(
                    ROOT + "/snapshot",
                    headers=bearer(phone_b),
                    params={"min_revision": 2, "cursor": fresh_image["retry_cursor"]},
                ),
                200,
            )
            assert fresh_page["revision"] == 2 and fresh_page["complete"]
            for route, key in (("snapshot", "items"), ("export", "items"), ("changes", "changes")):
                params = {"after_revision": 0, "owner_generation": 2} if route == "changes" else {}
                initial = await second.get(ROOT + "/" + route, headers=bearer(phone_b), params=params)
                if route in ("snapshot", "export"):  # Existing image leases already consumed first-page 429.
                    page = await expect(initial, 200)
                    if route == "snapshot":
                        old_cursor = fresh_image["retry_cursor"]  # phone B's cursor, invalidated by later erasure.
                else:
                    retry = await expect(initial, 429)
                    assert retry["error"] == "rate_limited" and retry["retry_cursor"]
                    # A lost initial 429 must reuse its durable lease across workers.
                    repeated_response = await first.get(ROOT + "/" + route, headers=bearer(phone_b), params=params)
                    assert repeated_response.status_code in (200, 429)
                    repeated = repeated_response.json()
                    assert repeated["read_lease_id"] == retry["read_lease_id"]
                    if route == "snapshot":
                        old_cursor = retry["retry_cursor"]
                    assert (
                        await expect(
                            await first.get(
                                ROOT + "/" + route,
                                headers=bearer(phone_a),
                                params={**params, "cursor": retry["retry_cursor"]},
                            ),
                            400,
                        )
                    )["error"] == "invalid_request"
                    head, signature = retry["retry_cursor"].rsplit(".", 1)
                    tampered = head + "." + ("A" if signature[0] != "A" else "B") + signature[1:]
                    assert (
                        await expect(
                            await second.get(
                                ROOT + "/" + route, headers=bearer(phone_b), params={**params, "cursor": tampered}
                            ),
                            400,
                        )
                    )["error"] == "invalid_request"
                    page = await expect(
                        await first.get(
                            ROOT + "/" + route,
                            headers=bearer(phone_b),
                            params={**params, "cursor": retry["retry_cursor"]},
                        ),
                        200,
                    )
                assert page[key] or (route in ("snapshot", "export") and page["complete"])
            engine = create_async_engine(url)
            try:
                # The 1001st distinct server subject is refused without a durable ID.
                overflow = uuid.uuid4()
                async with engine.begin() as conn:
                    server_id = await conn.scalar(
                        text("SELECT server_id FROM mobile_server_identity WHERE singleton=true")
                    )
                    await conn.execute(
                        text(
                            "INSERT INTO users (id,email,username,name,role,created_at) "
                            "VALUES (:id,:email,:username,'Scratch','user',clock_timestamp())"
                        ),
                        {"id": overflow, "email": f"{overflow}@scratch.invalid", "username": overflow.hex[:20]},
                    )
                    await conn.execute(
                        text("""INSERT INTO users (id,email,username,name,role,created_at)
                        SELECT md5(('follow-http-cap-'||i)::text)::uuid, 'fhcap'||i||'@scratch.invalid',
                        'fhcap'||i,'Scratch','user',clock_timestamp() FROM generate_series(1,999) i""")
                    )
                    await conn.execute(
                        text("""INSERT INTO mobile_follow_subjects
                        (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
                        SELECT :server,'default',:owner,'synthetic-author',md5(('follow-http-cap-'||i)::text)::uuid,
                        1,true,2 FROM generate_series(1,999) i"""),
                        {"server": server_id, "owner": owner},
                    )
                    await conn.execute(
                        text("""UPDATE mobile_follow_partitions SET subject_count=1000
                        WHERE server_id=:server AND project_id='default' AND owner_id=:owner
                        AND cohort='synthetic-author'"""),
                        {"server": server_id, "owner": owner},
                    )
                overflow_body = dict(
                    operation_id=str(uuid.uuid4()),
                    subject_id=str(overflow),
                    owner_generation=2,
                    base_person_revision=0,
                    action="follow",
                )
                assert (
                    await expect(
                        await second.post(ROOT + "/operations", headers=bearer(grant_b), json=overflow_body), 409
                    )
                )["error"] == "capacity_reached"
                assert (
                    await expect(
                        await first.get(ROOT + "/operations/" + overflow_body["operation_id"], headers=bearer(phone_a)),
                        404,
                    )
                )["error"] == "unknown_operation"
            finally:
                await engine.dispose()
            nonce = (await expect(await first.post(ROOT + "/removals/prepare", headers=bearer(grant)), 200))["nonce"]
            removal = await expect(
                await second.post(
                    ROOT + "/removals",
                    headers=bearer(grant),
                    json={"nonce": nonce, "confirm": True, "owner_generation": 2},
                ),
                202,
            )
            rid = removal["removal_id"]
            assert (
                await expect(
                    await first.post(
                        ROOT + "/removals/lookup",
                        headers=bearer(phone_a),
                        json={"nonce": nonce, "original_owner_generation": 2},
                    ),
                    200,
                )
            )["removal_id"] == rid
            assert (await expect(await second.get(ROOT + "/removals/" + rid, headers=bearer(phone_a)), 200))[
                "state"
            ] == "pending"
            assert (await first.get(ROOT + "/removals/" + rid, headers=bearer(other_phone))).status_code == 404
            assert (await expect(await second.get(ROOT + "/consent/state", headers=bearer(desktop)), 200))[
                "state"
            ] == "withdrawal_pending"
            assert (
                await expect(
                    await first.get(ROOT + "/snapshot", headers=bearer(phone_b), params={"cursor": old_cursor}), 409
                )
            )["error"] == "generation_conflict"
            for body in competing:
                result = await expect(
                    await second.get(ROOT + "/operations/" + body["operation_id"], headers=bearer(phone_b)), 200
                )
                assert not result["effective"] and result["result"]["status"] == "superseded"
            other_desktop, _ = create_access_token(other, UserRole.user)
            await expect(
                await first.post(
                    ROOT + "/consent",
                    headers=browser(other_desktop),
                    json={"consent_id": str(uuid.uuid4()), "owner_generation": 1, "consent": True},
                ),
                200,
            )
            wid = str(uuid.uuid4())
            assert (
                await expect(
                    await second.post(
                        ROOT + "/consent/withdraw",
                        headers=browser(other_desktop),
                        json={"withdrawal_id": wid, "owner_generation": 2, "confirm": True},
                    ),
                    202,
                )
            )["withdrawal_id"] == wid
            assert (
                await expect(await first.get(ROOT + "/consent/withdrawals/" + wid, headers=bearer(other_desktop)), 200)
            )["state"] == "pending"
            withdrawal_body = {"withdrawal_id": wid, "owner_generation": 2, "confirm": True}
            assert (
                await expect(
                    await first.post(ROOT + "/consent/withdraw", headers=browser(other_desktop), json=withdrawal_body),
                    202,
                )
            )["withdrawal_id"] == wid
            changed = await second.post(
                ROOT + "/consent/withdraw",
                headers=browser(other_desktop),
                json={**withdrawal_body, "owner_generation": 3},
            )
            assert (await expect(changed, 409))["error"] == "generation_conflict"
            # A stale pre-removal write must not resurrect the old owner generation.
            stale = await first.post(ROOT + "/operations", headers=bearer(grant), json=competing[0])
            assert (await expect(stale, 401))["error"] == "unauthorized"
            await redis.set(f"revoked_user:{owner}", str(int(datetime.now(UTC).timestamp() * 1_000_000) + 1))
            assert (await first.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 401
            assert (await second.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 401
            assert (await second.get(ROOT + "/availability", headers=bearer(other_phone))).status_code == 200
            await redis.delete(f"revoked_user:{owner}")
            await redis.set("revoked_mobile_device:phone-a", "1")
            assert (await first.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 401
            assert (await second.get(ROOT + "/availability", headers=bearer(phone_a))).status_code == 401
            assert (await second.get(ROOT + "/availability", headers=bearer(phone_b))).status_code == 200
            assert {(method, path) for method, path, status in OBSERVED if status in (200, 202)} == {
                (method.upper(), path)
                for path, operations in SPEC["paths"].items()
                for method, operation in operations.items()
                if any(status in operation["responses"] for status in ("200", "202"))
            }
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=10)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=5)
        for sock in sockets:
            sock.close()


def test_local_quota_and_old_server_are_contract_only_not_http_proofs():
    """There is no Android client here; assert only the separate local policy fixtures."""
    vectors = json.loads((SERVER.parent / "contracts/mobile-activity-v1/follow-sync-v105-vectors.json").read_text())
    cases = {case["name"]: case for case in vectors["cases"]}
    local = cases["local_1001_follow_entries_never_trimmed"]
    assert (local["local_encrypted_count"], local["explicitly_selected_import_count"], local["local_only_count"]) == (
        1001,
        1000,
        1,
    )
    assert "retain_all_1001_local" in local["client_result"]
    denied = cases["local_1001st_import_is_denied_without_deleting_local"]
    assert denied["body"]["error"] == "capacity_reached"
    assert "kept_encrypted_local_only" in denied["client_result"]
    older = cases["availability_404_without_fresh_v12_proof_not_fallback"]
    assert older["status"] == 404 and "not_fallback" in older["name"]
    for name, status in (
        ("old_server_non_json_404_after_fresh_same_issuer_proof", 404),
        ("old_server_non_json_405_after_fresh_same_issuer_proof", 405),
    ):
        case = cases[name]
        assert case["status"] == status and case["credential"] == "fresh_v12_mobile_read"
        assert case["client_result"] == "local_follows_only_sync_unavailable;never_empty_snapshot"
