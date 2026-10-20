# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in disposable PostgreSQL + Redis proof: closed issue gate cannot burn grants."""

import inspect
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.skipif(
    os.getenv("MOBILE_REFRESH_PG_SCRATCH") != "1", reason="isolated loopback PostgreSQL + Redis required"
)


@pytest.mark.asyncio(loop_scope="session")
async def test_real_pg_gate_before_real_redis_swap_and_immutable_expiry(monkeypatch, tmp_path):
    from api.routes import auth, scim
    from models import Base
    from models.enterprise_config import EnterpriseConfig
    from models.user import User, UserRole
    from schemas.auth import RefreshRequest
    from services.crypto import init_key_manager
    from services.jwt_service import MOBILE_CLIENT_ID, decode_refresh_token

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    assert os.environ["MOBILE_REFRESH_REDIS_URL"] == "redis://127.0.0.1:16408/15"
    name = "mobile_refresh_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    engine = None
    cache = Redis.from_url(os.environ["MOBILE_REFRESH_REDIS_URL"], decode_responses=True)
    keys: set[str] = set()
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + name))
            created = True
        target = base.set(database=name)
        engine = create_async_engine(target)
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.run_sync(Base.metadata.create_all)
        env = os.environ.copy()
        env["DATABASE_URL"] = target.render_as_string(hide_password=False)
        for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "head")):
            subprocess.run(
                [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=120
            )
        init_key_manager(key_dir=str(tmp_path / "keys"), key_password=None)
        monkeypatch.setattr(auth, "get_redis", lambda: cache)
        monkeypatch.setattr(scim, "get_redis", lambda: cache)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        user = User(
            id=uuid.uuid4(),
            email="refresh@example.invalid",
            username="refresh_scratch",
            name="Synthetic Refresh",
            role=UserRole.user,
        )
        async with maker() as db:
            db.add(user)
            db.add(EnterpriseConfig(key="mobile.auth_enabled", value="false"))
            db.add(EnterpriseConfig(key="mobile.synthetic_test_enabled", value="false"))
            await db.execute(
                text("UPDATE mobile_read_controls SET source_policy_ready=true WHERE project_id='default'")
            )
            await db.commit()
            _access, original, _ = await auth._issue_tokens(user, client_id=MOBILE_CLIENT_ID, device_id="pg-scratch")
        previous = decode_refresh_token(original)
        previous_key = f"refresh_jti:{previous['jti']}"
        keys.add(previous_key)
        async with maker() as closed:
            with pytest.raises(HTTPException) as denied:
                await inspect.unwrap(auth.refresh_token)(
                    SimpleNamespace(headers={}), RefreshRequest(refresh_token=original), closed
                )
            assert denied.value.status_code == 503
            assert await cache.get(previous_key) == str(user.id)
        async with maker() as enabled:
            await enabled.execute(text("UPDATE enterprise_config SET value='true' WHERE key='mobile.auth_enabled'"))
            await enabled.commit()
        async with maker() as permitted:
            successor = await inspect.unwrap(auth.refresh_token)(
                SimpleNamespace(headers={}), RefreshRequest(refresh_token=original), permitted
            )
            rotated = decode_refresh_token(successor.refresh_token)
            keys.add(f"refresh_jti:{rotated['jti']}")
            assert rotated["exp"] == previous["exp"]
            assert await cache.get(previous_key) is None
            assert await cache.get(f"refresh_jti:{rotated['jti']}") == str(user.id)
            await permitted.commit()
        # Account deactivation is terminal, unlike the reversible project
        # pause. Even a later SCIM re-enable cannot revive the old successor.
        async with maker() as deactivated:
            actor = await deactivated.get(User, user.id)
            actor.auth_provider = "deactivated"
            await scim._fence_account_transition(deactivated, user.id)
            await deactivated.commit()
        async with maker() as reactivated:
            actor = await reactivated.get(User, user.id)
            actor.auth_provider = "scim"
            await scim._fence_account_transition(reactivated, user.id)
            await reactivated.commit()
        async with maker() as denied:
            with pytest.raises(HTTPException) as terminal:
                await inspect.unwrap(auth.refresh_token)(
                    SimpleNamespace(headers={}), RefreshRequest(refresh_token=successor.refresh_token), denied
                )
            assert terminal.value.status_code == 401
            assert await cache.get(f"refresh_jti:{rotated['jti']}") == str(user.id)
    finally:
        if keys:
            await cache.delete(*keys)
        await cache.aclose()
        if engine is not None:
            await engine.dispose()
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"))
        await admin.dispose()
