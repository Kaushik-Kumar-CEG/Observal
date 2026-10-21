# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Disposable loopback-only QA application. Never imported by production routes."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from api.ratelimit import limiter
from api.routes import auth, config, device_auth, mobile_follow_browser, mobile_follow_read, mobile_follow_write
from config import settings
from database import async_session, engine
from services import dynamic_settings as ds
from services.crypto import init_key_manager
from services.redis import close as close_redis
from services.redis import get_redis


@asynccontextmanager
async def lifespan(_app):
    await ds.load_sync_cache()
    init_key_manager(key_dir=settings.JWT_KEY_DIR, key_password=None)
    yield
    await close_redis()
    await engine.dispose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.state.limiter = limiter
for router in (
    auth.router,
    device_auth.router,
    config.router,
    mobile_follow_read.router,
    mobile_follow_write.router,
    mobile_follow_browser.router,
):
    app.include_router(router)


@app.get("/readyz")
async def ready():
    async with async_session() as db:
        await db.execute(text("SELECT 1"))
    await get_redis().ping()
    return {"status": "ok"}


# The 17 follow endpoints are registered here only; production app_factory/routes remain untouched.
assert len([r for r in app.routes if r.path.startswith("/api/v1/mobile-follow-sync/v1/")]) == 17
