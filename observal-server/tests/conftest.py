# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for JWT / auth tests."""

import os
import sys
import uuid
from pathlib import Path

import pytest

# Ensure repo root is on sys.path
_repo_root = str(Path(__file__).resolve().parent.parent.parent)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

# Override settings before any app code imports them
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-prod")


@pytest.fixture()
def user_id():
    return str(uuid.uuid4())


@pytest.fixture()
def user_role():
    return "admin"


@pytest.fixture
async def version_review_api(monkeypatch):
    """Real SQLite review state behind the supported review HTTP endpoints."""
    from datetime import UTC, datetime

    import httpx
    from fastapi import FastAPI
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from api.deps import get_current_user, get_db
    from api.routes.reviews import router as review_router
    from models import Base
    from models.agent import Agent, AgentVersion
    from models.mcp import McpListing, McpVersion
    from models.user import User, UserRole
    from services.review.decisions import open_or_push

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        author = User(
            id=uuid.uuid4(), username="author", email="author@example.test", name="Author", role=UserRole.user
        )
        reviewer = User(
            id=uuid.uuid4(), username="reviewer", email="reviewer@example.test", name="Reviewer", role=UserRole.reviewer
        )
        db.add_all([author, reviewer])
        await db.flush()
        agent = Agent(name="Agent", namespace="tests", slug="agent", owner="author", created_by=author.id)
        mcp = McpListing(
            name="MCP", namespace="tests", slug="mcp", category="x", owner="author", submitted_by=author.id
        )
        db.add_all([agent, mcp])
        await db.flush()
        agent_ver = AgentVersion(
            agent_id=agent.id,
            version="1.2.3",
            description="Agent",
            prompt="Help",
            model_name="model",
            released_by=author.id,
            released_at=datetime.now(UTC),
        )
        mcp_ver = McpVersion(
            listing_id=mcp.id,
            version="1.2.3",
            description="MCP",
            url="https://example.test",
            released_by=author.id,
            released_at=datetime.now(UTC),
        )
        db.add_all([agent_ver, mcp_ver])
        await db.flush()
        reviews = {}
        for kind, subject, version in (("agent", agent, agent_ver), ("mcp", mcp, mcp_ver)):
            review = await open_or_push(db, kind, subject, version, author.id)
            reviews[kind] = (review.number, subject.id, version.id)
        await db.commit()

    app = FastAPI()
    app.include_router(review_router)
    current = [reviewer]

    async def db_dep():
        async with factory() as db:
            yield db

    async def silent(*args, **kwargs):
        return []

    async def checks_off():
        return False

    app.dependency_overrides[get_db] = db_dep
    app.dependency_overrides[get_current_user] = lambda: current[0]
    monkeypatch.setattr("services.review.check_config.enabled", checks_off)
    monkeypatch.setattr("services.review.notifications.deliver", silent)
    monkeypatch.setattr("api.routes.reviews.actions.notify_update", silent)
    monkeypatch.setattr("api.routes.reviews.submissions.notify_update", silent)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client, reviews, factory
    await engine.dispose()
