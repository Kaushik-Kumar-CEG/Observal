# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Minimal phone views. Local following is not an authorization grant."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import apply_visibility_filter, get_current_user, get_db, hidden_unapproved_listing
from api.routes.sessions import _has_admin_trace_access
from models.agent import Agent, AgentVersion
from models.hook import HookListing, HookVersion
from models.mcp import McpListing, McpVersion
from models.prompt import PromptListing, PromptVersion
from models.sandbox import SandboxListing, SandboxVersion
from models.skill import SkillListing, SkillVersion
from models.user import User, is_deleted_account, live_users
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.component_activity import hook_queries, queries, skill_queries
from services.dynamic_settings import get_bool
from services.mobile_usage import SUPPORTED_TYPES, component_usage, usage

router = APIRouter(prefix="/api/v1/mobile", tags=["mobile"])
Scope = Literal["author", "user"]
_MODELS = {
    "mcp": (McpListing, McpVersion, "submitted_by"),
    "skill": (SkillListing, SkillVersion, "submitted_by"),
    "hook": (HookListing, HookVersion, "submitted_by"),
    "agent": (Agent, AgentVersion, "created_by"),
    "prompt": (PromptListing, PromptVersion, "submitted_by"),
    "sandbox": (SandboxListing, SandboxVersion, "submitted_by"),
}


def person(user: User):
    return {"id": str(user.id), "name": user.name or user.username or "Unnamed user", "username": user.username}


async def mobile_user(current_user: User = Depends(get_current_user)):
    if not await get_bool("mobile.enabled"):
        raise HTTPException(403, "Mobile access is off")
    return current_user


async def subject(user_id: UUID, db: AsyncSession, viewer: User):
    if not _has_admin_trace_access(viewer) and user_id != viewer.id:
        raise HTTPException(403, "Account not allowed")
    user = await db.get(User, user_id)
    if not user or is_deleted_account(user):
        raise HTTPException(404, "Person not found")
    return user


async def components(db: AsyncSession, viewer: User, owner: UUID | None):
    result = []
    for kind, (model, version, author_key) in _MODELS.items():
        if owner is None and kind not in SUPPORTED_TYPES:
            continue  # No recorded per-user component evidence for these types.
        author = getattr(model, author_key)
        stmt = (
            select(
                model.id, model.name, author, User.name, User.username, version.status, model.co_authors, model.team_id
            )
            .join(User, User.id == author)
            .outerjoin(version, model.latest_version_id == version.id)
        )
        stmt = apply_visibility_filter(stmt, model, viewer)
        if owner is not None:
            stmt = stmt.where(author == owner)
        for identifier, name, author_id, author_name, username, status, co_authors, team_id in (
            await db.execute(stmt)
        ).all():
            listing = SimpleNamespace(
                id=identifier, submitted_by=author_id, co_authors=co_authors, team_id=team_id, status=status
            )
            if await hidden_unapproved_listing(listing, viewer, db):
                continue
            result.append(
                {
                    "id": str(identifier),
                    "type": kind,
                    "name": name,
                    "author": {
                        "id": str(author_id),
                        "name": author_name or username or "Unnamed user",
                        "username": username,
                    },
                }
            )
    return sorted(result, key=lambda c: (c["name"].casefold(), c["type"], c["id"]))


def period(days: int):
    end = datetime.now(UTC)
    return end - timedelta(days=days), end


def allowed_users(viewer: User, target: User, scope: Scope):
    if scope == "user":
        return [str(target.id)]
    return None if _has_admin_trace_access(viewer) else [str(viewer.id)]


async def measure(items, viewer, target, scope, window):
    try:
        return await usage(
            [(c["type"], c["id"]) for c in items], DEFAULT_PROJECT_ID, window, allowed_users(viewer, target, scope)
        )
    except Exception as error:
        raise HTTPException(503, "Usage temporarily unavailable") from error


@router.get("/capabilities")
async def capabilities():
    return {
        "version": 1,
        "enabled": await get_bool("mobile.enabled"),
        "unit": "sessions",
        "supported_types": list(SUPPORTED_TYPES),
        "supported_harnesses": queries.supported_harnesses(),
        "coverage": {
            "mcp": queries.supported_harnesses(),
            "skill": skill_queries.skill_supported_harnesses(),
            "hook": hook_queries.hook_supported_harnesses(),
        },
        "not_recorded_types": ["agent", "prompt", "sandbox"],
        "limitations": [
            "Skill loads are evidence of loading, not proof of invocation.",
            "Claude Code does not record silent hook successes.",
            "Only verified current component publications count.",
        ],
    }


@router.get("/people")
async def people(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    viewer: User = Depends(mobile_user),
    db: AsyncSession = Depends(get_db),
):
    # Tombstoned users are filtered before pagination (ordinary accounts cannot
    # see directory identities outside their trace scope).
    stmt = select(User).where(live_users()).order_by(User.name, User.id)
    if not _has_admin_trace_access(viewer):
        stmt = stmt.where(User.id == viewer.id)
    users = (await db.scalars(stmt.offset(offset).limit(limit + 1))).all()
    return {"people": [person(u) for u in users[:limit]], "has_more": len(users) > limit}


@router.get("/people/{user_id}/summary")
async def summary(
    user_id: UUID,
    days: int = Query(7, ge=1, le=90),
    viewer: User = Depends(mobile_user),
    db: AsyncSession = Depends(get_db),
):
    target = await subject(user_id, db, viewer)
    window = period(days)
    authored = await components(db, viewer, target.id)
    visible = await components(db, viewer, None)
    return {
        "person": person(target),
        "days": days,
        "author": await measure(authored, viewer, target, "author", window),
        "user": await measure(visible, viewer, target, "user", window),
    }


@router.get("/people/{user_id}/components")
async def breakdown(
    user_id: UUID,
    scope: Scope,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    viewer: User = Depends(mobile_user),
    db: AsyncSession = Depends(get_db),
):
    target = await subject(user_id, db, viewer)
    items = await components(db, viewer, target.id if scope == "author" else None)
    window = period(days)
    try:
        metrics = await component_usage(
            [(c["type"], c["id"]) for c in items], DEFAULT_PROJECT_ID, window, allowed_users(viewer, target, scope)
        )
    except Exception as error:
        raise HTTPException(503, "Usage temporarily unavailable") from error
    if scope == "user":
        items = [c for c in items if (c["type"], c["id"]) in metrics]
    page = items[offset : offset + limit]
    for item in page:
        item["usage"] = metrics.get((item["type"], item["id"]), {"value": None, "state": "not_recorded"})
    return {"components": page, "has_more": len(items) > offset + limit, "days": days}


@router.get("/people/{user_id}/components/{component_type}/{component_id}")
async def detail(
    user_id: UUID,
    component_type: Literal["mcp", "skill", "hook", "agent", "prompt", "sandbox"],
    component_id: UUID,
    scope: Scope,
    days: int = Query(7, ge=1, le=90),
    viewer: User = Depends(mobile_user),
    db: AsyncSession = Depends(get_db),
):
    target = await subject(user_id, db, viewer)
    items = await components(db, viewer, target.id if scope == "author" else None)
    item = next((c for c in items if c["type"] == component_type and c["id"] == str(component_id)), None)
    if item is None:
        raise HTTPException(404, "Component not found")
    item["usage"] = await measure([item], viewer, target, scope, period(days))
    return {"component": item, "days": days}
