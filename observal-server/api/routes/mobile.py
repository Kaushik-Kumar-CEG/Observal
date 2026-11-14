# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Minimal phone views. Local following is not an authorization grant."""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import apply_visibility_filter, get_current_user, get_db
from api.routes.sessions import _has_admin_trace_access
from models.hook import HookListing
from models.mcp import McpListing
from models.skill import SkillListing
from models.user import User, is_deleted_account
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.component_activity import hook_queries, queries, skill_queries
from services.dynamic_settings import get_bool
from services.mobile_usage import usage

router = APIRouter(prefix="/api/v1/mobile", tags=["mobile"])
Scope = Literal["author", "user"]
_MODELS = {"mcp": McpListing, "skill": SkillListing, "hook": HookListing}


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
    for kind, model in _MODELS.items():
        stmt = select(model.id, model.name, model.submitted_by, User.name, User.username).join(
            User, User.id == model.submitted_by
        )
        stmt = apply_visibility_filter(stmt, model, viewer)
        if owner is not None:
            stmt = stmt.where(model.submitted_by == owner)
        for identifier, name, author_id, author_name, username in (await db.execute(stmt)).all():
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
        "supported_types": list(_MODELS),
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
    stmt = select(User).order_by(User.name, User.id)
    if not _has_admin_trace_access(viewer):
        stmt = stmt.where(User.id == viewer.id)
    users = [u for u in (await db.scalars(stmt)).all() if not is_deleted_account(u)]
    return {"people": [person(u) for u in users[offset : offset + limit]], "has_more": len(users) > offset + limit}


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
    # Include verified zero and unrecorded components, never installs as usage.
    page = items[offset : offset + limit]
    for item in page:
        item["usage"] = await measure([item], viewer, target, scope, window)
    return {"components": page, "has_more": len(items) > offset + limit, "days": days}


@router.get("/people/{user_id}/components/{component_type}/{component_id}")
async def detail(
    user_id: UUID,
    component_type: Literal["mcp", "skill", "hook"],
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
