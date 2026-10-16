# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Allowlisted, uploader-bound v2 identity manifest (not proof of execution)."""

import hashlib
import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db
from api.ratelimit import limiter
from models.hook import HookListing, HookVersion
from models.mcp import ListingStatus, McpListing, McpVersion
from models.skill import SkillListing, SkillVersion
from models.user import User
from observal_shared.migration.constants import DEFAULT_PROJECT_ID

router = APIRouter(prefix="/api/v1/mobile-evidence/v1", tags=["mobile-evidence"])


class ComponentPin(BaseModel):
    id: uuid.UUID
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$")
    alias: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")


class SkillPin(BaseModel):
    id: uuid.UUID
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$")
    alias: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    scope: Literal["user", "project"]
    location_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class HookPin(BaseModel):
    id: uuid.UUID
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$")
    alias: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    scope: Literal["user"]
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LayerRequest(BaseModel):
    harness: Literal["pi"]
    components: list[ComponentPin] = Field(default_factory=list, max_length=100)
    skills: list[SkillPin] = Field(default_factory=list, max_length=100)
    hooks: list[HookPin] = Field(default_factory=list, max_length=100)


class LayerReceipt(BaseModel):
    hash: str
    mapped_components: int


def canonical_layer_hash(
    components: list[ComponentPin], skills: list[SkillPin] | None = None, hooks: list[HookPin] | None = None
) -> str:
    if skills or hooks:
        canonical = sorted(
            [["mcp", str(c.id), c.version, c.alias] for c in components]
            + [
                ["skill", str(s.id), s.version, s.scope, s.alias, s.location_sha256, s.content_sha256]
                for s in (skills or [])
            ]
            + [["hook", str(h.id), h.version, h.scope, h.alias, h.binding_sha256] for h in (hooks or [])]
        )
        return "v3_" + hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
    canonical = sorted([(str(c.id), c.version, c.alias) for c in components])
    return "v2_" + hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()


@router.post("/layers", response_model=LayerReceipt)
@limiter.limit("10/minute")
async def upload_layer(
    request: Request,
    layer: LayerRequest,
    db: AsyncSession = Depends(get_db),
    viewer: User = Depends(get_current_user),
):
    del request
    if (not layer.components and not layer.skills and not layer.hooks) or (
        len(layer.components) + len(layer.skills) + len(layer.hooks) > 100
    ):
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    if len({pin.alias for pin in layer.skills}) != len(layer.skills):
        raise HTTPException(status_code=422, detail="Duplicate skill alias")
    if len({pin.id for pin in layer.skills}) != len(layer.skills):
        raise HTTPException(status_code=422, detail="Duplicate skill ID")
    if (
        len({pin.id for pin in layer.hooks}) != len(layer.hooks)
        or len({pin.binding_sha256 for pin in layer.hooks}) != len(layer.hooks)
        or len({pin.alias for pin in layer.hooks}) != len(layer.hooks)
    ):
        raise HTTPException(status_code=422, detail="Ambiguous hook identity")
    if len({pin.alias for pin in layer.components}) != len(layer.components):
        raise HTTPException(status_code=422, detail="Duplicate component alias")
    if len({pin.id for pin in layer.components}) != len(layer.components):
        raise HTTPException(status_code=422, detail="Duplicate component ID")
    pins = {pin.id: pin for pin in layer.components}
    matches = (
        await db.execute(
            select(McpListing.id, McpVersion.id, McpVersion.version)
            .join(McpVersion, McpVersion.listing_id == McpListing.id)
            .where(
                McpListing.id.in_(pins),
                McpVersion.status == ListingStatus.approved,
                McpListing.is_private.is_(False),
            )
        )
    ).all()
    resolved: dict[uuid.UUID, uuid.UUID] = {}
    for listing_id, version_id, version in matches:
        if version == pins[listing_id].version:
            resolved[listing_id] = version_id
    # Do not expose which private/unknown/unapproved pin failed.
    if len(resolved) != len(pins):
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    skill_pins = {pin.id: pin for pin in layer.skills}
    skill_versions = (
        (
            await db.execute(
                select(SkillListing.id, SkillVersion.id, SkillVersion.version, SkillVersion.skill_md_content)
                .join(SkillVersion, SkillVersion.listing_id == SkillListing.id)
                .where(
                    SkillListing.id.in_(skill_pins),
                    SkillVersion.status == ListingStatus.approved,
                    SkillListing.is_private.is_(False),
                )
            )
        ).all()
        if skill_pins
        else []
    )
    resolved_skills: dict[uuid.UUID, uuid.UUID] = {}
    for listing_id, version_id, version, content in skill_versions:
        if (
            content is not None
            and version == skill_pins[listing_id].version
            and hashlib.sha256(content.encode()).hexdigest() == skill_pins[listing_id].content_sha256
        ):
            resolved_skills[listing_id] = version_id
    if len(resolved_skills) != len(skill_pins):
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    hook_pins = {pin.id: pin for pin in layer.hooks}
    hook_versions = (
        (
            await db.execute(
                select(
                    HookListing.id,
                    HookVersion.id,
                    HookVersion.version,
                    HookVersion.event,
                    HookVersion.handler_type,
                    HookVersion.handler_config,
                    HookVersion.tool_filter,
                    HookVersion.script_content,
                    HookVersion.script_filename,
                )
                .join(HookVersion, HookVersion.listing_id == HookListing.id)
                .where(
                    HookListing.id.in_(hook_pins),
                    HookVersion.status == ListingStatus.approved,
                    HookListing.is_private.is_(False),
                )
            )
        ).all()
        if hook_pins
        else []
    )
    event_map = {"PreToolUse": "tool_call", "PostToolUse": "tool_result"}
    resolved_hooks: dict[uuid.UUID, tuple[uuid.UUID, str]] = {}
    for listing_id, version_id, version, event, handler, config, tool_filter, script, filename in hook_versions:
        command = config.get("command") if isinstance(config, dict) else None
        mapped_event = event_map.get(event)
        pin = hook_pins[listing_id]
        if (
            version == pin.version
            and handler == "command"
            and mapped_event
            and isinstance(command, str)
            and command.strip()
            and tool_filter is None
            and not script
            and not filename
            and hashlib.sha256(f"{mapped_event}\0{command}".encode()).hexdigest() == pin.binding_sha256
        ):
            resolved_hooks[listing_id] = (version_id, mapped_event)
    if len(resolved_hooks) != len(hook_pins):
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    digest = canonical_layer_hash(layer.components, layer.skills, layer.hooks)
    params = {"project": str(DEFAULT_PROJECT_ID), "user": viewer.id, "harness": layer.harness, "hash": digest}
    existing = (
        await db.execute(
            text(
                "SELECT expected_components,expected_skills,expected_hooks FROM mobile_verified_layers "
                "WHERE project_id=:project AND user_id=:user AND harness=:harness AND layer_hash=:hash"
            ),
            params,
        )
    ).first()
    if existing is not None:
        count = await db.scalar(
            text(
                "SELECT count(*) FROM mobile_layer_components "
                "WHERE project_id=:project AND user_id=:user AND harness=:harness AND layer_hash=:hash"
            ),
            params,
        )
        skill_count = await db.scalar(
            text(
                "SELECT count(*) FROM mobile_skill_layer_components "
                "WHERE project_id=:project AND user_id=:user AND harness=:harness AND layer_hash=:hash"
            ),
            params,
        )
        hook_count = await db.scalar(
            text(
                "SELECT count(*) FROM mobile_hook_layer_components WHERE project_id=:project AND user_id=:user "
                "AND harness=:harness AND layer_hash=:hash"
            ),
            params,
        )
        if (
            existing[2] != len(hook_pins)
            or hook_count != existing[2]
            or existing[0] != len(pins)
            or count != existing[0]
            or existing[1] != len(skill_pins)
            or skill_count != existing[1]
        ):
            raise HTTPException(status_code=409, detail="Layer mapping invalidated")
        return LayerReceipt(hash=digest, mapped_components=count + skill_count + hook_count)
    await db.execute(
        text(
            "INSERT INTO mobile_verified_layers(project_id,user_id,harness,layer_hash,expected_components,expected_skills,expected_hooks) "
            "VALUES (:project,:user,:harness,:hash,:count,:skills,:hooks) ON CONFLICT DO NOTHING"
        ),
        {**params, "count": len(pins), "skills": len(skill_pins), "hooks": len(hook_pins)},
    )
    for pin in layer.components:
        await db.execute(
            text(
                "INSERT INTO mobile_layer_components(project_id,user_id,harness,layer_hash,alias,component_id,version_id) "
                "VALUES (:project,:user,:harness,:hash,:alias,:component,:version) ON CONFLICT DO NOTHING"
            ),
            {**params, "alias": pin.alias, "component": pin.id, "version": resolved[pin.id]},
        )
    for pin in layer.skills:
        await db.execute(
            text(
                "INSERT INTO mobile_skill_layer_components(project_id,user_id,harness,layer_hash,scope,alias,"
                "component_id,version_id,location_sha256,content_sha256) "
                "VALUES (:project,:user,:harness,:hash,:scope,:alias,:component,:version,:location,:content) "
                "ON CONFLICT DO NOTHING"
            ),
            {
                **params,
                "scope": pin.scope,
                "alias": pin.alias,
                "component": pin.id,
                "version": resolved_skills[pin.id],
                "location": pin.location_sha256,
                "content": pin.content_sha256,
            },
        )
    for pin in layer.hooks:
        await db.execute(
            text(
                "INSERT INTO mobile_hook_layer_components(project_id,user_id,harness,layer_hash,binding_sha256,"
                "event,alias,component_id,version_id) VALUES (:project,:user,:harness,:hash,:binding,:event,:alias,:component,:version) "
                "ON CONFLICT DO NOTHING"
            ),
            {
                **params,
                "binding": pin.binding_sha256,
                "event": resolved_hooks[pin.id][1],
                "alias": pin.alias,
                "component": pin.id,
                "version": resolved_hooks[pin.id][0],
            },
        )
    await db.commit()
    return LayerReceipt(hash=digest, mapped_components=len(pins) + len(skill_pins) + len(hook_pins))
