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


class LayerRequest(BaseModel):
    harness: Literal["pi"]
    components: list[ComponentPin] = Field(default_factory=list, max_length=100)
    skills: list[SkillPin] = Field(default_factory=list, max_length=100)


class LayerReceipt(BaseModel):
    hash: str
    mapped_components: int


def canonical_layer_hash(components: list[ComponentPin], skills: list[SkillPin] | None = None) -> str:
    if skills:
        canonical = sorted(
            [["mcp", str(c.id), c.version, c.alias] for c in components]
            + [["skill", str(s.id), s.version, s.scope, s.alias, s.location_sha256, s.content_sha256] for s in skills]
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
    if (not layer.components and not layer.skills) or len(layer.components) + len(layer.skills) > 100:
        raise HTTPException(status_code=422, detail="Unsupported component identity")
    if len({pin.alias for pin in layer.skills}) != len(layer.skills):
        raise HTTPException(status_code=422, detail="Duplicate skill alias")
    if len({pin.id for pin in layer.skills}) != len(layer.skills):
        raise HTTPException(status_code=422, detail="Duplicate skill ID")
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
    digest = canonical_layer_hash(layer.components, layer.skills)
    params = {"project": str(DEFAULT_PROJECT_ID), "user": viewer.id, "harness": layer.harness, "hash": digest}
    existing = (
        await db.execute(
            text(
                "SELECT expected_components,expected_skills FROM mobile_verified_layers "
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
        if (
            existing[0] != len(pins)
            or count != existing[0]
            or existing[1] != len(skill_pins)
            or skill_count != existing[1]
        ):
            raise HTTPException(status_code=409, detail="Layer mapping invalidated")
        return LayerReceipt(hash=digest, mapped_components=count + skill_count)
    await db.execute(
        text(
            "INSERT INTO mobile_verified_layers(project_id,user_id,harness,layer_hash,expected_components,expected_skills) "
            "VALUES (:project,:user,:harness,:hash,:count,:skills) ON CONFLICT DO NOTHING"
        ),
        {**params, "count": len(pins), "skills": len(skill_pins)},
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
    await db.commit()
    return LayerReceipt(hash=digest, mapped_components=len(pins) + len(skill_pins))
