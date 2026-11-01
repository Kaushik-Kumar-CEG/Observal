# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Pi v2 source must map only to same-uploader, verified, approved typed pins."""

import copy
import hashlib
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from api.routes import mobile_evidence
from api.routes.mobile_evidence import ComponentPin, HookPin, LayerRequest, SkillPin, canonical_layer_hash
from services.mobile_layer_registration import matches_verified_pi_snapshot


def _proof():
    ids = [uuid.UUID(int=n) for n in (1, 2, 3)]
    skill = b"---\nname: rc\n---\nRead the complete skill.\n"
    content = hashlib.sha256(skill).hexdigest()
    location = hashlib.sha256(b"/isolated/.pi/agent/skills/rc/SKILL.md").hexdigest()
    binding = hashlib.sha256(b"tool_call\0true").hexdigest()
    layer = LayerRequest(
        harness="pi",
        source_layer_hash="v2_" + "a" * 60,
        components=[ComponentPin(id=ids[0], version="1.0.0", alias="rc")],
        skills=[
            SkillPin(
                id=ids[1], version="1.0.0", alias="rc", scope="user", location_sha256=location, content_sha256=content
            )
        ],
        hooks=[HookPin(id=ids[2], version="1.0.0", alias="guard", scope="user", binding_sha256=binding)],
    )
    standalone = [
        dict(type=kind, id=str(identity), version="1.0.0", local_name=alias, scope="user", name=alias, harness="pi")
        for kind, identity, alias in zip(("mcp", "skill", "hook"), ids, ("rc", "rc", "guard"), strict=True)
    ]
    verifications = [
        dict(
            harness="pi",
            component_id=str(identity),
            alias=alias,
            scope="user",
            parent_agent_id="",
            status="verified",
            location_sha256=value,
        )
        for identity, alias, value in zip(ids, ("rc", "rc", "guard"), ("", location, binding), strict=True)
    ]
    files = [
        "user:mcp.json",
        "user:skills/rc/SKILL.md",
        "user:observal-hooks.json",
        "observal:mcp-verification",
        "observal:skill-verification",
        "observal:hook-verification",
    ]
    snapshot = {
        "hash_schema_version": 2,
        "harnesses": {
            "pi": [
                {"path": path, "hash": "sha256-" + (content if path.endswith("/SKILL.md") else "a" * 64)}
                for path in files
            ]
        },
        "pinned_versions": {"schema_version": 2, "agents": [], "standalone": standalone},
        "drift": {
            "mcp_verifications": [verifications[0]],
            "skill_verifications": [verifications[1]],
            "hook_verifications": [verifications[2]],
        },
    }
    return layer, snapshot


def test_pending_mapping_hash_mismatch_then_exact_verified_source_mapping():
    layer, snapshot = _proof()
    # Prior behavior: an identity-only registration returned a different hash
    # from Pi's v2 source, so the worker could only publish pending_mapping.
    assert canonical_layer_hash(layer.components, layer.skills, layer.hooks) != layer.source_layer_hash
    assert matches_verified_pi_snapshot(snapshot, layer)
    assert layer.source_layer_hash == "v2_" + "a" * 60


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s["drift"]["hook_verifications"][0].update(status="unverified"),
        lambda s: s["drift"]["skill_verifications"][0].update(status="drifted"),
        lambda s: s["harnesses"]["pi"].pop(1),  # complete installed SKILL.md absent
        lambda s: s["harnesses"]["pi"].pop(),  # verifier identity absent
        lambda s: s["pinned_versions"]["standalone"].append(dict(s["pinned_versions"]["standalone"][0])),
        lambda s: s.update(hash_schema_version=1),
    ],
)
def test_never_map_missing_or_unverified_pins(mutation):
    layer, snapshot = _proof()
    tampered = copy.deepcopy(snapshot)
    mutation(tampered)
    assert not matches_verified_pi_snapshot(tampered, layer)


def test_changed_skill_bytes_or_hook_binding_never_qualify():
    layer, snapshot = _proof()
    snapshot["harnesses"]["pi"][1]["hash"] = "sha256-" + "b" * 64
    assert not matches_verified_pi_snapshot(snapshot, layer)
    layer, snapshot = _proof()
    layer.hooks[0].binding_sha256 = "b" * 64
    assert not matches_verified_pi_snapshot(snapshot, layer)


@pytest.mark.asyncio
async def test_authenticated_registration_returns_pi_source_hash_for_worker(monkeypatch):
    layer, snapshot = _proof()
    monkeypatch.setattr("services.layer_components.extractor._snapshot", AsyncMock(return_value=(snapshot, False)))
    calls = []
    rows = [
        [(layer.components[0].id, uuid.uuid4(), "1.0.0")],
        [(layer.skills[0].id, uuid.uuid4(), "1.0.0", "---\nname: rc\n---\nRead the complete skill.\n")],
        [(layer.hooks[0].id, uuid.uuid4(), "1.0.0", "PreToolUse", "command", {"command": "true"}, None, None, None)],
    ]

    class Result:
        def __init__(self, values=()):
            self.values = values

        def all(self):
            return self.values

        def first(self):
            return None

    async def execute(statement, _params=None):
        calls.append(str(statement))
        return Result(rows.pop(0)) if rows else Result()

    db = SimpleNamespace(execute=execute, commit=AsyncMock())
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/mobile-evidence/v1/layers",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )
    receipt = await mobile_evidence.upload_layer(request, layer, db, SimpleNamespace(id=uuid.uuid4()))
    assert receipt.hash == layer.source_layer_hash
    assert receipt.mapped_components == 3
    assert len([sql for sql in calls if "INSERT INTO mobile_" in sql]) == 4
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_unverified_snapshot_never_inserts_typed_mapping(monkeypatch):
    layer, snapshot = _proof()
    snapshot["drift"]["mcp_verifications"][0]["status"] = "unverified"
    monkeypatch.setattr("services.layer_components.extractor._snapshot", AsyncMock(return_value=(snapshot, False)))
    ids = [layer.components[0].id, layer.skills[0].id, layer.hooks[0].id]
    approved = [
        [(ids[0], uuid.uuid4(), "1.0.0")],
        [(ids[1], uuid.uuid4(), "1.0.0", "---\nname: rc\n---\nRead the complete skill.\n")],
        [(ids[2], uuid.uuid4(), "1.0.0", "PreToolUse", "command", {"command": "true"}, None, None, None)],
    ]
    calls = []

    class Result:
        def __init__(self, values):
            self.values = values

        def all(self):
            return self.values

    async def execute(statement, _params=None):
        calls.append(str(statement))
        return Result(approved.pop(0))

    with pytest.raises(HTTPException) as error:
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/mobile-evidence/v1/layers",
                "headers": [],
                "client": ("127.0.0.1", 12345),
            }
        )
        await mobile_evidence.upload_layer(
            request, layer, SimpleNamespace(execute=execute), SimpleNamespace(id=uuid.uuid4())
        )
    assert error.value.status_code == 422
    assert not any("INSERT INTO mobile_" in sql for sql in calls)
