# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in isolated Pi source→ClickHouse→PostgreSQL skill projector proof.

Requires the disposable localhost mobile stack upgraded to 059. A synthetic
verified inline skill is created in a unique scope, then removed. No real
account, live source, mobile read barrier, or production flag is modified.
"""

import hashlib
import inspect
import json
import os
import secrets
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTEGRATION_SKILL") != "1", reason="disposable mobile DB only")


@pytest.mark.asyncio(loop_scope="session")
async def test_pi_linked_skill_load_projects_root_and_replay_and_listing_deletion_fence():
    from api.routes.mobile_evidence import ComponentPin, HookPin, LayerRequest, SkillPin, upload_layer
    from config import settings
    from database import async_session
    from jobs.mobile_evidence import _rows, project_pi_session
    from models.hook import HookListing, HookVersion
    from models.mcp import McpListing, McpVersion
    from models.skill import SkillListing, SkillVersion
    from models.user import User, UserRole
    from services.clickhouse.client import _query
    from services.mobile_activity_query import trace_component_page, trace_pair_batch, trace_union
    from services.mobile_run_identity import admit_pi_run
    from services.session_ingest import ingest_session_lines

    url = make_url(settings.DATABASE_URL)
    assert (url.host, url.port, url.database) == ("127.0.0.1", 15438, "observal")
    marker = uuid.uuid4().hex
    actor = User(
        id=uuid.uuid4(),
        email=f"mobile-skill-actor-{marker}@example.invalid",
        username=f"ms_actor_{marker[:12]}",
        name="Disposable Skill Actor",
        role=UserRole.user,
    )
    actor.set_password(secrets.token_urlsafe(24))
    author = User(
        id=uuid.uuid4(),
        email=f"mobile-skill-author-{marker}@example.invalid",
        username=f"ms_author_{marker[:12]}",
        name="Disposable Skill Author",
        role=UserRole.admin,
    )
    author.set_password(secrets.token_urlsafe(24))
    component = SkillListing(
        id=uuid.uuid4(),
        name="ISOLATED SYNTHETIC SKILL NOT LIVE",
        namespace="mobile_skill_probe",
        slug="probe-" + marker[:12],
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    content = "---\nname: review\ndescription: synthetic test only\n---\n"
    version = SkillVersion(
        id=uuid.uuid4(),
        listing_id=component.id,
        version="1.0.0",
        description="synthetic",
        status="approved",
        released_by=author.id,
        released_at=datetime.now(UTC),
        supported_harnesses=["pi"],
        skill_md_content=content,
        skill_path="/SKILL.md",
        delivery_mode="inline",
        validated=True,
        target_agents=[],
        task_type="general",
        extra_files=[],
        download_count=0,
    )
    mcp = McpListing(
        id=uuid.uuid4(),
        name="ISOLATED SYNTHETIC MCP NOT LIVE",
        namespace="mobile_skill_probe",
        slug="mcp-" + marker[:12],
        category="testing",
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    mcp_version = McpVersion(
        id=uuid.uuid4(),
        listing_id=mcp.id,
        version="1.0.0",
        description="synthetic",
        status="approved",
        released_by=author.id,
        released_at=datetime.now(UTC),
        supported_harnesses=["pi"],
        command="not-executed-test-command",
        mcp_validated=True,
    )
    hook = HookListing(
        id=uuid.uuid4(),
        name="ISOLATED SYNTHETIC HOOK NOT LIVE",
        namespace="mobile_skill_probe",
        slug="hook-" + marker[:12],
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    hook_command = "synthetic-only-not-executed"
    hook_binding = hashlib.sha256(f"tool_call\0{hook_command}".encode()).hexdigest()
    hook_version = HookVersion(
        id=uuid.uuid4(),
        listing_id=hook.id,
        version="1.0.0",
        description="synthetic",
        status="approved",
        released_by=author.id,
        released_at=datetime.now(UTC),
        supported_harnesses=["pi"],
        event="PreToolUse",
        handler_type="command",
        handler_config={"command": hook_command},
    )
    path = "/home/synthetic/.pi/agent/skills/review/SKILL.md"
    session = "mobile-skill-probe-" + marker
    root = uuid.uuid4()
    source_stored = False
    try:
        async with async_session() as db:
            assert await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'")) is True
            db.add_all([actor, author])
            await db.flush()
            db.add(component)
            await db.flush()
            db.add(mcp)
            await db.flush()
            db.add(hook)
            await db.flush()
            db.add_all([version, mcp_version, hook_version])
            await db.commit()
        layer = LayerRequest(
            harness="pi",
            components=[ComponentPin(id=mcp.id, version="1.0.0", alias="alpha")],
            hooks=[HookPin(id=hook.id, version="1.0.0", alias="pre-tool", scope="user", binding_sha256=hook_binding)],
            skills=[
                SkillPin(
                    id=component.id,
                    version="1.0.0",
                    alias="review",
                    scope="user",
                    location_sha256=hashlib.sha256(path.encode()).hexdigest(),
                    content_sha256=hashlib.sha256(content.encode()).hexdigest(),
                )
            ],
        )
        async with async_session() as db:
            receipt = await inspect.unwrap(upload_layer)(SimpleNamespace(), layer, db, actor)
            replay = await inspect.unwrap(upload_layer)(SimpleNamespace(), layer, db, actor)
            from fastapi import HTTPException

            bad_hook = layer.model_copy(
                update={
                    "hooks": [
                        layer.hooks[0].model_copy(
                            update={
                                "binding_sha256": "0" * 64,
                            }
                        )
                    ]
                }
            )
            bad_skill = layer.model_copy(
                update={
                    "skills": [
                        layer.skills[0].model_copy(
                            update={
                                "content_sha256": "0" * 64,
                            }
                        )
                    ]
                }
            )
            for invalid in (bad_hook, bad_skill):
                with pytest.raises(HTTPException) as denied:
                    await inspect.unwrap(upload_layer)(SimpleNamespace(), invalid, db, actor)
                assert denied.value.status_code == 422
        assert replay == receipt and receipt.hash.startswith("v3_") and receipt.mapped_components == 3
        start = datetime.now(UTC)
        stamp = (start + timedelta(milliseconds=1)).isoformat()
        lines = [
            json.dumps({"type": "session", "id": session, "timestamp": start.isoformat(), "cwd": "/work"}),
            json.dumps(
                {
                    "type": "message",
                    "timestamp": stamp,
                    "message": {
                        "role": "system",
                        "sections": {
                            "skills": f"<available_skills><skill><name>review</name><description>test</description>"
                            f"<location>{path}</location></skill></available_skills>"
                        },
                    },
                }
            ),
            json.dumps(
                {
                    "type": "message",
                    "timestamp": stamp,
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "toolCall", "id": "skill-read", "name": "read", "arguments": {"path": path}},
                            {
                                "type": "toolCall",
                                "id": "mcp-1",
                                "name": "mcp",
                                "arguments": {
                                    "server": "alpha",
                                    "tool": "fetch",
                                },
                            },
                        ],
                    },
                }
            ),
            json.dumps(
                {
                    "type": "custom",
                    "timestamp": stamp,
                    "customType": "observal-hook-run",
                    "data": {
                        "v": 1,
                        "event": "tool_call",
                        "tool_call_id": "mcp-1",
                        "binding": hook_binding,
                        "outcome": "ran",
                        "exit_code": 0,
                    },
                }
            ),
            json.dumps(
                {
                    "type": "message",
                    "timestamp": stamp,
                    "message": {"role": "toolResult", "toolCallId": "skill-read", "isError": False, "content": []},
                }
            ),
            json.dumps(
                {
                    "type": "message",
                    "timestamp": stamp,
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "mcp-1",
                        "toolName": "mcp",
                        "isError": False,
                        "details": {"mode": "call", "server": "alpha", "tool": "fetch"},
                        "content": [],
                    },
                }
            ),
        ]
        await admit_pi_run(
            project="default",
            user=actor.id,
            session=session,
            harness="pi",
            start_offset=0,
            lines=lines,
            run_incarnation=root,
            run_header_hash=hashlib.sha256(lines[0].encode()).hexdigest(),
            run_origin="pi_session_start_root_v1",
        )
        byte_count = 0
        offsets = []
        for line in lines:
            byte_count += len(line.encode()) + 1
            offsets.append(byte_count)
        result = await ingest_session_lines(
            session_id=session,
            project_id="default",
            user_id=str(actor.id),
            agent_id=None,
            agent_version=None,
            layer_hash=receipt.hash,
            harness="pi",
            lines=lines,
            start_offset=0,
            end_byte_offsets=offsets,
        )
        assert result.errors == 0
        source_stored = True
        assert len(await _rows("default", str(actor.id), "pi", session)) == len(lines)
        projected = await project_pi_session({}, "default", str(actor.id), "pi", session)
        assert projected == {"status": "complete", "matched": 3}
        async with async_session() as db:
            facts = (
                await db.execute(
                    text(
                        "SELECT component_id,root_run_incarnation,source_revision,run_incarnation "
                        "FROM mobile_skill_evidence_events WHERE project_id='default' AND user_id=:actor AND session_id=:session"
                    ),
                    {"actor": actor.id, "session": session},
                )
            ).all()
            assert len(facts) == 1
            assert facts[0].component_id == component.id
            assert facts[0].root_run_incarnation == facts[0].run_incarnation == root
            assert len(facts[0].source_revision) == 64
            union = (
                await db.execute(
                    text(
                        "SELECT component_id,root_run_incarnation FROM mobile_evidence_events "
                        "WHERE user_id=:actor AND session_id=:session "
                        "UNION ALL SELECT component_id,root_run_incarnation FROM mobile_skill_evidence_events "
                        "WHERE user_id=:actor AND session_id=:session"
                    ),
                    {"actor": actor.id, "session": session},
                )
            ).all()
            hook_fact = (
                await db.execute(
                    text(
                        "SELECT component_id,root_run_incarnation,outcome FROM mobile_hook_evidence_events "
                        "WHERE user_id=:actor AND session_id=:session"
                    ),
                    {"actor": actor.id, "session": session},
                )
            ).one()
            assert hook_fact.component_id == hook.id and hook_fact.root_run_incarnation == root
            assert hook_fact.outcome == "ran", "silent success still counts as a recorded run"
            assert {item.component_id for item in union} == {component.id, mcp.id}
            assert len({item.root_run_incarnation for item in union}) == 1, "one person trace, two component rows"
            assert union[0].root_run_incarnation == root
            user_epoch = await db.scalar(
                text(
                    "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='user'"
                ),
                {"id": actor.id},
            )
            author_epoch = await db.scalar(
                text(
                    "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
                ),
                {"id": author.id},
            )
            assert user_epoch is not None and author_epoch is not None
        # Override the read *function only in this process*. The project read
        # barrier remains blocked for every actual API/phone and other user.
        with patch("services.mobile_read_control.readable", new=AsyncMock(return_value=True)):
            async with async_session() as db:
                lower, upper = start - timedelta(minutes=1), start + timedelta(minutes=1)
                user = await trace_union(db, actor.id, "user", "default", lower, upper, viewer_self=True)
                author_read = await trace_union(db, author.id, "author", "default", lower, upper)
                assert user == author_read == {"roots": 1, "calls": 1, "skill_loads": 1, "hook_runs": 1, "days": 1}
                authors, users = await trace_pair_batch(db, [actor.id, author.id], author.id, "default", lower, upper)
                assert (
                    authors[author.id]["roots"],
                    authors[author.id]["calls"],
                    authors[author.id]["skill_loads"],
                ) == (1, 1, 1)
                assert (users[actor.id]["roots"], users[actor.id]["calls"], users[actor.id]["skill_loads"]) == (1, 1, 1)
                page = await trace_component_page(db, actor.id, "user", "default", lower, upper, viewer_self=True)
                assert len(page) == 3 and {row["kind"] for row in page} == {"mcp", "skill", "hook"}
                assert {row["roots"] for row in page} == {1}
                remaining = await trace_component_page(
                    db,
                    actor.id,
                    "user",
                    "default",
                    lower,
                    upper,
                    viewer_self=True,
                    after=(page[0]["roots"], page[0]["kind"], page[0]["id"]),
                    limit=1,
                )
                assert [entry["kind"] for entry in remaining] == ["mcp", "skill"]
                skill_detail = await trace_component_page(
                    db,
                    actor.id,
                    "user",
                    "default",
                    lower,
                    upper,
                    viewer_self=True,
                    component=component.id,
                    kind="skill",
                    limit=1,
                )
                assert skill_detail[0]["skill_loads"] == 1 and skill_detail[0]["calls"] == 0
                assert not await trace_component_page(
                    db,
                    actor.id,
                    "user",
                    "default",
                    lower,
                    upper,
                    viewer_self=True,
                    component=component.id,
                    kind="mcp",
                    limit=1,
                )
                # Privacy and review changes must drop this kind from BOTH
                # scopes, but not touch the overlapping MCP root.
                await db.execute(text("UPDATE skill_listings SET is_private=true WHERE id=:id"), {"id": component.id})
                await db.commit()
                assert await trace_union(db, author.id, "author", "default", lower, upper) == {
                    "roots": 1,
                    "calls": 1,
                    "skill_loads": 0,
                    "hook_runs": 1,
                    "days": 1,
                }
                assert await trace_union(db, actor.id, "user", "default", lower, upper, viewer_self=True) == {
                    "roots": 1,
                    "calls": 1,
                    "skill_loads": 0,
                    "hook_runs": 1,
                    "days": 1,
                }
                assert not await trace_component_page(
                    db, author.id, "author", "default", lower, upper, component=component.id, kind="skill"
                )
                await db.execute(text("UPDATE skill_listings SET is_private=false WHERE id=:id"), {"id": component.id})
                await db.execute(text("UPDATE skill_versions SET status='rejected' WHERE id=:id"), {"id": version.id})
                await db.commit()
                assert (await trace_union(db, author.id, "author", "default", lower, upper))["skill_loads"] == 0
                await db.execute(text("UPDATE skill_versions SET status='approved' WHERE id=:id"), {"id": version.id})
                await db.commit()
                await db.execute(text("UPDATE hook_listings SET is_private=true WHERE id=:id"), {"id": hook.id})
                await db.commit()
                assert (await trace_union(db, actor.id, "user", "default", lower, upper, viewer_self=True))[
                    "hook_runs"
                ] == 0
                assert (await trace_union(db, author.id, "author", "default", lower, upper))["hook_runs"] == 0
                assert not await trace_component_page(
                    db, author.id, "author", "default", lower, upper, component=hook.id, kind="hook"
                )
                await db.execute(text("UPDATE hook_listings SET is_private=false WHERE id=:id"), {"id": hook.id})
                await db.execute(
                    text("UPDATE hook_versions SET status='rejected' WHERE id=:id"), {"id": hook_version.id}
                )
                await db.commit()
                assert (await trace_union(db, author.id, "author", "default", lower, upper))["hook_runs"] == 0
                await db.execute(
                    text("UPDATE hook_versions SET status='approved' WHERE id=:id"), {"id": hook_version.id}
                )
                await db.commit()
                assert (await trace_union(db, author.id, "author", "default", lower, upper))["hook_runs"] == 1
        # Real PostgreSQL-backed HTTP routes, with only this process's
        # synthetic viewer dependency substituted. Mobile auth remains OFF and
        # the disposable stack's read barrier remains blocked throughout.
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from api.deps import get_db, get_mobile_user
        from api.routes.mobile_activity import router as mobile_router
        from services.crypto import init_key_manager

        async def isolated_db():
            async with async_session() as connection:
                yield connection

        app = FastAPI()
        app.include_router(mobile_router)
        app.dependency_overrides[get_db] = isolated_db
        app.dependency_overrides[get_mobile_user] = lambda: actor
        with (
            tempfile.TemporaryDirectory(prefix="mobile-hook-asgi-keys-") as keydir,
            patch("services.crypto._key_manager", None),
            patch("services.mobile_read_control.readable", new=AsyncMock(return_value=True)),
            patch("api.routes.mobile_activity.readable", new=AsyncMock(return_value=True)),
        ):
            init_key_manager(keydir)
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://isolated-only") as http:
                actor_summary = await http.get(
                    f"/api/v1/mobile-activity/v1/people/{actor.id}/summary",
                    params={"scope": "user", "period": "1w"},
                )
                forbidden = await http.get(
                    f"/api/v1/mobile-activity/v1/people/{actor.id}/summary",
                    params={"scope": "author", "period": "1w"},
                )
                app.dependency_overrides[get_mobile_user] = lambda: author
                with patch("api.routes.mobile_activity.ds.get_bool", new=AsyncMock(return_value=False)):
                    author_summary = await http.get(
                        f"/api/v1/mobile-activity/v1/people/{author.id}/summary",
                        params={"scope": "author", "period": "1w"},
                    )
                    admin_user = await http.get(
                        f"/api/v1/mobile-activity/v1/people/{actor.id}/summary",
                        params={"scope": "user", "period": "1w"},
                    )
                    paired = await http.post(
                        "/api/v1/mobile-activity/v1/people/summaries",
                        json={"subject_ids": [str(author.id), str(actor.id)], "period": "1w"},
                    )
                    payload = author_summary.json()
                    details = []
                    for kind, ident in (("mcp", mcp.id), ("skill", component.id), ("hook", hook.id)):
                        detail = await http.get(
                            f"/api/v1/mobile-activity/v1/people/{author.id}/author/components/{kind}/{ident}",
                            params={
                                "period": "1w",
                                "window_anchor": payload["window_anchor"],
                                "expected_revision": payload["revision"],
                            },
                        )
                        details.append(detail)
        assert actor_summary.status_code == 200 and forbidden.status_code == 403 and not forbidden.content
        assert author_summary.status_code == admin_user.status_code == paired.status_code == 200
        author_card, actor_card = paired.json()["items"]
        assert author_card["author_usage"]["value"] == 1 and author_card["user_usage"]["value"] is None
        assert actor_card["author_usage"]["value"] is None and actor_card["user_usage"]["value"] == 1
        for summary in (actor_summary.json(), author_summary.json(), admin_user.json()):
            assert summary["component_trace_union"]["value"] == 1
            assert summary["mcp_calls"]["value"] == 1
            assert summary["confirmed_skill_loads"]["value"] == 1
            assert summary["recorded_hook_runs"]["value"] == 1
        assert [item.status_code for item in details] == [200, 200, 200]
        assert [item.json()["component"]["kind"] for item in details] == ["mcp", "skill", "hook"]
        assert (await project_pi_session({}, "default", str(actor.id), "pi", session))["matched"] == 3
        async with async_session() as db:
            assert (
                await db.scalar(
                    text(
                        "SELECT count(*) FROM mobile_skill_evidence_events WHERE user_id=:actor AND session_id=:session"
                    ),
                    {"actor": actor.id, "session": session},
                )
                == 1
            )
            await db.execute(text("DELETE FROM skill_listings WHERE id=:component"), {"component": component.id})
            await db.commit()
            assert (
                await db.scalar(
                    text(
                        "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='user'"
                    ),
                    {"id": actor.id},
                )
            ) > user_epoch
            assert (
                await db.scalar(
                    text(
                        "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
                    ),
                    {"id": author.id},
                )
            ) > author_epoch
        assert (await project_pi_session({}, "default", str(actor.id), "pi", session))["status"] == "pending_mapping"
        async with async_session() as db:
            for table in ("mobile_evidence_events", "mobile_skill_evidence_events", "mobile_hook_evidence_events"):
                # Static table names only; all untrusted identifiers remain bound.
                assert (
                    await db.scalar(
                        text(f"SELECT count(*) FROM {table} WHERE user_id=:actor AND session_id=:session"),
                        {"actor": actor.id, "session": session},
                    )
                    == 0
                )
    finally:
        async with async_session() as db:
            await db.execute(text("DELETE FROM skill_listings WHERE id=:component"), {"component": component.id})
            await db.execute(text("DELETE FROM mcp_listings WHERE id=:component"), {"component": mcp.id})
            await db.execute(text("DELETE FROM hook_listings WHERE id=:component"), {"component": hook.id})
            await db.execute(
                text("DELETE FROM users WHERE id IN (:actor,:author)"),
                {
                    "actor": actor.id,
                    "author": author.id,
                },
            )
            await db.commit()
        if source_stored:
            await _query(
                "ALTER TABLE session_events DELETE WHERE project_id={project:String} "
                "AND user_id={user:String} AND harness='pi' AND session_id={session:String} "
                "SETTINGS mutations_sync=2",
                {"param_project": "default", "param_user": str(actor.id), "param_session": session},
            )
