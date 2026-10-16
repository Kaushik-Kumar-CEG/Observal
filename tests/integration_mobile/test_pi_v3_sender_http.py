# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, loopback-only Pi SDK→extension→authenticated HTTP→worker proof.

The SDK serializes transcript entries; it does not invoke a model or discover
skills itself. No phone audience, read barrier or production setting is opened.
"""

import asyncio
import json
import os
import secrets
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTEGRATION_V3_SENDER") != "1", reason="isolated loopback stack only")


@pytest.mark.asyncio(loop_scope="session")
async def test_pi_sdk_extension_uploads_one_root_three_kinds_to_worker():
    from config import settings
    from database import async_session
    from jobs.mobile_evidence import _rows
    from models.hook import HookListing, HookVersion
    from models.mcp import McpListing, McpVersion
    from models.skill import SkillListing, SkillVersion
    from models.user import User, UserRole
    from services.clickhouse.client import _query

    db_url = make_url(settings.DATABASE_URL)
    assert (db_url.host, db_url.port, db_url.database) == ("127.0.0.1", 15438, "observal")
    origin = "http://127.0.0.1:18480"
    sdk = Path(os.environ["PI_PROBE_SDK_ENTRY"])
    assert sdk.is_file()
    marker = uuid.uuid4().hex
    actor = User(
        id=uuid.uuid4(),
        email=f"v3-driver-{marker}@example.invalid",
        username=f"v3_{marker[:12]}",
        name="Synthetic SDK Actor",
        role=UserRole.user,
    )
    actor_password = secrets.token_urlsafe(25)
    actor.set_password(actor_password)
    author = User(
        id=uuid.uuid4(),
        email=f"v3-author-{marker}@example.invalid",
        username=f"va_{marker[:12]}",
        name="Synthetic SDK Author",
        role=UserRole.admin,
    )
    author.set_password(secrets.token_urlsafe(25))
    mcp_id, skill_id, hook_id = (uuid.uuid4() for _ in range(3))
    content = "---\nname: review\ndescription: isolated SDK test\n---\n# Review\n"
    command = "true"  # No stdout, no subprocess network or secrets.
    mcp = McpListing(
        id=mcp_id,
        name="Synthetic SDK MCP",
        namespace="v3_driver",
        slug="mcp-" + marker[:12],
        category="testing",
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    skill = SkillListing(
        id=skill_id,
        name="Synthetic SDK Skill",
        namespace="v3_driver",
        slug="skill-" + marker[:12],
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    hook = HookListing(
        id=hook_id,
        name="Synthetic SDK Hook",
        namespace="v3_driver",
        slug="hook-" + marker[:12],
        owner="synthetic",
        is_private=False,
        submitted_by=author.id,
        co_authors=[],
        unique_agents=0,
    )
    versions = [
        McpVersion(
            id=uuid.uuid4(),
            listing_id=mcp_id,
            version="1.0.0",
            description="synthetic",
            status="approved",
            released_by=author.id,
            released_at=datetime.now(UTC),
            supported_harnesses=["pi"],
            command="synthetic-no-launch",
            mcp_validated=True,
        ),
        SkillVersion(
            id=uuid.uuid4(),
            listing_id=skill_id,
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
        ),
        HookVersion(
            id=uuid.uuid4(),
            listing_id=hook_id,
            version="1.0.0",
            description="synthetic",
            status="approved",
            released_by=author.id,
            released_at=datetime.now(UTC),
            supported_harnesses=["pi"],
            event="PreToolUse",
            handler_type="command",
            handler_config={"command": command},
        ),
    ]
    session = None
    try:
        async with async_session() as db:
            assert await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'")) is True
            db.add_all([actor, author])
            await db.flush()
            db.add_all([mcp, skill, hook])
            await db.flush()
            db.add_all(versions)
            await db.commit()
        async with httpx.AsyncClient(base_url=origin, timeout=30) as client:
            response = await client.post("/api/v1/auth/login", json={"email": actor.email, "password": actor_password})
            assert response.status_code == 200, (response.status_code, response.text[:100])
            token = response.json()["access_token"]
        with tempfile.TemporaryDirectory(prefix="observal-pi-v3-", dir="/tmp") as temp:
            home = Path(temp)
            home.chmod(0o700)
            content_file = home / "approved-skill.md"
            content_file.write_text(content)
            content_file.chmod(0o600)
            env = {
                **os.environ,
                "HOME": temp,
                "PI_PROBE_HOME": temp,
                "PI_PROBE_ORIGIN": origin,
                "PI_PROBE_ACCESS_TOKEN": token,
                "PI_PROBE_SDK_ENTRY": str(sdk),
                "PI_PROBE_SKILL_CONTENT_FILE": str(content_file),
                "PI_PROBE_MCP_ID": str(mcp_id),
                "PI_PROBE_SKILL_ID": str(skill_id),
                "PI_PROBE_HOOK_ID": str(hook_id),
                "PI_PROBE_HOOK_COMMAND": command,
            }
            driver = Path(__file__).with_name("pi_v3_sdk_driver.ts")
            launched = await asyncio.to_thread(
                subprocess.run,
                [os.environ.get("PI_PROBE_NODE", "node"), "--experimental-strip-types", str(driver)],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert launched.returncode == 0, launched.stderr[-700:]
            # The driver prints no credential, command or transcript content.
            result = json.loads(launched.stdout.strip())
            session = result["session"]
            assert result["receipt_count"] == 1 and result["line_count"] >= 5
            assert len(await _rows("default", str(actor.id), "pi", session)) == result["line_count"]
        # Ingest queues a durable projection request; the *running* isolated
        # worker must consume it. Do not call project_pi_session in this test.
        for _ in range(60):
            async with async_session() as db:
                rows = (
                    await db.execute(
                        text(
                            "SELECT (SELECT count(*) FROM mobile_evidence_events WHERE user_id=:u AND session_id=:s),"
                            "(SELECT count(*) FROM mobile_skill_evidence_events WHERE user_id=:u AND session_id=:s),"
                            "(SELECT count(*) FROM mobile_hook_evidence_events WHERE user_id=:u AND session_id=:s)"
                        ),
                        {"u": actor.id, "s": session},
                    )
                ).one()
                counts = tuple(rows)
            if counts == (1, 1, 1):
                break
            await asyncio.sleep(1)
        assert counts == (1, 1, 1), f"running worker failed to project three kinds: {counts}"
        async with async_session() as db:
            roots = (
                (
                    await db.execute(
                        text(
                            "SELECT root_run_incarnation FROM mobile_evidence_events WHERE user_id=:u AND session_id=:s "
                            "UNION ALL SELECT root_run_incarnation FROM mobile_skill_evidence_events WHERE user_id=:u AND session_id=:s "
                            "UNION ALL SELECT root_run_incarnation FROM mobile_hook_evidence_events WHERE user_id=:u AND session_id=:s"
                        ),
                        {"u": actor.id, "s": session},
                    )
                )
                .scalars()
                .all()
            )
            assert len(roots) == 3 and len(set(roots)) == 1
    finally:
        if session:
            # Remove ClickHouse source before relational identity; async
            # mutations must finish before the temporary actor disappears.
            await _query(
                "ALTER TABLE session_events DELETE WHERE project_id={p:String} AND user_id={u:String} "
                "AND harness='pi' AND session_id={s:String} SETTINGS mutations_sync=0",
                {"param_p": "default", "param_u": str(actor.id), "param_s": session},
            )
            for _ in range(30):
                if not await _rows("default", str(actor.id), "pi", session):
                    break
                await asyncio.sleep(1)
            else:
                raise AssertionError("isolated source erasure did not complete")
        async with async_session() as db:
            for table, ident in (("mcp_listings", mcp_id), ("skill_listings", skill_id), ("hook_listings", hook_id)):
                await db.execute(text(f"DELETE FROM {table} WHERE id=:id"), {"id": ident})
            await db.execute(
                text("DELETE FROM users WHERE id IN (:actor,:author)"), {"actor": actor.id, "author": author.id}
            )
            await db.commit()
