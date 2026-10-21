# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Produce genuine disposable Pi raw source via SDK/extension; never forge typed facts.

Requires the owned QA instance, migrated ClickHouse and projection worker.
The real Pi SDK creates root/child lines. Its extension uploads via same-issuer
HTTPS with a disposable desktop bearer. Worker-derived publications and typed
facts are independently verified by source_fixture.py before Android handoff.
"""

import asyncio
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
from source_fixture import ORIGIN, require_disposable_environment
from sqlalchemy import text

from database import async_session, engine
from models.hook import HookListing, HookVersion
from models.mcp import McpListing, McpVersion
from models.skill import SkillListing, SkillVersion

ROOT = Path(__file__).resolve().parents[3]
DRIVER = ROOT / "tests/integration_mobile/pi_v3_sdk_driver.ts"
SDK = Path("/home/kaushik/.local/npm/lib/node_modules/@earendil-works/pi-coding-agent/dist/core/session-manager.js")


async def qualify() -> None:
    runtime = require_disposable_environment()
    assert DRIVER.is_file() and SDK.is_file(), "reviewed local Pi driver and installed SDK required"
    password = (runtime / "password").read_text().strip()
    marker = secrets.token_hex(8)
    async with async_session() as db:
        people = (
            await db.execute(
                text("SELECT email,id FROM users WHERE email IN ('owner@follow-qa.invalid','viewer@follow-qa.invalid')")
            )
        ).all()
        ids = dict(people)
        assert len(ids) == 2, "two strictly disposable cohort identities required"
        assert (
            await db.scalar(
                text(
                    "SELECT source_policy_ready AND source_policy_since IS NOT NULL "
                    "FROM mobile_read_controls WHERE project_id='default'"
                )
            )
            is True
        )
        assert await db.scalar(text("SELECT count(*) FROM mobile_evidence_events")) == 0, "not a fresh fixture"
        owner = ids["owner@follow-qa.invalid"]
        mcp_id, skill_id, hook_id = (uuid.uuid4() for _ in range(3))
        content = "---\nname: review\ndescription: disposable source proof\n---\n# Review\n"
        command = "true"  # No subprocess network, secrets or stdout.
        listings = [
            McpListing(
                id=mcp_id,
                name="Disposable source MCP",
                namespace="followqa",
                slug="mcp-" + marker,
                category="testing",
                owner="synthetic",
                is_private=False,
                submitted_by=owner,
                co_authors=[],
                unique_agents=0,
            ),
            SkillListing(
                id=skill_id,
                name="Disposable source Skill",
                namespace="followqa",
                slug="skill-" + marker,
                owner="synthetic",
                is_private=False,
                submitted_by=owner,
                co_authors=[],
                unique_agents=0,
            ),
            HookListing(
                id=hook_id,
                name="Disposable source Hook",
                namespace="followqa",
                slug="hook-" + marker,
                owner="synthetic",
                is_private=False,
                submitted_by=owner,
                co_authors=[],
                unique_agents=0,
            ),
        ]
        db.add_all(listings)
        await db.flush()
        db.add_all(
            [
                McpVersion(
                    id=uuid.uuid4(),
                    listing_id=mcp_id,
                    version="1.0.0",
                    description="disposable",
                    status="approved",
                    released_by=owner,
                    released_at=datetime.now(UTC),
                    supported_harnesses=["pi"],
                    command="synthetic-no-launch",
                    mcp_validated=True,
                ),
                SkillVersion(
                    id=uuid.uuid4(),
                    listing_id=skill_id,
                    version="1.0.0",
                    description="disposable",
                    status="approved",
                    released_by=owner,
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
                    description="disposable",
                    status="approved",
                    released_by=owner,
                    released_at=datetime.now(UTC),
                    supported_harnesses=["pi"],
                    event="PreToolUse",
                    handler_type="command",
                    handler_config={"command": command},
                ),
            ]
        )
        await db.commit()
    tls = ssl.create_default_context(cafile=str(runtime / "ca.crt"))
    async with httpx.AsyncClient(base_url=ORIGIN, verify=tls, trust_env=False, timeout=15) as client:
        for email in ("viewer@follow-qa.invalid", "owner@follow-qa.invalid"):
            login = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
            assert login.status_code == 200, ("disposable login", login.status_code)
            # The driver writes only to a brand-new temporary HOME, not a real Pi account.
            with tempfile.TemporaryDirectory(prefix="followqa-pi-source-") as tmp:
                home = Path(tmp)
                home.chmod(0o700)
                skill = home / "skill.md"
                skill.write_text(content)
                skill.chmod(0o600)
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": tmp,
                    "NODE_EXTRA_CA_CERTS": str(runtime / "ca.crt"),
                    "PI_PROBE_HOME": tmp,
                    "PI_PROBE_ORIGIN": ORIGIN,
                    "PI_PROBE_ACCESS_TOKEN": login.json()["access_token"],
                    "PI_PROBE_SDK_ENTRY": str(SDK),
                    "PI_PROBE_SKILL_CONTENT_FILE": str(skill),
                    "PI_PROBE_MCP_ID": str(mcp_id),
                    "PI_PROBE_SKILL_ID": str(skill_id),
                    "PI_PROBE_HOOK_ID": str(hook_id),
                    "PI_PROBE_HOOK_COMMAND": command,
                }
                launched = await asyncio.to_thread(
                    subprocess.run,
                    ["node", "--experimental-strip-types", str(DRIVER)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                assert launched.returncode == 0, ("Pi disposable driver", launched.returncode)
                result = json.loads(launched.stdout.strip())
                assert result["receipt_count"] == 1 and result["line_count"] >= 5
                for _ in range(60):
                    async with async_session() as db:
                        counts = (
                            await db.execute(
                                text(
                                    "SELECT (SELECT count(*) FROM mobile_evidence_events WHERE session_id=:s),"
                                    "(SELECT count(*) FROM mobile_skill_evidence_events WHERE session_id=:s),"
                                    "(SELECT count(*) FROM mobile_hook_evidence_events WHERE session_id=:s)"
                                ),
                                {"s": result["session"]},
                            )
                        ).one()
                    if tuple(counts) == (1, 1, 1):
                        break
                    await asyncio.sleep(1)
                assert tuple(counts) == (1, 1, 1), "source not projected by real worker"
    print("GENUINE_DISPOSABLE_PI_SDK_EXTENSION_THREE_KINDS_PER_VIEWER=PASS")


async def main() -> None:
    try:
        await qualify()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
