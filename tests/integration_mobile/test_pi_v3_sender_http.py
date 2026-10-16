# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, loopback-only Pi SDK→extension→authenticated HTTP→worker proof.

The SDK serializes transcript entries; it does not invoke a model or discover
skills itself. A tightly gated localhost-only option opens a synthetic phone cohort.
"""

import asyncio
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
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
    assert (db_url.host, db_url.port, db_url.database) in {
        ("127.0.0.1", 15438, "observal"),
        ("127.0.0.1", 15439, "observal"),
        ("127.0.0.1", 15440, "observal"),
    }
    origin = {15438: "http://127.0.0.1:18485", 15439: "http://127.0.0.1:18482", 15440: "http://127.0.0.1:18483"}[
        db_url.port
    ]
    joint = os.getenv("MOBILE_INTEGRATION_JOINT_HOLD") == "1"
    assert not joint or (db_url.port == 15440 and os.getenv("MOBILE_INTEGRATION_V3_HTTPS") == "1")
    https_origin = "https://localhost:18443" if joint else "https://localhost:18444"
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
    author_password = secrets.token_urlsafe(25)
    author.set_password(author_password)
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
    opened = False
    author_mobile = None
    actor_mobile = None
    if os.getenv("MOBILE_INTEGRATION_V3_HTTPS") == "1":
        assert db_url.port in (15439, 15440), "HTTPS reads require fresh, synthetic-only stack"
        async with async_session() as db:
            assert await db.scalar(text("SELECT count(*) FROM users")) == 4
            assert await db.scalar(text("SELECT count(*) FROM users WHERE email NOT LIKE '%@demo.example'")) == 0
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
        if os.getenv("MOBILE_INTEGRATION_V3_HTTPS") == "1":
            # On this disposable fresh DB *only*, temporarily open the real
            # PostgreSQL gate and exercise actual scoped mobile credentials.
            ca = Path(os.environ["MOBILE_PROBE_CA"])
            assert ca.is_file() and ca.stat().st_mode & 0o077 == 0
            tls = ssl.create_default_context(cafile=str(ca))
            async with httpx.AsyncClient(
                base_url=https_origin,
                verify=tls,
                timeout=30,
                headers={"User-Agent": "Observal-Android-Isolated/1.0"},
            ) as client:
                admin_login = await client.post(
                    "/api/v1/auth/login", json={"email": author.email, "password": author_password}
                )
                assert admin_login.status_code == 200
                desktop_admin = {"Authorization": "Bearer " + admin_login.json()["access_token"]}
                async with async_session() as db:
                    server_id = await db.scalar(
                        text("SELECT server_id FROM mobile_server_identity WHERE singleton=true")
                    )
                assert server_id is not None
                for key, value in (
                    ("deployment.frontend_url", https_origin),
                    ("deployment.public_url", https_origin),
                    ("mobile.auth_enabled", "true"),
                    ("mobile.synthetic_test_server_id", str(server_id)),
                    ("mobile.synthetic_test_viewer_id", str(author.id)),
                    ("mobile.synthetic_test_self_user_viewer_id", str(actor.id)),
                    ("mobile.synthetic_test_ack", "isolated-disposable-synthetic-only-v1"),
                    ("mobile.synthetic_test_enabled", "true"),
                ):
                    changed = await client.put(
                        f"/api/v1/admin/settings/{key}", headers=desktop_admin, json={"value": value}
                    )
                    assert changed.status_code == 200, (key, changed.status_code, changed.json().get("detail"))
                async with async_session() as db:
                    assert await db.scalar(text("SELECT count(*) FROM users")) == 6
                    assert (
                        await db.scalar(text("SELECT count(*) FROM users WHERE email NOT LIKE '%@demo.example'")) == 2
                    )
                    await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('mobile-read:default',0))"))
                    allowed = await db.execute(
                        text(
                            "UPDATE mobile_read_controls SET blocked=false,generation=generation+1,updated_at=now() "
                            "WHERE project_id='default' AND blocked=true"
                        )
                    )
                    assert allowed.rowcount == 1
                    await db.commit()
                    opened = True

                async def mobile_pair(email: str, password: str):
                    challenge = await client.post(
                        "/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"}
                    )
                    assert challenge.status_code == 200
                    data = challenge.json()
                    assert data["verification_origins"] == [https_origin]
                    login = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
                    confirmed = await client.post(
                        "/api/v1/auth/device/confirm",
                        headers={"Authorization": "Bearer " + login.json()["access_token"]},
                        json={"user_code": data["user_code"]},
                    )
                    assert confirmed.status_code == 200
                    grant = await client.post(
                        "/api/v1/auth/device/token",
                        json={
                            "device_code": data["device_code"],
                            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        },
                    )
                    assert grant.status_code == 200
                    pair = grant.json()
                    bearer = {"Authorization": "Bearer " + pair["access_token"]}
                    proof = await client.get("/api/v1/auth/mobile/credential", headers=bearer)
                    assert proof.status_code == 200
                    assert pair["audience"] == "observal-mobile-activity-v1" and pair["scope"] == "mobile:read"
                    capability = await client.get("/api/v1/mobile-activity/v1/capabilities", headers=bearer)
                    assert capability.status_code == 200
                    assert capability.json()["synthetic_test_cohort"] is True
                    assert capability.json()["trace_headlines"] is False
                    assert capability.json()["supported_kinds"] == [
                        "mcp_calls",
                        "confirmed_skill_loads",
                        "recorded_hook_runs",
                    ]
                    assert (await client.get("/api/v1/auth/whoami", headers=bearer)).status_code in (401, 403)
                    assert (await client.get("/api/v1/layer-snapshots/" + "a" * 16, headers=bearer)).status_code in (
                        401,
                        403,
                    )
                    # Public GraphQL health is intentionally available to anonymous clients;
                    # a mobile bearer must not acquire a private query context.
                    graphql = await client.post("/api/v1/graphql", headers=bearer, json={"query": "{ health }"})
                    anonymous = await client.post("/api/v1/graphql", json={"query": "{ health }"})
                    assert graphql.status_code == anonymous.status_code == 200
                    assert graphql.json() == anonymous.json() == {"data": {"health": "ok"}}
                    return pair, bearer

                author_mobile, admin = await mobile_pair(author.email, author_password)
                actor_mobile, member = await mobile_pair(actor.email, actor_password)
                # A seeded administrator has the same role but is NOT an
                # allowlisted viewer. Device proof alone grants no trace data.
                demo_challenge = await client.post(
                    "/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"}
                )
                assert demo_challenge.status_code == 200
                demo_login = await client.post(
                    "/api/v1/auth/login",
                    json={"email": os.environ["DEMO_ADMIN_EMAIL"], "password": os.environ["DEMO_ADMIN_PASSWORD"]},
                )
                assert demo_login.status_code == 200
                demo_confirm = await client.post(
                    "/api/v1/auth/device/confirm",
                    headers={"Authorization": "Bearer " + demo_login.json()["access_token"]},
                    json={"user_code": demo_challenge.json()["user_code"]},
                )
                assert demo_confirm.status_code == 200
                demo_grant = await client.post(
                    "/api/v1/auth/device/token",
                    json={
                        "device_code": demo_challenge.json()["device_code"],
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                )
                assert demo_grant.status_code == 200
                demo_head = {"Authorization": "Bearer " + demo_grant.json()["access_token"]}
                demo_cap = await client.get("/api/v1/mobile-activity/v1/capabilities", headers=demo_head)
                assert demo_cap.status_code == 200 and demo_cap.json()["synthetic_test_cohort"] is False
                denied = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{author.id}/summary",
                    headers=demo_head,
                    params={"scope": "author", "period": "1w"},
                )
                assert denied.status_code == 403 and denied.content == b""
                assert (
                    await client.post(
                        "/api/v1/auth/mobile/logout",
                        headers=demo_head,
                        json={"refresh_token": demo_grant.json()["refresh_token"]},
                    )
                ).status_code == 200
                paired = await client.post(
                    "/api/v1/mobile-activity/v1/people/summaries",
                    headers=admin,
                    json={"subject_ids": [str(author.id), str(actor.id)], "period": "1w"},
                )
                assert paired.status_code == 200, (paired.status_code, paired.text[:160])
                authors, users = paired.json()["items"]
                assert authors["author_usage"]["value"] == users["user_usage"]["value"] == 1
                assert authors["author_usage"]["status"] == users["user_usage"]["status"] == "partial"
                for subject, scope, revision in (
                    (author.id, "author", authors["author_revision"]),
                    (actor.id, "user", users["user_revision"]),
                ):
                    params = {
                        "period": "1w",
                        "window_anchor": paired.json()["window_anchor"],
                        "expected_revision": revision,
                    }
                    base = f"/api/v1/mobile-activity/v1/people/{subject}/{scope}/components"
                    page = await client.get(base, headers=admin, params=params)
                    assert page.status_code == 200, (scope, page.status_code)
                    assert page.json()["complete"] and len(page.json()["items"]) == 3
                    assert {item["kind"] for item in page.json()["items"]} == {"mcp", "skill", "hook"}
                    summary = await client.get(
                        f"/api/v1/mobile-activity/v1/people/{subject}/summary",
                        headers=admin,
                        params={"scope": scope, **params},
                    )
                    assert summary.status_code == 200
                    for field in ("component_trace_union", "mcp_calls", "confirmed_skill_loads", "recorded_hook_runs"):
                        assert summary.json()[field]["value"] == 1
                        assert summary.json()[field]["status"] == "partial"
                    for item in page.json()["items"]:
                        assert item["component_traces"]["value"] == 1
                        detail = await client.get(
                            f"{base}/{item['kind']}/{item['component_id']}", headers=admin, params=params
                        )
                        assert detail.status_code == 200 and detail.json()["component"] == item
                own = await client.post(
                    "/api/v1/mobile-activity/v1/people/summaries",
                    headers=member,
                    json={"subject_ids": [str(actor.id), str(author.id)], "period": "1w"},
                )
                assert own.status_code == 200
                assert own.json()["items"][0]["user_usage"]["value"] == 1
                assert own.json()["items"][1]["author_usage"] == {"status": "restricted"}
                own_card = own.json()["items"][0]
                # The installed Android User breakdown first fetches the named
                # summary as the subject themself. Unlike a different viewer,
                # this invokes prompted_roots against retained ClickHouse source.
                # A healthy card/page alone would miss a ClickHouse auth failure.
                own_summary = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{actor.id}/summary",
                    headers=member,
                    params={
                        "scope": "user",
                        "period": "1w",
                        "window_anchor": own.json()["window_anchor"],
                        "expected_revision": own_card["user_revision"],
                    },
                )
                assert own_summary.status_code == 200
                assert own_summary.json()["component_trace_union"]["status"] == "partial"
                assert own_summary.json()["component_trace_union"]["value"] == 1
                own_page = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{actor.id}/user/components",
                    headers=member,
                    params={
                        "period": "1w",
                        "window_anchor": own.json()["window_anchor"],
                        "expected_revision": own_card["user_revision"],
                    },
                )
                assert own_page.status_code == 200 and len(own_page.json()["items"]) == 3
                stale_params = {
                    "period": "1w",
                    "window_anchor": paired.json()["window_anchor"],
                    "expected_revision": authors["author_revision"],
                }
                async with async_session() as db:
                    await db.execute(text("UPDATE hook_listings SET is_private=true WHERE id=:id"), {"id": hook_id})
                    await db.commit()
                stale = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{author.id}/author/components",
                    headers=admin,
                    params=stale_params,
                )
                assert stale.status_code == 409, "visibility epoch must invalidate earlier named page"
                fresh = await client.post(
                    "/api/v1/mobile-activity/v1/people/summaries",
                    headers=admin,
                    json={"subject_ids": [str(author.id)], "period": "1w"},
                )
                assert fresh.status_code == 200 and fresh.json()["items"][0]["author_usage"]["value"] == 1
                hidden = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{author.id}/summary",
                    headers=admin,
                    params={"scope": "author", "period": "1w"},
                )
                assert hidden.status_code == 200
                assert hidden.json()["recorded_hook_runs"]["value"] is None
                assert hidden.json()["recorded_hook_runs"]["status"] == "not_recorded"
                async with async_session() as db:
                    await db.execute(text("UPDATE hook_listings SET is_private=false WHERE id=:id"), {"id": hook_id})
                    await db.commit()
                refreshed = await client.post(
                    "/api/v1/auth/token/refresh", json={"refresh_token": actor_mobile["refresh_token"]}
                )
                assert refreshed.status_code == 200
                replay = await client.post(
                    "/api/v1/auth/token/refresh", json={"refresh_token": actor_mobile["refresh_token"]}
                )
                assert replay.status_code == 401
                renewed = {"Authorization": "Bearer " + refreshed.json()["access_token"]}
                assert (await client.get("/api/v1/auth/mobile/credential", headers=renewed)).status_code == 200
                logged_out = await client.post(
                    "/api/v1/auth/mobile/logout",
                    headers=renewed,
                    json={"refresh_token": refreshed.json()["refresh_token"]},
                )
                assert logged_out.status_code == 200
                assert (await client.get("/api/v1/auth/mobile/credential", headers=renewed)).status_code == 401
                assert (
                    await client.post(
                        "/api/v1/auth/mobile/logout",
                        headers=admin,
                        json={"refresh_token": author_mobile["refresh_token"]},
                    )
                ).status_code == 200
            if joint:
                # Local Android owner obtains passwords from the protected file,
                # starts new device grants, then records the app result. This
                # process retains the actual Pi source until ack or fixed TTL.
                handoff = Path("/tmp/observal-mobile-joint")
                assert handoff.is_dir() and handoff.stat().st_mode & 0o077 == 0
                done = handoff / "owner-done"
                assert not done.exists()
                until = datetime.now(UTC) + timedelta(hours=4)
                record = {
                    "expires_at": until.isoformat(),
                    "origin": https_origin,
                    "author": {
                        "id": str(author.id),
                        "email": author.email,
                        "password": author_password,
                        "username": author.username,
                        "role": "admin",
                    },
                    "actor": {
                        "id": str(actor.id),
                        "email": actor.email,
                        "password": actor_password,
                        "username": actor.username,
                        "role": "user",
                    },
                    "session": session,
                    "root_run_incarnation": str(roots[0]),
                    "components": {"mcp": str(mcp_id), "skill": str(skill_id), "hook": str(hook_id)},
                }
                destination = handoff / "owner.json"
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    json.dump(record, output)
                print("ANDROID_JOINT_READY", until.isoformat(), flush=True)
                while datetime.now(UTC) < until and not done.is_file():
                    await asyncio.sleep(2)
                print("ANDROID_JOINT_COMPLETED" if done.is_file() else "ANDROID_JOINT_EXPIRED", flush=True)
    finally:
        if opened:
            async with async_session() as db:
                await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('mobile-read:default',0))"))
                await db.execute(
                    text(
                        "UPDATE mobile_read_controls SET blocked=true,generation=generation+1,"
                        "updated_at=now() WHERE project_id='default'"
                    )
                )
                await db.commit()
        if os.getenv("MOBILE_INTEGRATION_V3_HTTPS") == "1":
            import services.dynamic_settings as ds
            from models.enterprise_config import EnterpriseConfig

            reset_keys = (
                "mobile.auth_enabled",
                "mobile.synthetic_test_enabled",
                "mobile.synthetic_test_server_id",
                "mobile.synthetic_test_viewer_id",
                "mobile.synthetic_test_self_user_viewer_id",
                "mobile.synthetic_test_ack",
            )
            async with async_session() as db:
                for key in reset_keys:
                    setting = await db.scalar(select(EnterpriseConfig).where(EnterpriseConfig.key == key))
                    if setting is not None:
                        setting.value = "false" if key.endswith("_enabled") else ""
                await db.commit()
            for key in reset_keys:
                await ds.invalidate(key)
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
