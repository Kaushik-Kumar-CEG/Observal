# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, rollback-only isolated PostgreSQL proof of intermediate Pi source expiry.

No new ClickHouse transcript is created: publication floors are explicitly
synthetic SQL fixtures and NEVER committed or served through the mobile API.
"""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTERMEDIATE_EXPIRY") != "1", reason="isolated loopback PG only")


@pytest.mark.asyncio
async def test_intermediate_parent_expiry_and_revocation_remove_child_from_typed_read_sql():
    from config import settings
    from database import async_session
    from services.mobile_activity_query import _trace_from

    url = make_url(settings.DATABASE_URL)
    assert (url.host, url.database) == ("127.0.0.1", "observal")
    assert 15000 <= url.port < 16000 and url.port == int(os.environ["MOBILE_INTERMEDIATE_PG_PORT"])
    owner_file = Path(os.environ["MOBILE_INTERMEDIATE_OWNER_FILE"]).resolve(strict=True)
    assert owner_file.name == "owner.json" and owner_file.parent.name.startswith("observal-mobile-")
    assert owner_file.parent.stat().st_mode & 0o077 == 0 and owner_file.stat().st_mode & 0o077 == 0
    owner = json.loads(owner_file.read_text())
    assert datetime.fromisoformat(owner["expires_at"]) > datetime.now(UTC)
    assert owner["author"]["email"].endswith("@demo.example")
    assert owner["actor"]["email"].endswith("@demo.example")
    actor, component = uuid.UUID(owner["actor"]["id"]), uuid.UUID(owner["components"]["mcp"])
    root, intermediate, child = (uuid.uuid4() for _ in range(3))
    suffix = uuid.uuid4().hex
    names = ["mobile-probe-root-" + suffix, "mobile-probe-middle-" + suffix, "mobile-probe-child-" + suffix]
    headers = ["a" * 64, "b" * 64, "c" * 64]
    now = datetime.now(UTC)
    async with async_session() as db:
        assert await db.scalar(text("SELECT blocked FROM mobile_read_controls WHERE project_id='default'")) is True
        assert (
            await db.scalar(
                text("SELECT count(*) FROM users WHERE email NOT LIKE '%@demo.example' AND id NOT IN (:actor,:author)"),
                {"actor": actor, "author": uuid.UUID(owner["author"]["id"])},
            )
            == 0
        )
        source = (
            await db.execute(
                text(
                    "SELECT layer_hash,alias FROM mobile_evidence_events "
                    "WHERE user_id=:actor AND session_id=:session AND component_id=:component LIMIT 1"
                ),
                {"actor": actor, "session": owner["session"], "component": component},
            )
        ).one()
        for index, (nonce, session) in enumerate(zip((root, intermediate, child), names, strict=True)):
            await db.execute(
                text(
                    "INSERT INTO mobile_run_instances(project_id,user_id,harness,session_id,run_incarnation,"
                    "header_hash,parent_session_id,parent_run_incarnation,parent_header_hash,started_at,"
                    "root_verified,source_status) VALUES ('default',:actor,'pi',:session,:nonce,:header,:parent,"
                    ":parent_nonce,:parent_hash,:started,:verified,'complete')"
                ),
                {
                    "actor": actor,
                    "session": session,
                    "nonce": nonce,
                    "header": headers[index],
                    "parent": names[index - 1] if index else None,
                    "parent_nonce": (root, intermediate)[index - 1] if index else None,
                    "parent_hash": headers[index - 1] if index else None,
                    "started": now - timedelta(minutes=5 - index),
                    "verified": index == 0,
                },
            )
            await db.execute(
                text(
                    "INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,"
                    "source_revision,status,source_retained_until) "
                    "VALUES ('default',:actor,'pi',:session,:revision,'complete',now()+interval '29 days')"
                ),
                {"actor": actor, "session": session, "revision": "d" * 64},
            )
        await db.execute(
            text(
                "INSERT INTO mobile_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                "block_key,layer_hash,alias,component_id,root_session_id,run_incarnation,root_run_incarnation,"
                "event_time,result_state) VALUES ('default',:actor,'pi',:child,0,'id:lineage',:layer,:alias,"
                ":component,:root_session,:child_nonce,:root_nonce,:event,'success')"
            ),
            {
                "actor": actor,
                "child": names[2],
                "layer": source.layer_hash,
                "alias": source.alias,
                "component": component,
                "root_session": names[0],
                "child_nonce": child,
                "root_nonce": root,
                "event": now - timedelta(seconds=1),
            },
        )
        sql = text(
            "SELECT count(*) "
            + _trace_from("mcp")
            + " AND e.session_id=:child AND e.user_id=:actor AND l.id=:component "
            "AND approval.status='approved'"
        )
        params = {
            "project": "default",
            "start": now - timedelta(days=7),
            "end": now + timedelta(minutes=1),
            "child": names[2],
            "actor": actor,
            "component": component,
        }

        async def count():
            return await db.scalar(sql, params)

        assert await count() == 1
        await db.execute(
            text(
                "UPDATE mobile_session_publications SET source_retained_until=now()-interval '1 second' "
                "WHERE session_id=:session"
            ),
            {"session": names[1]},
        )
        assert await count() == 0, "expired intermediate raw source must remove grandchild positive immediately"
        await db.execute(
            text(
                "UPDATE mobile_session_publications SET source_retained_until=now()+interval '29 days',"
                "status='pending_mapping' WHERE session_id=:session"
            ),
            {"session": names[1]},
        )
        assert await count() == 0, "parent revocation must not wait for child queue"
        await db.execute(
            text("UPDATE mobile_session_publications SET status='complete' WHERE session_id=:session"),
            {"session": names[1]},
        )
        assert await count() == 1
        await db.execute(
            text(
                "UPDATE mobile_session_publications SET source_retained_until=now()-interval '1 second' "
                "WHERE session_id=:session"
            ),
            {"session": names[0]},
        )
        assert await count() == 0, "expired root must also invalidate its grandchild"
        await db.execute(
            text(
                "UPDATE mobile_session_publications SET source_retained_until=now()+interval '29 days' "
                "WHERE session_id=:session"
            ),
            {"session": names[0]},
        )
        assert await count() == 1
        await db.execute(text("DELETE FROM mobile_run_instances WHERE session_id=:session"), {"session": names[1]})
        assert await count() == 0, "missing intermediate run must not silently shorten verified lineage"
        await db.rollback()


def test_every_typed_kind_uses_same_intermediate_guard():
    from services.mobile_activity_query import _trace_from

    for kind in ("mcp", "skill", "hook"):
        sql = _trace_from(kind)
        assert "WITH RECURSIVE chain AS" in sql
        assert "ancestor_pub.source_retained_until>now()" in sql
        assert "ancestor_pub.status IN ('complete','partial')" in sql
