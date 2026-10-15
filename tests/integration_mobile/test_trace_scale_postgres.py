# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real PostgreSQL synthetic trace-union/overlap test (rollback only).

Run against an ISOLATED disposable database already migrated through 051:
MOBILE_INTEGRATION_SCALE=1 pytest tests/integration_mobile/test_trace_scale_postgres.py -q
Never run against a shared or production database. No JSONL/source is stored.
"""

import hashlib
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_INTEGRATION_SCALE") != "1", reason="isolated PostgreSQL only")

AUTHOR = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-author")
OTHER = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-actor")
A = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-component-a")
B = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-component-b")
VA = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-version-a")
VB = uuid.uuid5(uuid.NAMESPACE_DNS, "observal-trace-scale-version-b")
LAYER = "v2_" + "b" * 64


@pytest.mark.asyncio(loop_scope="session")
async def test_100_follow_candidates_and_ten_thousand_distinct_actor_runs_with_overlap():
    from database import async_session
    from services.mobile_activity_query import trace_component_page, trace_pair_batch, trace_union

    # This transaction never commits. Its verified root witness flags are
    # SYNTHETIC acceptance fixtures, not a claim about an eligible live sender.
    async with async_session() as db:
        await db.execute(text("UPDATE mobile_read_controls SET blocked=false WHERE project_id='default'"))
        await db.execute(
            text("""
            INSERT INTO users(id,email,username,name,role,created_at)
            SELECT CASE WHEN n=1 THEN :author WHEN n=2 THEN :other ELSE md5('mobile-scale-author:'||n)::uuid END,
                   'mobile-scale-'||n||'@example.invalid', 'mobile_scale_'||lpad(n::text,3,'0'),
                   'Synthetic '||n, 'user'::userrole, now()
            FROM generate_series(1,100) n
        """),
            {"author": AUTHOR, "other": OTHER},
        )
        for ident, version, suffix in ((A, VA, "a"), (B, VB, "b")):
            await db.execute(
                text("""
                INSERT INTO mcp_listings(id,name,namespace,slug,category,owner,is_private,submitted_by,
                    co_authors,unique_agents,created_at,updated_at)
                VALUES (:id,:name,'mobile_scale',:slug,'tools','synthetic',false,:author,'[]'::json,0,now(),now())
            """),
                {"id": ident, "name": "Synthetic " + suffix, "slug": "component-" + suffix, "author": AUTHOR},
            )
            await db.execute(
                text("""
                INSERT INTO mcp_versions(id,listing_id,version,description,mcp_validated,
                    supported_harnesses,status,download_count,released_by,released_at,created_at,is_editing)
                VALUES (:id,:listing,'1.0.0','synthetic',true,'["pi"]'::json,'approved'::listingstatus,
                    0,:author,now()-INTERVAL '2 days',now()-INTERVAL '2 days',false)
            """),
                {"id": version, "listing": ident, "author": AUTHOR},
            )
        await db.execute(
            text("""
            UPDATE mobile_publication_events SET recorded_at=now()-INTERVAL '2 days'
            WHERE kind='mcp' AND version_id IN (:va,:vb)
        """),
            {"va": VA, "vb": VB},
        )
        for user in (AUTHOR, OTHER):
            await db.execute(
                text("""
                INSERT INTO mobile_verified_layers(project_id,user_id,harness,layer_hash,expected_components)
                VALUES ('default',:user,'pi',:hash,2)
            """),
                {"user": user, "hash": LAYER},
            )
            for alias, component, version in (("alpha", A, VA), ("beta", B, VB)):
                await db.execute(
                    text("""
                    INSERT INTO mobile_layer_components(project_id,user_id,harness,layer_hash,alias,component_id,version_id)
                    VALUES ('default',:user,'pi',:hash,:alias,:component,:version)
                """),
                    {"user": user, "hash": LAYER, "alias": alias, "component": component, "version": version},
                )
        await db.execute(
            text("""
            INSERT INTO mobile_run_instances(project_id,user_id,harness,session_id,run_incarnation,
                header_hash,root_verified,source_status)
            SELECT 'default',CASE WHEN n<=6000 THEN CAST(:other AS uuid) ELSE CAST(:author AS uuid) END,'pi',
                   'mobile-scale-'||n,md5('mobile-scale-run:'||n)::uuid,
                   repeat('a',64),true,'complete'
            FROM generate_series(1,10000) n
        """),
            {"author": AUTHOR, "other": OTHER},
        )
        await db.execute(
            text("""
            INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,source_revision,status)
            SELECT project_id,user_id,harness,session_id,repeat('a',64),'complete'
            FROM mobile_run_instances WHERE session_id LIKE 'mobile-scale-%'
        """)
        )
        await db.execute(
            text("""
            INSERT INTO mobile_evidence_events(project_id,user_id,harness,session_id,source_line_offset,
                block_key,layer_hash,alias,component_id,root_session_id,run_incarnation,root_run_incarnation,
                event_time,result_state)
            SELECT r.project_id,r.user_id,'pi',r.session_id,0,'id:alpha',:hash,'alpha',:component,
                   r.session_id,r.run_incarnation,r.run_incarnation,now()-INTERVAL '1 day','success'
            FROM mobile_run_instances r WHERE r.session_id LIKE 'mobile-scale-%'
        """),
            {"hash": LAYER, "component": A},
        )
        await db.execute(
            text("""
            INSERT INTO mobile_evidence_events(project_id,user_id,harness,session_id,source_line_offset,
                block_key,layer_hash,alias,component_id,root_session_id,run_incarnation,root_run_incarnation,
                event_time,result_state)
            SELECT r.project_id,r.user_id,'pi',r.session_id,1,'id:beta',:hash,'beta',:component,
                   r.session_id,r.run_incarnation,r.run_incarnation,now()-INTERVAL '1 day','success'
            FROM mobile_run_instances r WHERE r.session_id LIKE 'mobile-scale-%'
            AND substring(r.session_id from 14)::int%5=0
        """),
            {"hash": LAYER, "component": B},
        )
        await db.execute(
            text("""
            INSERT INTO mobile_evidence_events(project_id,user_id,harness,session_id,source_line_offset,
                block_key,layer_hash,alias,component_id,root_session_id,run_incarnation,root_run_incarnation,
                event_time,result_state)
            SELECT r.project_id,r.user_id,'pi',r.session_id,extra.n+1,
                   'id:extra-'||extra.n,:hash,'alpha',:component,
                   r.session_id,r.run_incarnation,r.run_incarnation,now()-INTERVAL '1 day','success'
            FROM mobile_run_instances r CROSS JOIN generate_series(1,39) extra(n)
            WHERE r.session_id='mobile-scale-1'
        """),
            {"hash": LAYER, "component": A},
        )
        for table in ("mobile_evidence_events", "mobile_run_instances", "mobile_session_publications"):
            await db.execute(text(f"ANALYZE {table}"))
        await db.execute(text("SET LOCAL statement_timeout='15000ms'"))
        print("scale_fixture_ready", flush=True)
        start, end = datetime.now(UTC) - timedelta(days=7), datetime.now(UTC)
        tick = time.perf_counter()
        author = await trace_union(db, AUTHOR, "author", "default", start, end)
        print("scale_author_union_ms", round((time.perf_counter() - tick) * 1000), flush=True)
        tick = time.perf_counter()
        own = await trace_union(db, AUTHOR, "user", "default", start, end, viewer_self=True)
        print("scale_own_union_ms", round((time.perf_counter() - tick) * 1000), flush=True)
        assert author and own and (author["roots"], own["roots"]) == (10000, 4000)
        assert author["calls"] == 12039 and own["calls"] == 4800
        forty = await db.scalar(
            text("SELECT count(*) FROM mobile_evidence_events WHERE session_id='mobile-scale-1' AND component_id=:id"),
            {"id": A},
        )
        assert forty == 40  # Forty calls are exactly one distinct root.
        print("scale_union_verified", author, own, flush=True)
        page = await trace_component_page(db, AUTHOR, "author", "default", start, end, limit=1)
        print("scale_first_page", page, flush=True)
        assert page and len(page) == 2
        after = (page[0]["roots"], page[0]["id"])
        last = await trace_component_page(db, AUTHOR, "author", "default", start, end, after=after, limit=1)
        print("scale_last_page", last, flush=True)
        assert last and len(last) == 1 and last[0]["id"] == B
        assert page[0]["roots"] + last[0]["roots"] > author["roots"], "component rows overlap union"
        # 100 bookmarked people; the viewport query only touches the 12
        # requested subjects and never performs per-card ClickHouse JSONL scans.
        sample = [AUTHOR, OTHER] + [
            uuid.UUID(hashlib.md5(f"mobile-scale-author:{n}".encode()).hexdigest()) for n in range(3, 101)
        ]
        if os.getenv("MOBILE_TRACE_EXPLAIN") == "1":
            from services.mobile_activity_query import _TRACE_APPROVED, _TRACE_FROM

            sql = (
                "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "
                "SELECT p.original_author_id, count(DISTINCT (e.user_id,e.root_run_incarnation)) AS roots, "
                "count(*) AS calls,count(DISTINCT (e.event_time AT TIME ZONE 'UTC')::date) AS days "
                + _TRACE_FROM
                + " AND p.original_author_id=:subject AND l.is_private=false "
                "AND v.status IN ('approved','archived') " + _TRACE_APPROVED + " GROUP BY p.original_author_id"
            )
            plan = (
                await db.execute(text(sql), {"project": "default", "start": start, "end": end, "subject": AUTHOR})
            ).scalar_one()[0]

            def walk(node, depth=0):
                print(
                    "plan",
                    depth,
                    node["Node Type"],
                    node.get("Relation Name"),
                    round(node.get("Actual Total Time", 0), 1),
                    "ms loops",
                    node.get("Actual Loops"),
                    "rows",
                    node.get("Actual Rows"),
                    "temp",
                    node.get("Temp Read Blocks", 0),
                    node.get("Temp Written Blocks", 0),
                    flush=True,
                )
                for child in node.get("Plans", []):
                    if depth < 7:
                        walk(child, depth + 1)

            print("plan_total_ms", round(plan["Execution Time"], 1), flush=True)
            walk(plan["Plan"])
        durations = []
        for _ in range(3):
            for index in range(0, len(sample), 12):
                tick = time.perf_counter()
                author_batch, user_batch = await trace_pair_batch(
                    db, sample[index : index + 12], AUTHOR, "default", start, end
                )
                if index == 0:
                    assert (author_batch[AUTHOR]["roots"], user_batch[AUTHOR]["roots"]) == (10000, 4000)
                    assert OTHER not in author_batch and user_batch[OTHER]["roots"] == 6000
                durations.append((time.perf_counter() - tick) * 1000)
        print(
            "isolated_pg_12_subject_p95_ms=",
            round(sorted(durations)[int((len(durations) - 1) * 0.95)], 1),
            "max_ms=",
            round(max(durations), 1),
        )
        # A private original-author listing is not a visible Author reading.
        # Its rows are visible in the submitter's own User scope only, not to
        # an administrator/other viewer inspecting that same actor.
        privacy_epoch = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        await db.execute(text("UPDATE mcp_listings SET is_private=true WHERE id=:id"), {"id": A})
        bumped = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        assert bumped == (privacy_epoch or 0) + 1, (privacy_epoch, bumped)
        authors, users = await trace_pair_batch(db, [AUTHOR, OTHER], AUTHOR, "default", start, end)
        assert authors[AUTHOR]["roots"] == 2000 and OTHER not in authors, authors
        assert users[AUTHOR]["roots"] == 4000 and users[OTHER]["roots"] == 1200, users
        _, other_view = await trace_pair_batch(db, [AUTHOR], OTHER, "default", start, end)
        assert other_view[AUTHOR]["roots"] == 800, other_view
        no_author, _ = await trace_pair_batch(db, [AUTHOR], AUTHOR, "default", start, end, include_author=False)
        assert not no_author
        await db.execute(text("UPDATE mcp_listings SET is_private=false WHERE id=:id"), {"id": A})
        review_epoch = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        await db.execute(text("UPDATE mcp_versions SET status='pending' WHERE id=:id"), {"id": VB})
        new_review_epoch = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        assert new_review_epoch > review_epoch, (review_epoch, new_review_epoch)  # Version and review-event triggers.
        assert await trace_component_page(db, AUTHOR, "author", "default", start, end, component=B) == []
        await db.execute(text("UPDATE mcp_versions SET status='approved' WHERE id=:id"), {"id": VB})
        before = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        await db.execute(text("UPDATE mobile_run_instances SET root_verified=false WHERE session_id='mobile-scale-1'"))
        after_epoch = await db.scalar(
            text(
                "SELECT epoch FROM mobile_scope_epochs WHERE project_id='default' AND subject_id=:id AND scope='author'"
            ),
            {"id": AUTHOR},
        )
        assert after_epoch == before + 1
        changed = await trace_union(db, AUTHOR, "author", "default", start, end)
        assert changed and changed["roots"] == 9999 and changed["calls"] == 11999
        await db.rollback()
