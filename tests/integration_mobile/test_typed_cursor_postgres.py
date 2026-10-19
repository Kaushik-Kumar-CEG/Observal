# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Isolated PostgreSQL retained-data upgrade and typed child cursor invalidation."""

import asyncio
import hashlib
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.skipif(os.getenv("MOBILE_MIGRATION_SCRATCH") != "1", reason="disposable loopback PG only")


@pytest.mark.asyncio(loop_scope="session")
async def test_skill_hook_only_child_revisions_change_on_ancestor_and_clock_expiry(tmp_path, monkeypatch):
    from api.routes import mobile_activity as route
    from api.routes.mobile_activity import _scope_revision
    from models import Base
    from models.hook import HookListing, HookVersion
    from models.skill import SkillListing, SkillVersion
    from models.user import User, UserRole
    from services.crypto import init_key_manager
    from services.mobile_activity_query import trace_component_page, trace_union

    # Only the direct typed-query proof bypasses the closed barrier in this
    # unique scratch database; no API grant is issued or request is served.
    monkeypatch.setattr("services.mobile_read_control.readable", AsyncMock(return_value=True))

    base = make_url(os.environ["DATABASE_URL"])
    assert (base.host, base.port, base.database) == ("127.0.0.1", 15440, "observal")
    database = "mobile_cursor_scratch_" + uuid.uuid4().hex[:12]
    admin = create_async_engine(base, isolation_level="AUTOCOMMIT")
    created = False
    try:
        async with admin.connect() as conn:
            await conn.execute(text("CREATE DATABASE " + database))
            created = True
        target = base.set(database=database)
        engine = create_async_engine(target)
        try:
            async with engine.begin() as conn:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                await conn.run_sync(Base.metadata.create_all)
            env = os.environ.copy()
            env["DATABASE_URL"] = target.render_as_string(hide_password=False)
            for args in (("stamp", "044_review_orphan_authors"), ("upgrade", "065_mobile_synthetic_deadline")):
                subprocess.run(
                    [sys.executable, "-m", "alembic", *args], env=env, check=True, capture_output=True, timeout=120
                )
            init_key_manager(key_dir=str(tmp_path / "keys"), key_password=None)
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            author = User(
                id=uuid.uuid4(),
                email="author@cursor.invalid",
                username="cursor_author",
                name="Author",
                role=UserRole.super_admin,
            )
            actor = User(
                id=uuid.uuid4(), email="actor@cursor.invalid", username="cursor_actor", name="Actor", role=UserRole.user
            )
            skill = SkillListing(
                id=uuid.uuid4(),
                name="Isolated cursor skill",
                namespace="cursor_probe",
                slug="skill",
                owner="synthetic",
                is_private=False,
                submitted_by=author.id,
                co_authors=[],
                unique_agents=0,
            )
            hook = HookListing(
                id=uuid.uuid4(),
                name="Isolated cursor hook",
                namespace="cursor_probe",
                slug="hook",
                owner="synthetic",
                is_private=False,
                submitted_by=author.id,
                co_authors=[],
                unique_agents=0,
            )
            approved_at = datetime.now(UTC) - timedelta(days=2)
            skill_version = SkillVersion(
                id=uuid.uuid4(),
                listing_id=skill.id,
                version="1.0.0",
                description="synthetic",
                status="approved",
                released_by=author.id,
                released_at=approved_at,
                supported_harnesses=["pi"],
                skill_md_content="---\nname: cursor\n---\n",
                skill_path="/SKILL.md",
                delivery_mode="inline",
                validated=True,
                target_agents=[],
                task_type="general",
                extra_files=[],
                download_count=0,
            )
            hook_version = HookVersion(
                id=uuid.uuid4(),
                listing_id=hook.id,
                version="1.0.0",
                description="synthetic",
                status="approved",
                released_by=author.id,
                released_at=approved_at,
                supported_harnesses=["pi"],
                event="PreToolUse",
                handler_type="command",
                handler_config={"command": "test-only-not-executed"},
            )
            root, middle, child = (uuid.uuid4() for _ in range(3))
            sessions_ids = ["cursor-root-" + database, "cursor-middle-" + database, "cursor-child-" + database]
            layer = "v3_" + "a" * 64
            binding = hashlib.sha256(b"test-only-hook-binding").hexdigest()
            revision = "a" * 64
            async with sessions() as db:
                db.add_all([actor, author])
                await db.flush()
                db.add_all([skill, hook])
                await db.flush()
                db.add_all([skill_version, hook_version])
                await db.commit()
                # Event-time approval must predate the synthetic child fact;
                # approved current listing state alone never qualifies a call.
                await db.execute(
                    text(
                        "UPDATE mobile_publication_events SET recorded_at=now()-interval '2 days' "
                        "WHERE version_id IN (:skill,:hook)"
                    ),
                    {"skill": skill_version.id, "hook": hook_version.id},
                )
                await db.commit()
                await db.execute(
                    text(
                        "INSERT INTO mobile_verified_layers(project_id,user_id,harness,layer_hash,expected_components,expected_skills,expected_hooks) "
                        "VALUES ('default',:actor,'pi',:layer,0,1,1)"
                    ),
                    {"actor": actor.id, "layer": layer},
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_skill_layer_components(project_id,user_id,harness,layer_hash,scope,alias,"
                        "component_id,version_id,location_sha256,content_sha256) VALUES "
                        "('default',:actor,'pi',:layer,'user','cursor',:component,:version,:digest,:digest)"
                    ),
                    {
                        "actor": actor.id,
                        "layer": layer,
                        "component": skill.id,
                        "version": skill_version.id,
                        "digest": "b" * 64,
                    },
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_hook_layer_components(project_id,user_id,harness,layer_hash,binding_sha256,"
                        "event,alias,component_id,version_id) VALUES "
                        "('default',:actor,'pi',:layer,:binding,'tool_call','cursor-hook',:component,:version)"
                    ),
                    {
                        "actor": actor.id,
                        "layer": layer,
                        "binding": binding,
                        "component": hook.id,
                        "version": hook_version.id,
                    },
                )
                for i, run in enumerate((root, middle, child)):
                    await db.execute(
                        text(
                            "INSERT INTO mobile_run_instances(project_id,user_id,harness,session_id,run_incarnation,"
                            "header_hash,parent_session_id,parent_run_incarnation,parent_header_hash,started_at,"
                            "root_verified,source_status) VALUES ('default',:actor,'pi',:session,:run,:header,:parent,"
                            ":parent_run,:parent_header,:started,:verified,'complete')"
                        ),
                        {
                            "actor": actor.id,
                            "session": sessions_ids[i],
                            "run": run,
                            "header": chr(97 + i) * 64,
                            "parent": sessions_ids[i - 1] if i else None,
                            "parent_run": (root, middle)[i - 1] if i else None,
                            "parent_header": chr(96 + i) * 64 if i else None,
                            "started": approved_at + timedelta(hours=i),
                            "verified": i == 0,
                        },
                    )
                    await db.execute(
                        text(
                            "INSERT INTO mobile_session_publications(project_id,user_id,harness,session_id,source_revision,"
                            "status,source_retained_until) VALUES ('default',:actor,'pi',:session,:revision,'complete',"
                            "clock_timestamp()+interval '28 days')"
                        ),
                        {"actor": actor.id, "session": sessions_ids[i], "revision": revision},
                    )
                params = {
                    "actor": actor.id,
                    "child": sessions_ids[2],
                    "child_run": child,
                    "root": root,
                    "root_session": sessions_ids[0],
                    "layer": layer,
                    "revision": revision,
                    "event_time": datetime.now(UTC) - timedelta(seconds=1),
                }
                await db.execute(
                    text(
                        "INSERT INTO mobile_skill_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                        "block_key,layer_hash,scope,alias,component_id,source_revision,run_incarnation,root_session_id,"
                        "root_run_incarnation,event_time,result_state) VALUES ('default',:actor,'pi',:child,1,'id:skill',"
                        ":layer,'user','cursor',:component,:revision,:child_run,:root_session,:root,:event_time,'success')"
                    ),
                    {**params, "component": skill.id},
                )
                await db.execute(
                    text(
                        "INSERT INTO mobile_hook_evidence_events(project_id,user_id,harness,session_id,source_line_offset,"
                        "block_key,layer_hash,binding_sha256,component_id,source_revision,run_incarnation,root_session_id,"
                        "root_run_incarnation,event_time,outcome) VALUES ('default',:actor,'pi',:child,2,'id:hook',"
                        ":layer,:binding,:component,:revision,:child_run,:root_session,:root,:event_time,'ran')"
                    ),
                    {**params, "binding": binding, "component": hook.id},
                )
                await db.commit()
            subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                env=env,
                check=True,
                capture_output=True,
                timeout=120,
            )
            async with sessions() as db:
                assert (
                    await db.scalar(
                        text(
                            "SELECT count(*) FROM mobile_author_actor_links WHERE author_id=:author AND actor_id=:actor"
                        ),
                        {"author": author.id, "actor": actor.id},
                    )
                    == 1
                )
                author_viewer = SimpleNamespace(id=author.id, role=UserRole.super_admin)
                user_viewer = SimpleNamespace(id=actor.id, role=UserRole.user)
                anchor = "isolated-anchored-1w"
                start, end = datetime.now(UTC) - timedelta(days=7), datetime.now(UTC) + timedelta(minutes=1)
                window = route.Window(start=start, end=end, as_of=end, period="1w")
                monkeypatch.setattr(route, "_paired_window", lambda *_args: (window, anchor))
                monkeypatch.setattr(route, "_authorize", AsyncMock(return_value=True))
                monkeypatch.setattr(route, "readable", AsyncMock(return_value=True))
                monkeypatch.setattr(route, "_synthetic_subjects", AsyncMock(return_value=None))

                async def revisions():
                    return (
                        await _scope_revision(db, user_viewer, actor.id, "user", anchor),
                        await _scope_revision(db, author_viewer, author.id, "author", anchor),
                    )

                async def assert_old_page_and_detail_stale(old, *, scopes=("user", "author")):
                    for scope, subject, viewer, revision_old in (
                        ("user", actor.id, user_viewer, old[0]),
                        ("author", author.id, author_viewer, old[1]),
                    ):
                        if scope not in scopes:
                            continue
                        with pytest.raises(HTTPException) as page_error:
                            await route.components(subject, scope, "1w", anchor, revision_old, None, db, viewer)
                        assert page_error.value.status_code == 409 and page_error.value.detail == "stale_cursor"
                        for kind, component in (("skill", skill.id), ("hook", hook.id)):
                            with pytest.raises(HTTPException) as detail_error:
                                await route.component_detail(
                                    subject, scope, kind, component, "1w", anchor, revision_old, db, viewer
                                )
                            assert detail_error.value.status_code == 409 and detail_error.value.detail == "stale_cursor"

                async def counts():
                    user = await trace_union(db, actor.id, "user", "default", start, end, viewer_self=True)
                    authored = await trace_union(db, author.id, "author", "default", start, end)
                    return user, authored

                first = await revisions()
                await db.execute(
                    text(
                        "UPDATE mobile_session_publications SET last_checked_at=clock_timestamp() "
                        "WHERE session_id=:middle"
                    ),
                    {"middle": sessions_ids[1]},
                )
                assert await revisions() == first  # unchanged retention sweep must preserve pagination
                first_author_page = await route.components(
                    author.id, "author", "1w", anchor, first[1], None, db, author_viewer
                )
                first_user_page = await route.components(
                    actor.id, "user", "1w", anchor, first[0], None, db, user_viewer
                )
                assert len(first_author_page.items) == len(first_user_page.items) == 2
                user, authored = await counts()
                assert user and authored and user["roots"] == authored["roots"] == 1
                assert user["skill_loads"] == authored["skill_loads"] == 1
                assert user["hook_runs"] == authored["hook_runs"] == 1
                assert user["calls"] == authored["calls"] == 0
                initial_rows = await trace_component_page(db, author.id, "author", "default", start, end, limit=10)
                assert initial_rows and {row["kind"] for row in initial_rows} == {"skill", "hook"}
                assert sum(row["roots"] for row in initial_rows) == 2  # overlapping rows, one union root
                for account in (actor.id, author.id):
                    before_status = (await revisions())[1]
                    await db.execute(text("UPDATE users SET auth_provider='deactivated' WHERE id=:id"), {"id": account})
                    updated = await revisions()
                    assert updated[1] != before_status
                    if account == author.id:
                        assert updated[0] != first[0]  # original author gates the actor's User scope
                        await assert_old_page_and_detail_stale(first)
                    else:
                        await assert_old_page_and_detail_stale((first[0], before_status), scopes=("author",))
                    assert (await counts())[1] is None
                    await db.execute(text("UPDATE users SET auth_provider='local' WHERE id=:id"), {"id": account})
                    assert (await counts())[1] is not None
                first = await revisions()
                await db.execute(
                    text(
                        "UPDATE mobile_skill_evidence_events SET event_time=clock_timestamp()-interval '8 days' "
                        "WHERE block_key='id:skill'"
                    ),
                )
                assert (await revisions())[0] != first[0] and (await revisions())[1] != first[1]
                await assert_old_page_and_detail_stale(first)
                assert (await counts())[0]["skill_loads"] == 0
                await db.execute(
                    text(
                        "UPDATE mobile_skill_evidence_events SET event_time=clock_timestamp()-interval '1 second' "
                        "WHERE block_key='id:skill'"
                    ),
                )
                first = await revisions()
                for kind, listing in (("skill", skill.id), ("hook", hook.id)):
                    table = "skill_listings" if kind == "skill" else "hook_listings"
                    await db.execute(
                        text(f"UPDATE {table} SET is_private=true,submitted_by=:actor WHERE id=:listing"),
                        {"actor": actor.id, "listing": listing},
                    )
                    owner_revision = await revisions()
                    await db.execute(
                        text(f"UPDATE {table} SET submitted_by=:author WHERE id=:listing"),
                        {"author": author.id, "listing": listing},
                    )
                    assert (await revisions())[0] != owner_revision[0]
                    await assert_old_page_and_detail_stale(owner_revision, scopes=("user",))
                    await db.execute(
                        text(f"UPDATE {table} SET is_private=false,submitted_by=:author WHERE id=:listing"),
                        {"author": author.id, "listing": listing},
                    )
                first = await revisions()
                with pytest.raises(DBAPIError):
                    async with db.begin_nested():
                        await db.execute(
                            text(
                                "UPDATE mobile_listing_provenance SET original_author_id=:actor "
                                "WHERE kind='skill' AND listing_id=:skill"
                            ),
                            {"actor": actor.id, "skill": skill.id},
                        )
                assert await revisions() == first  # ownership transfer may never rewrite original authorship
                before_delete = first
                await db.execute(
                    text("DELETE FROM mobile_listing_provenance WHERE kind='skill' AND listing_id=:skill"),
                    {"skill": skill.id},
                )
                after_delete = await revisions()
                assert after_delete[1] != before_delete[1] and after_delete[0] != before_delete[0]
                await assert_old_page_and_detail_stale(before_delete)
                await db.execute(
                    text(
                        "INSERT INTO mobile_listing_provenance(kind,listing_id,original_author_id) "
                        "VALUES ('skill',:skill,:author)"
                    ),
                    {"author": author.id, "skill": skill.id},
                )
                assert (await revisions())[0] != after_delete[0]
                first = await revisions()
                await db.commit()

                # Interleave two independent READ COMMITTED transactions in
                # both orders. Each trigger sees the other side only AFTER its
                # transaction-level listing lock is released by a commit.
                async def insert_concurrent_fact(fact_db, offset):
                    await fact_db.execute(
                        text(
                            "INSERT INTO mobile_skill_evidence_events(project_id,user_id,harness,session_id,"
                            "source_line_offset,block_key,layer_hash,scope,alias,component_id,source_revision,"
                            "run_incarnation,root_session_id,root_run_incarnation,event_time,result_state) "
                            "SELECT project_id,user_id,harness,session_id,:offset,:block,layer_hash,scope,alias,"
                            "component_id,source_revision,run_incarnation,root_session_id,root_run_incarnation,"
                            "event_time,result_state FROM mobile_skill_evidence_events "
                            "WHERE block_key='id:skill'"
                        ),
                        {"offset": offset, "block": f"id:skill-{offset}"},
                    )

                async def insert_concurrent_provenance(provenance_db):
                    await provenance_db.execute(
                        text(
                            "INSERT INTO mobile_listing_provenance(kind,listing_id,original_author_id) "
                            "VALUES ('skill',:skill,:author)"
                        ),
                        {"skill": skill.id, "author": author.id},
                    )

                for fact_first, offset in ((True, 11), (False, 12)):
                    await db.execute(
                        text("DELETE FROM mobile_listing_provenance WHERE kind='skill' AND listing_id=:skill"),
                        {"skill": skill.id},
                    )
                    await db.commit()
                    stale_author = (await revisions())[1]
                    await db.commit()
                    async with sessions() as fact_db, sessions() as provenance_db:
                        if fact_first:
                            await insert_concurrent_fact(fact_db, offset)
                            waiting = asyncio.create_task(insert_concurrent_provenance(provenance_db))
                            await asyncio.sleep(0.07)
                            assert not waiting.done(), "provenance must wait on fact's listing lock"
                            await fact_db.commit()
                            await asyncio.wait_for(waiting, timeout=3)
                            await provenance_db.commit()
                        else:
                            await insert_concurrent_provenance(provenance_db)
                            waiting = asyncio.create_task(insert_concurrent_fact(fact_db, offset))
                            await asyncio.sleep(0.07)
                            assert not waiting.done(), "fact must wait on provenance's listing lock"
                            await provenance_db.commit()
                            await asyncio.wait_for(waiting, timeout=3)
                            await fact_db.commit()
                    assert (await revisions())[1] != stale_author
                    assert (
                        await db.scalar(
                            text(
                                "SELECT count(*) FROM mobile_author_actor_links "
                                "WHERE author_id=:author AND actor_id=:actor"
                            ),
                            {"author": author.id, "actor": actor.id},
                        )
                        == 1
                    )
                    await db.commit()
                # Previously: fact T1 held the shared Author epoch while
                # delayed provenance T2 held another listing lock. A second
                # T1 fact for that listing then formed a deadlock cycle.
                await db.execute(
                    text("DELETE FROM mobile_listing_provenance WHERE kind='hook' AND listing_id=:hook"),
                    {"hook": hook.id},
                )
                await db.commit()
                async with sessions() as fact_db, sessions() as provenance_db:
                    await insert_concurrent_fact(fact_db, 13)
                    waiting = asyncio.create_task(
                        provenance_db.execute(
                            text(
                                "INSERT INTO mobile_listing_provenance(kind,listing_id,original_author_id) "
                                "VALUES ('hook',:hook,:author)"
                            ),
                            {"hook": hook.id, "author": author.id},
                        )
                    )
                    await asyncio.sleep(0.07)
                    assert not waiting.done()
                    await fact_db.execute(
                        text(
                            "INSERT INTO mobile_hook_evidence_events(project_id,user_id,harness,session_id,"
                            "source_line_offset,block_key,layer_hash,binding_sha256,component_id,source_revision,"
                            "run_incarnation,root_session_id,root_run_incarnation,event_time,outcome) "
                            "SELECT project_id,user_id,harness,session_id,13,'id:hook-13',layer_hash,"
                            "binding_sha256,component_id,source_revision,run_incarnation,root_session_id,"
                            "root_run_incarnation,event_time,outcome FROM mobile_hook_evidence_events "
                            "WHERE block_key='id:hook'"
                        ),
                    )
                    await fact_db.commit()
                    await asyncio.wait_for(waiting, timeout=3)
                    await provenance_db.commit()
                first = await revisions()
                await db.execute(
                    text("UPDATE mobile_run_instances SET source_status='pending_mapping' WHERE session_id=:middle"),
                    {"middle": sessions_ids[1]},
                )
                assert (await revisions()) != first  # both Author and User revisions changed
                await assert_old_page_and_detail_stale(first)
                user, authored = await counts()
                assert user is None and authored is None
                assert not await trace_component_page(db, author.id, "author", "default", start, end, limit=10)
                await db.execute(
                    text("UPDATE mobile_run_instances SET source_status='complete' WHERE session_id=:middle"),
                    {"middle": sessions_ids[1]},
                )
                recovered = await revisions()
                await db.execute(
                    text("UPDATE mobile_session_publications SET status='pending_mapping' WHERE session_id=:middle"),
                    {"middle": sessions_ids[1]},
                )
                assert (await revisions()) != recovered
                await assert_old_page_and_detail_stale(recovered)
                await db.execute(
                    text(
                        "UPDATE mobile_session_publications SET status='complete',"
                        "source_retained_until=clock_timestamp()+interval '0.3 seconds' WHERE session_id=:middle"
                    ),
                    {"middle": sessions_ids[1]},
                )
                await db.commit()
                before_clock = await revisions()
                assert (await counts())[0] is not None
                await asyncio.sleep(0.5)
                # Keep the same PostgreSQL transaction alive across expiry:
                # transaction-start now() would otherwise admit expired facts
                # under a freshly computed revision.
                assert (await revisions()) != before_clock  # NO write after the before_clock call
                await assert_old_page_and_detail_stale(before_clock)
                user, authored = await counts()
                assert user is None and authored is None
                assert not await trace_component_page(db, author.id, "author", "default", start, end, limit=10)
                await db.rollback()
                # Projection holds the writer gate; listing deletion must
                # wait BEFORE taking its FK row lock (no lock-order cycle).
                async with sessions() as fact_db, sessions() as listing_db:
                    await insert_concurrent_fact(fact_db, 14)
                    waiting = asyncio.create_task(
                        listing_db.execute(text("DELETE FROM skill_listings WHERE id=:skill"), {"skill": skill.id})
                    )
                    await asyncio.sleep(0.07)
                    assert not waiting.done()
                    await fact_db.commit()
                    await asyncio.wait_for(waiting, timeout=3)
                    await listing_db.rollback()
        finally:
            await engine.dispose()
    finally:
        if created:
            async with admin.connect() as conn:
                await conn.execute(text("DROP DATABASE " + database + " WITH (FORCE)"))
        await admin.dispose()
