# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed qualification gate for a future *genuine* Pi three-kind upload.

Evidence checks are read-only. Login/device authorization creates short-lived
OAuth state for two disposable identities, but does not alter follow consent.
This does NOT synthesize session lines, approve listings, or upload evidence. Run
only after an independently started disposable QA session and real Pi sender run.
No success message is printed until both authenticated viewers and retained raw
sources qualify. In particular, it must not be wired into up.sh as a flag override.
"""

import asyncio
import json
import os
import re
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
from sqlalchemy import text
from sqlalchemy.engine import make_url

from database import async_session, engine
from jobs.mobile_evidence import _policy_source_complete, _revision, _rows, _source_retained_until
from observal_shared.migration.constants import DEFAULT_PROJECT_ID
from services.clickhouse.client import _query

KINDS = ("mcp", "skill", "hook")
EXPECTED = {"mcp_calls", "confirmed_skill_loads", "recorded_hook_runs"}
ISSUER_PORT = int(os.environ.get("MOBILE_FOLLOW_QA_PORT", "18443"))
ORIGIN = f"https://localhost:{ISSUER_PORT}"


def require_disposable_environment() -> Path:
    pg = make_url(os.environ["DATABASE_URL"])
    ch = urlsplit(os.environ["CLICKHOUSE_URL"])
    qa = Path(__file__).resolve().parent
    state_name = os.environ.get("MOBILE_FOLLOW_QA_STATE_NAME", ".runtime")
    expected_port = (
        18443
        if state_name == ".runtime"
        else 18446
        if re.fullmatch(r"\.runtime-android-[0-9a-f]{6,12}", state_name)
        else 18448
        if re.fullmatch(r"\.runtime-android-next-[0-9a-f]{6,12}", state_name)
        else 18449
        if re.fullmatch(r"\.runtime-android-diagnostic-[0-9a-f]{6,12}", state_name)
        else 18444
    )
    if not (
        state_name == ".runtime"
        or re.fullmatch(r"\.runtime-scratch-[0-9a-f]{6,12}", state_name)
        or re.fullmatch(r"\.runtime-android-[0-9a-f]{6,12}", state_name)
        or re.fullmatch(r"\.runtime-android-next-[0-9a-f]{6,12}", state_name)
        or re.fullmatch(r"\.runtime-android-diagnostic-[0-9a-f]{6,12}", state_name)
    ):
        raise RuntimeError("Invalid disposable QA state name")
    state = qa / state_name
    if (
        expected_port != ISSUER_PORT
        or os.environ.get("MOBILE_FOLLOW_LOCAL_QA") != "1"
        or pg.host != "127.0.0.1"
        or pg.database != "followqa"
        or pg.username != "followqa"
        or ch.scheme != "http"
        or ch.hostname != "127.0.0.1"
        or ch.path != "/followqa"
        or ch.username != "followqa"
        or not ch.port
        or state.is_symlink()
        or not (state / "id").is_file()
        or not (state / "run").is_file()
    ):
        raise RuntimeError("Only the disposable loopback follow QA database is permitted")
    session_id = (state / "id").read_text().strip()
    if (state / "issuer-port").read_text().strip() != str(ISSUER_PORT):
        raise RuntimeError("QA session port does not match selected issuer")
    if not re.fullmatch(r"followqa[0-9a-f]{10}", session_id):
        raise RuntimeError("Invalid disposable QA session identity")
    for suffix, port, requested in (("pg", 5432, pg.port), ("ch", 8123, ch.port)):
        name = session_id + suffix
        label = subprocess.run(
            ["docker", "inspect", "--format", '{{index .Config.Labels "observal.followqa.owner"}}', name],
            capture_output=True,
            text=True,
            check=True,
            timeout=8,
        ).stdout.strip()
        published = subprocess.run(
            ["docker", "port", name, f"{port}/tcp"],
            capture_output=True,
            text=True,
            check=True,
            timeout=8,
        ).stdout.strip()
        if label != session_id or published != f"127.0.0.1:{requested}":
            raise RuntimeError("Source verification refused unrelated loopback service")
    runtime = Path((state / "run").read_text().strip())
    if not runtime.is_dir() or runtime.parent != Path("/tmp") or not runtime.name.startswith("observal-follow-qa."):
        raise RuntimeError("Invalid disposable runtime directory")
    return runtime


async def verify_source(publication, policy_since: datetime, retention_days: int) -> None:
    user_id, session_id = str(publication.user_id), publication.session_id
    rows = await _rows(str(DEFAULT_PROJECT_ID), user_id, "pi", session_id)
    revision = _revision(rows or [])
    assert revision is not None and rows and rows[0]["line_offset"] == 0, "complete Pi raw source missing"
    assert revision == publication.source_revision, "projection revision differs from retained raw source"
    assert rows[-1]["line_offset"] == publication.source_highest_line, "publication source highwater differs"
    async with async_session() as db:
        scope = {"project": str(DEFAULT_PROJECT_ID), "user": publication.user_id, "session": session_id}
        highwater = await db.scalar(
            text(
                "SELECT max_line FROM mobile_source_line_highwater WHERE project_id=:project "
                "AND user_id=:user AND harness='pi' AND session_id=:session"
            ),
            scope,
        )
        final = (
            await db.execute(
                text(
                    "SELECT final_line,source_hash FROM mobile_source_final_receipts WHERE project_id=:project "
                    "AND user_id=:user AND harness='pi' AND session_id=:session"
                ),
                scope,
            )
        ).one_or_none()
    assert final is not None and _policy_source_complete(
        rows, revision, None, None, highwater, policy_since, final.final_line, final.source_hash
    ), "Pi raw source has no verified complete final receipt"
    floor = _source_retained_until(rows, revision, retention_days=retention_days)
    assert floor is not None and floor > datetime.now(UTC), "raw Pi source expired"
    assert publication.source_retained_until <= floor, "publication exceeds verified source TTL"


async def verify_db() -> dict[str, str]:
    async with async_session() as db:
        policy = (
            await db.execute(
                text(
                    "SELECT source_policy_ready,source_policy_since,source_policy_epoch,synthetic_expires_at "
                    "FROM mobile_read_controls WHERE project_id=:project"
                ),
                {"project": str(DEFAULT_PROJECT_ID)},
            )
        ).one()
        assert policy.source_policy_ready and policy.source_policy_since is not None, "source policy not verified"
        assert policy.synthetic_expires_at and policy.synthetic_expires_at > datetime.now(UTC), "QA cohort expired"
        configured = await db.scalar(text("SELECT value FROM enterprise_config WHERE key='data.retention_days'"))
        retention_days = int(configured) if configured is not None else 90
        assert 0 <= retention_days <= 36500, "invalid source retention"
        identities = (
            await db.execute(
                text("SELECT email,id FROM users WHERE email IN ('owner@follow-qa.invalid','viewer@follow-qa.invalid')")
            )
        ).all()
        users = {email: str(uid) for email, uid in identities}
        assert len(users) == 2, "both disposable identities required"
        sessions = (
            await db.execute(
                text(
                    "SELECT p.user_id,p.session_id,p.source_revision,p.source_retained_until,p.source_highest_line "
                    "FROM mobile_session_publications p WHERE p.project_id=:project AND p.harness='pi' "
                    "AND p.status IN ('complete','partial') AND p.source_policy_epoch=:epoch "
                    "AND p.source_retained_until>clock_timestamp() AND p.user_id=ANY(:users)"
                ),
                {
                    "project": str(DEFAULT_PROJECT_ID),
                    "epoch": policy.source_policy_epoch,
                    "users": [UUID(user) for user in users.values()],
                },
            )
        ).all()
        # Check evidence under each uploader, without inserting typed facts.
        # The worker and the protected read route remain responsible for
        # validating event provenance and approval at event time.
        for user_id in users.values():
            for kind in KINDS:
                table = {
                    "mcp": "mobile_evidence_events",
                    "skill": "mobile_skill_evidence_events",
                    "hook": "mobile_hook_evidence_events",
                }[kind]
                listing = {"mcp": "mcp", "skill": "skill", "hook": "hook"}[kind]
                count = await db.scalar(
                    text(
                        f"SELECT count(*) FROM {table} e JOIN {listing}_listings l ON l.id=e.component_id "
                        f"JOIN mobile_listing_provenance provenance ON provenance.kind='{kind}' "
                        "AND provenance.listing_id=e.component_id "
                        "JOIN mobile_session_publications p ON p.project_id=e.project_id AND p.user_id=e.user_id "
                        "AND p.harness=e.harness AND p.session_id=e.session_id "
                        "WHERE e.project_id=:project AND e.user_id=:user AND e.harness='pi' "
                        "AND e.root_run_incarnation IS NOT NULL AND l.is_private=false "
                        "AND p.status IN ('complete','partial') AND p.source_retained_until>clock_timestamp() "
                        "AND p.source_policy_epoch=:epoch"
                    ),
                    {"project": str(DEFAULT_PROJECT_ID), "user": UUID(user_id), "epoch": policy.source_policy_epoch},
                )
                assert count and count > 0, f"{kind} missing projected public fact for disposable uploader"
        owner_id = UUID(users["owner@follow-qa.invalid"])
        for kind in KINDS:
            table = {
                "mcp": "mobile_evidence_events",
                "skill": "mobile_skill_evidence_events",
                "hook": "mobile_hook_evidence_events",
            }[kind]
            authored = await db.scalar(
                text(
                    f"SELECT count(*) FROM {table} e JOIN mobile_listing_provenance provenance "
                    "ON provenance.listing_id=e.component_id AND provenance.kind=:kind "
                    "WHERE provenance.original_author_id=:owner AND e.project_id=:project "
                    "AND e.user_id=ANY(:users) AND e.harness='pi' AND e.root_run_incarnation IS NOT NULL"
                ),
                {
                    "kind": kind,
                    "owner": owner_id,
                    "project": str(DEFAULT_PROJECT_ID),
                    "users": [UUID(user) for user in users.values()],
                },
            )
            assert authored and authored > 0, f"{kind} lacks original-author provenance for disposable owner"
        sources = {(str(row.user_id), row.session_id) for row in sessions}
        assert all(any(user == uid for user, _ in sources) for uid in users.values()), "missing uploader publication"
    # Check actual ClickHouse source outside the database transaction; mobile
    # endpoints perform their own source revision check on each read.
    await asyncio.gather(*(verify_source(row, policy.source_policy_since, retention_days) for row in sessions))
    ddl = await _query(
        "SELECT create_table_query FROM system.tables WHERE database=currentDatabase() "
        "AND name='session_events' FORMAT JSON"
    )
    ddl.raise_for_status()
    actual = (ddl.json().get("data") or [{}])[0].get("create_table_query", "")
    clause = actual.split(" ENGINE =", 1)[-1]
    whole = rf"\bTTL\s+toDate\(timestamp\)\s*\+\s*toIntervalDay\({retention_days}\)"
    raw = r"`?raw_line`?\s+String(?:\s+CODEC\(ZSTD\(3\)\))?\s+TTL\s+timestamp\s*\+\s*toIntervalDay\(30\)"
    assert bool(re.search(whole, clause)) if retention_days else " TTL " not in clause, "whole-row TTL mismatch"
    assert re.search(raw, actual), "raw-line TTL mismatch"
    return users


async def verify_capabilities(runtime: Path, users: dict[str, str]) -> None:
    tls = ssl.create_default_context(cafile=str(runtime / "ca.crt"))
    async with httpx.AsyncClient(base_url=ORIGIN, verify=tls, trust_env=False, timeout=15) as client:
        password = (runtime / "password").read_text().strip()
        proofs: dict[str, dict[str, str]] = {}
        for email, user_id in users.items():
            login = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
            assert login.status_code == 200, f"disposable login failed: {login.status_code}"
            desktop = {"Authorization": "Bearer " + login.json()["access_token"], "Origin": ORIGIN}
            challenge = await client.post("/api/v1/auth/device/authorize", json={"client_id": "observal-mobile"})
            assert challenge.status_code == 200, f"device authorize failed: {challenge.status_code}"
            issued = challenge.json()
            confirmed = await client.post(
                "/api/v1/auth/device/confirm", headers=desktop, json={"user_code": issued["user_code"]}
            )
            assert confirmed.status_code == 200, f"device confirm failed: {confirmed.status_code}"
            redeemed = await client.post(
                "/api/v1/auth/device/token",
                json={
                    "device_code": issued["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            )
            assert redeemed.status_code == 200, f"device token failed: {redeemed.status_code}"
            mobile = {"Authorization": "Bearer " + redeemed.json()["access_token"]}
            proof = await client.get("/api/v1/auth/mobile/credential", headers=mobile)
            assert proof.status_code == 200 and proof.json()["subject_id"] == user_id
            token = redeemed.json()
            access_exp = datetime.fromtimestamp(
                jwt.decode(token["access_token"], options={"verify_signature": False})["exp"], UTC
            )
            refresh_exp = datetime.fromtimestamp(
                jwt.decode(token["refresh_token"], options={"verify_signature": False})["exp"], UTC
            )
            assert datetime.now(UTC) < access_exp <= datetime.now(UTC) + timedelta(days=1, seconds=60)
            assert refresh_exp > access_exp
            proofs[email] = {
                "subject_id": user_id,
                "probe_device_id": proof.json()["device_id"],
                "probe_mobile_access_expires_at": access_exp.isoformat(),
                "probe_mobile_refresh_expires_at": refresh_exp.isoformat(),
            }
            response = await client.get("/api/v1/mobile-activity/v1/capabilities", headers=mobile)
            assert response.status_code == 200, f"capabilities failed: {response.status_code}"
            capabilities = response.json()
            assert capabilities["viewer_id"] == user_id
            assert capabilities["synthetic_test_cohort"] is True, "cohort not qualified"
            assert set(capabilities["supported_kinds"]) == EXPECTED, "three-kind evidence not qualified"
            proofs[email]["capabilities_status"] = str(response.status_code)
            proofs[email]["synthetic_test_cohort"] = str(capabilities["synthetic_test_cohort"]).lower()
            proofs[email]["supported_kinds"] = ",".join(capabilities["supported_kinds"])
            own_scope = "author" if email.startswith("owner@") else "user"
            positive = await client.get(
                f"/api/v1/mobile-activity/v1/people/{user_id}/summary",
                params={"scope": own_scope, "period": "3m"},
                headers=mobile,
            )
            assert positive.status_code == 200, f"{own_scope} scoped read failed: {positive.status_code}"
            summary = positive.json()
            assert summary["component_trace_union"]["value"] > 0
            assert summary["confirmed_skill_loads"]["value"] > 0
            assert summary["recorded_hook_runs"]["value"] > 0
            proofs[email]["positive_scope"] = own_scope
            proofs[email]["positive_summary_status"] = str(positive.status_code)
            proofs[email]["positive_mcp_calls"] = str(summary["mcp_calls"]["value"])
            proofs[email]["positive_skill_loads"] = str(summary["confirmed_skill_loads"]["value"])
            proofs[email]["positive_hook_runs"] = str(summary["recorded_hook_runs"]["value"])
            if email.startswith("viewer@"):
                for subject_id, scope in ((user_id, "author"), (users["owner@follow-qa.invalid"], "user")):
                    denied = await client.get(
                        f"/api/v1/mobile-activity/v1/people/{subject_id}/summary",
                        params={"scope": scope, "period": "3m"},
                        headers=mobile,
                    )
                    assert denied.status_code == 403, "ordinary viewer gained foreign or Author scope"
                proofs[email]["self_author_status"] = "403"
                proofs[email]["foreign_user_status"] = "403"
            else:
                actor = users["viewer@follow-qa.invalid"]
                actor_read = await client.get(
                    f"/api/v1/mobile-activity/v1/people/{actor}/summary",
                    params={"scope": "user", "period": "3m"},
                    headers=mobile,
                )
                assert actor_read.status_code == 200 and actor_read.json()["component_trace_union"]["value"] > 0
                proofs[email]["other_user_scope_status"] = "200"
            available = await client.get("/api/v1/mobile-follow-sync/v1/availability", headers=mobile)
            assert available.status_code == 200, f"follow availability failed: {available.status_code}"
            proofs[email]["follow_availability_status"] = str(available.status_code)
            proofs[email]["follow_state"] = available.json()["state"]
        # Only IDs, never passwords, JWTs or OAuth challenge codes, leave the
        # 0700 runtime for a session-bound handoff receipt after validation.
        (runtime / "probe-roles.json").write_text(json.dumps(proofs, sort_keys=True))
        (runtime / "probe-roles.json").chmod(0o600)


async def main() -> None:
    runtime = require_disposable_environment()
    try:
        users = await verify_db()
        await verify_capabilities(runtime, users)
    finally:
        await engine.dispose()
    print("DISPOSABLE_PI_RAW_SOURCE_RETENTION_THREE_KINDS_SCOPED_READ_AND_DENIAL_BOTH_VIEWERS=PASS")


if __name__ == "__main__":
    asyncio.run(main())
