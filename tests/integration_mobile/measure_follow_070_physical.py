# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Opt-in LOCAL physical follow-070 capacity sample. Never connects to an existing cluster.

Run: MOBILE_FOLLOW_PHYSICAL_SCRATCH=1 .venv/bin/python tests/integration_mobile/measure_follow_070_physical.py
Requires local PostgreSQL binaries (initdb, pg_ctl, pg_dump) and a free 127.0.0.1:15440.
The script creates and destroys its own temporary cluster; it never uses DATABASE_URL.
"""

import asyncio
import json
import math
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "observal-server"
sys.path.insert(0, str(SERVER))
from models import Base  # noqa: E402

HOST, PORT, DB = "127.0.0.1", 15440, "follow_070_physical_scratch"
TABLES = (
    "mobile_follow_partitions",
    "mobile_follow_subjects",
    "mobile_follow_operations",
    "mobile_follow_changes",
    "mobile_follow_leases",
    "mobile_follow_pins",
    "mobile_follow_page_throttles",
    "mobile_follow_approvals",
    "mobile_follow_consents",
    "mobile_follow_nonces",
    "mobile_follow_privacy_actions",
)
COUNTS = {
    "subjects": 1000,
    "operations": 10000,
    "changes": 1000,
    "leases": 4,
    "pins": 4000,
    "indexed_receipts": 1000,
    "state_only_receipts": 1,
    "consents": 1000,
}


def binary(name):
    found = shutil.which(name) or f"/usr/lib/postgresql/16/bin/{name}"
    if not Path(found).is_file():
        raise RuntimeError(f"Missing local PostgreSQL binary: {name}")
    return found


def run(args, *, cwd=None, env=None, timeout=180, detached=False):
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        timeout=timeout,
        stdout=subprocess.DEVNULL if detached else subprocess.PIPE,
        stderr=subprocess.DEVNULL if detached else subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {(result.stderr or '')[-3000:]}")
    return result


async def measure():
    # Fail closed before touching the network, even if a caller supplies DATABASE_URL.
    if os.environ.get("MOBILE_FOLLOW_PHYSICAL_SCRATCH") != "1":
        raise RuntimeError("Set MOBILE_FOLLOW_PHYSICAL_SCRATCH=1 to create a disposable LOCAL cluster")
    with socket.socket() as probe:
        if probe.connect_ex((HOST, PORT)) == 0:
            raise RuntimeError("Port 15440 is occupied; refusing to use an existing PostgreSQL server")
    started = time.perf_counter()
    timings = {}
    with tempfile.TemporaryDirectory(prefix="follow-070-physical-") as tmp:
        data = Path(tmp) / "pgdata"
        sock = Path(tmp) / "socket"
        sock.mkdir()
        # Reject PG* connection overrides and user-supplied DATABASE_URL for every child process.
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and k != "DATABASE_URL"}
        run([binary("initdb"), "-D", str(data), "-A", "trust", "-U", "scratch", "--no-instructions"], env=env)
        pg_ctl = binary("pg_ctl")
        # Only a newly initialized cluster is ever started on this port.
        run(
            [
                pg_ctl,
                "-D",
                str(data),
                "-o",
                f"-c listen_addresses={HOST} -c port={PORT} -c unix_socket_directories={sock}",
                "-w",
                "-l",
                str(Path(tmp) / "postgres.log"),
                "start",
            ],
            env=env,
            detached=True,
            timeout=30,
        )
        try:
            admin = await asyncpg.connect(host=HOST, port=PORT, user="scratch", database="postgres")
            try:
                await admin.execute(f'CREATE DATABASE "{DB}"')
            finally:
                await admin.close()
            dsn = f"postgresql+asyncpg://scratch@{HOST}:{PORT}/{DB}"
            engine = create_async_engine(dsn)
            try:
                t = time.perf_counter()
                async with engine.begin() as conn:
                    await conn.execute(__import__("sqlalchemy").text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                    await conn.run_sync(
                        lambda sync: Base.metadata.create_all(
                            sync,
                            tables=[
                                table
                                for table in Base.metadata.sorted_tables
                                if not table.name.startswith("mobile_follow_")
                            ],
                        )
                    )
                for cmd in (("stamp", "044_review_orphan_authors"), ("upgrade", "070_mobile_follow_sync_state")):
                    run([sys.executable, "-m", "alembic", *cmd], cwd=SERVER, env={**env, "DATABASE_URL": dsn})
                timings["setup_s"] = round(time.perf_counter() - t, 3)
            finally:
                await engine.dispose()
            conn = await asyncpg.connect(host=HOST, port=PORT, user="scratch", database=DB)
            try:
                version = await conn.fetchval("SELECT version_num FROM alembic_version")
                if version != "070_mobile_follow_sync_state":
                    raise RuntimeError(f"Expected migration 070, got {version}")
                server, owner = uuid.uuid4(), uuid.uuid4()
                key = (server, "physical-capacity", owner, "real")
                # Fixed-size payloads; all logical counters agree with inserted rows.
                t = time.perf_counter()
                wal_before = await conn.fetchval("SELECT pg_current_wal_lsn()")
                async with conn.transaction():
                    await conn.execute(
                        """INSERT INTO users (id,email,username,name,role,created_at)
                        VALUES ($1,$2,$3,'Scratch','user',clock_timestamp())""",
                        owner,
                        f"{owner}@scratch.invalid",
                        owner.hex[:20],
                    )
                    await conn.execute("""INSERT INTO users (id,email,username,name,role,created_at)
                        SELECT md5('physical-subject-'||i)::uuid,
                        'physical-'||i||'@scratch.invalid','physical-'||i,
                        'Scratch','user',clock_timestamp() FROM generate_series(1,1000) i""")
                    await conn.execute(
                        """INSERT INTO mobile_follow_partitions
                        (server_id,project_id,owner_id,cohort,consent_state,current_revision,subject_count,
                        normal_outcomes,history_bytes,pin_bytes,consent_bindings,indexed_receipts)
                        VALUES ($1,$2,$3,$4,'available',1000,1000,10000,1536000,1024512,1000,1000)""",
                        *key,
                    )
                    await conn.execute(
                        """INSERT INTO mobile_follow_subjects
                        (server_id,project_id,owner_id,cohort,subject_id,person_revision,following,changed_revision)
                        SELECT $1,$2,$3,$4,md5('physical-subject-'||i)::uuid,1,true,i
                        FROM generate_series(1,1000) i""",
                        *key,
                    )
                    for first in range(1, 10001, 500):
                        await conn.execute(
                            """INSERT INTO mobile_follow_operations
                            (server_id,project_id,owner_id,cohort,operation_id,original_generation,
                             subject_id,body_digest,original_http_status,outcome,lane,logical_bytes,expires_at)
                            SELECT $1,$2,$3,$4,md5('physical-operation-'||i)::uuid,1,
                            md5('physical-subject-'||(1+(i-1)%1000))::uuid,
                            decode(md5('physical-digest-'||i)||md5('physical-digest-'||i),'hex'),
                            200,jsonb_build_object('status','applied','revision',i),
                            'normal',128,clock_timestamp()+interval '91 days'
                            FROM generate_series($5::integer,$6::integer) i""",
                            *key,
                            first,
                            first + 499,
                        )
                    await conn.execute(
                        """INSERT INTO mobile_follow_changes
                        (server_id,project_id,owner_id,cohort,owner_generation,revision,ordinal,
                        subject_id,person_revision,following,expires_at,logical_bytes)
                        SELECT $1,$2,$3,$4,1,i,0,md5('physical-subject-'||i)::uuid,
                        1,true,clock_timestamp()+interval '91 days',256
                        FROM generate_series(1,1000) i""",
                        *key,
                    )
                    leases = []
                    for kind in ("image", "changes"):
                        for slot in (1, 2):
                            lease = uuid.uuid4()
                            leases.append((kind, lease))
                            await conn.execute(
                                """INSERT INTO mobile_follow_leases
                                (server_id,project_id,owner_id,cohort,lease_id,kind,slot,device_id,
                                owner_generation,pinned_revision,erasure_floor,after_revision,upper_revision,
                                logical_bytes,row_count,admitted_at,expires_at)
                                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,1000,0,$9,$10,128,1000,
                                statement_timestamp(),statement_timestamp()+interval '15 minutes')""",
                                *key,
                                lease,
                                kind,
                                slot,
                                f"physical-device-{slot}" if kind == "changes" else None,
                                0 if kind == "changes" else None,
                                1000 if kind == "changes" else None,
                            )
                            await conn.execute(
                                """INSERT INTO mobile_follow_pins
                                (server_id,project_id,owner_id,cohort,lease_id,row_number,subject_id,
                                person_revision,following,revision,ordinal,logical_bytes)
                                SELECT $1,$2,$3,$4,$5,i,md5('physical-subject-'||i)::uuid,
                                1,true,$6::bigint * i,$7::integer,256 FROM generate_series(1,1000) i""",
                                *key,
                                lease,
                                1 if kind == "changes" else None,
                                0 if kind == "changes" else None,
                            )
                    for first in (1, 501):
                        await conn.execute(
                            """INSERT INTO mobile_follow_privacy_actions
                            (server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,
                             device_id,nonce_digest,original_generation,fenced_generation,
                             status,logical_bytes,expires_at)
                            SELECT $1,$2,$3,$4,md5('physical-receipt-'||i)::uuid,
                            'removal','nonce_lookup_90d','physical-receipt-'||i,
                            decode(md5('physical-nonce-'||i)||md5('physical-nonce-'||i),'hex'),
                            1,2,'completed',128,clock_timestamp()+interval '91 days'
                            FROM generate_series($5::integer,$6::integer) i""",
                            *key,
                            first,
                            first + 499,
                        )
                        await conn.execute(
                            """INSERT INTO mobile_follow_consents
                            (server_id,project_id,owner_id,cohort,consent_id,request_generation,
                             accepted_generation,body_digest,expires_at)
                            SELECT $1,$2,$3,$4,md5('physical-consent-'||i)::uuid,1,2,
                            decode(md5('physical-consent-digest-'||i)||md5('physical-consent-digest-'||i),'hex'),
                            clock_timestamp()+interval '91 days'
                            FROM generate_series($5::integer,$6::integer) i""",
                            *key,
                            first,
                            first + 499,
                        )
                    await conn.execute(
                        """INSERT INTO mobile_follow_privacy_actions
                        (server_id,project_id,owner_id,cohort,action_id,kind,recovery_mode,
                        device_id,nonce_digest,original_generation,fenced_generation,status,logical_bytes)
                        VALUES ($1,$2,$3,$4,$5,'removal','state_only','physical-state',
                        decode(repeat('ab',32),'hex'),1,2,'completed',0)""",
                        *key,
                        uuid.uuid4(),
                    )
                timings["fill_s"] = round(time.perf_counter() - t, 3)
                wal_after = await conn.fetchval("SELECT pg_current_wal_lsn()")
                wal_bytes = await conn.fetchval(
                    "SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint", wal_after, wal_before
                )
                coverage = {}
                for label, table, where in (
                    ("subjects", "mobile_follow_subjects", ""),
                    ("operations", "mobile_follow_operations", ""),
                    ("changes", "mobile_follow_changes", ""),
                    ("leases", "mobile_follow_leases", ""),
                    ("pins", "mobile_follow_pins", ""),
                    ("indexed_receipts", "mobile_follow_privacy_actions", " AND recovery_mode='nonce_lookup_90d'"),
                    ("state_only_receipts", "mobile_follow_privacy_actions", " AND recovery_mode='state_only'"),
                    ("consents", "mobile_follow_consents", ""),
                ):
                    coverage[label] = await conn.fetchval(
                        f"SELECT count(*) FROM {table} WHERE server_id=$1 AND project_id=$2 "
                        f"AND owner_id=$3 AND cohort=$4{where}",
                        *key,
                    )
                lease_coverage = dict(
                    await conn.fetch(
                        """SELECT kind, count(*) AS n
                    FROM mobile_follow_leases WHERE server_id=$1 AND project_id=$2
                    AND owner_id=$3 AND cohort=$4 GROUP BY kind""",
                        *key,
                    )
                )
                pin_coverage = dict(
                    await conn.fetch(
                        """SELECT l.kind, count(*) AS n
                    FROM mobile_follow_pins p JOIN mobile_follow_leases l
                    ON (p.server_id,p.project_id,p.owner_id,p.cohort,p.lease_id) =
                       (l.server_id,l.project_id,l.owner_id,l.cohort,l.lease_id)
                    WHERE p.server_id=$1 AND p.project_id=$2 AND p.owner_id=$3 AND p.cohort=$4
                    GROUP BY l.kind""",
                        *key,
                    )
                )
                distinct_subject_users = await conn.fetchval(
                    """SELECT count(DISTINCT s.subject_id)
                    FROM mobile_follow_subjects s JOIN users u ON u.id=s.subject_id
                    WHERE s.server_id=$1 AND s.project_id=$2 AND s.owner_id=$3 AND s.cohort=$4""",
                    *key,
                )
                if (
                    coverage != COUNTS
                    or lease_coverage != {"image": 2, "changes": 2}
                    or pin_coverage != {"image": 2000, "changes": 2000}
                    or distinct_subject_users != 1000
                ):
                    raise RuntimeError(
                        f"Capacity coverage mismatch: {coverage}, {lease_coverage}, "
                        f"{pin_coverage}, {distinct_subject_users}"
                    )
                coverage.update(
                    {
                        "lease_kinds": lease_coverage,
                        "pin_kinds": pin_coverage,
                        "distinct_subject_users": distinct_subject_users,
                    }
                )
                sizes = {}
                for table in TABLES:
                    heap, indexes, total = await conn.fetchrow(
                        "SELECT pg_relation_size($1::regclass),pg_indexes_size($1::regclass),"
                        "pg_total_relation_size($1::regclass)",
                        table,
                    )
                    sizes[table] = {"heap_bytes": heap, "indexes_bytes": indexes, "total_bytes": total}
                # Same keyset SQL as lease_page; bound by 10 pages and 100 measured samples.
                sql = """SELECT row_number,subject_id,person_revision,following,revision,ordinal
                    FROM mobile_follow_pins WHERE server_id=$1 AND project_id=$2 AND owner_id=$3
                    AND cohort=$4 AND lease_id=$5 AND row_number>$6
                    ORDER BY row_number LIMIT 100"""
                samples = []
                for i in range(110):
                    lease = leases[i % 4][1]
                    last = (i % 10) * 100
                    t = time.perf_counter_ns()
                    rows = await conn.fetch(sql, *key, lease, last)
                    elapsed = (time.perf_counter_ns() - t) / 1_000_000
                    if len(rows) != 100:
                        raise RuntimeError(f"Short page: {len(rows)}")
                    if i >= 10:
                        samples.append(elapsed)
                samples.sort()
                page = {
                    "samples": len(samples),
                    "warmup": 10,
                    "rows": 100,
                    "p50_ms": round(samples[math.ceil(0.50 * len(samples)) - 1], 4),
                    "p95_ms": round(samples[math.ceil(0.95 * len(samples)) - 1], 4),
                }
                dump = Path(tmp) / "scratch.dump"
                t = time.perf_counter()
                run(
                    [binary("pg_dump"), "-h", HOST, "-p", str(PORT), "-U", "scratch", "-d", DB, "-Fc", "-f", str(dump)],
                    env=env,
                )
                timings["backup_s"] = round(time.perf_counter() - t, 3)
                result = {
                    "database": DB,
                    "migration": version,
                    "params": COUNTS,
                    "coverage": coverage,
                    "timings": {**timings, "total_s": round(time.perf_counter() - started, 3)},
                    "relations": sizes,
                    "follow_total_bytes": sum(v["total_bytes"] for v in sizes.values()),
                    "wal_fill_bytes": wal_bytes,
                    "pg_dump_custom_bytes": dump.stat().st_size,
                    "page_query": page,
                    "caveats": [
                        "One local PostgreSQL 16 sample, not a production throughput or concurrency benchmark.",
                        "WAL includes scratch users and indexes; excludes initial schema setup and backup.",
                        "pg_dump -Fc covers the entire scratch database including baseline tables, not just follow tables.",
                        "No VACUUM, deletes, retention, TOAST growth or real HTTP/auth overhead; payloads are synthetic.",
                    ],
                }
                print(json.dumps(result, indent=2))
            finally:
                await conn.close()
        finally:
            run([pg_ctl, "-D", str(data), "-m", "immediate", "-w", "stop"], env=env, timeout=30, detached=True)


if __name__ == "__main__":
    asyncio.run(measure())
