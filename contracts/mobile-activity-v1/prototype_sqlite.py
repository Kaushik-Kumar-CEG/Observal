#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""DISPOSABLE in-memory SQLite arithmetic/index thought experiment; no real DB or private data."""

import sqlite3
import time

conn = sqlite3.connect(":memory:")
conn.executescript("""
CREATE TABLE reach(actor INTEGER,root INTEGER,component INTEGER,kind INTEGER,day INTEGER,generation INTEGER,PRIMARY KEY(actor,root,component,kind,day));
CREATE INDEX actor_day ON reach(actor,day,root);
CREATE INDEX component_day ON reach(component,day,actor,root);
CREATE TABLE listing(component INTEGER PRIMARY KEY,author INTEGER,visible INTEGER,approved INTEGER);
CREATE INDEX author_visible ON listing(author,visible,component);
CREATE TABLE eligible(actor INTEGER,root INTEGER,day INTEGER,qualified INTEGER,PRIMARY KEY(actor,root));
CREATE INDEX eligible_day ON eligible(actor,day);
""")
reach, eligible = [], []
for actor in range(100):
    for root in range(10000 if actor == 0 else 500):
        eligible.append((actor, root, root % 7, 1))
        if root % 10:
            reach.extend((actor, root, actor * 2 + component, component, root % 7, 1) for component in (0, 1))
conn.executemany("INSERT INTO reach VALUES (?,?,?,?,?,?)", reach)
conn.executemany("INSERT INTO eligible VALUES (?,?,?,?)", eligible)
conn.executemany(
    "INSERT INTO listing VALUES (?,?,?,?)", [(actor * 2 + c, actor, 1, 1) for actor in range(100) for c in (0, 1)]
)
user_sql = "SELECT COUNT(DISTINCT root) FROM reach WHERE actor=? AND day>=? AND day<?"
author_sql = """SELECT COUNT(DISTINCT r.actor || ':' || r.root) FROM reach r JOIN listing l ON l.component=r.component WHERE l.author=? AND l.visible=1 AND l.approved=1 AND r.day>=? AND r.day<?"""
row_sql = "SELECT component,COUNT(DISTINCT root) FROM reach WHERE actor=? AND day>=? AND day<? GROUP BY component ORDER BY component"
assert conn.execute(user_sql, (0, 0, 7)).fetchone()[0] == 9000
assert conn.execute(author_sql, (0, 0, 7)).fetchone()[0] == 9000
assert [n for _, n in conn.execute(row_sql, (0, 0, 7))] == [9000, 9000]
assert conn.execute("SELECT count(*) FROM eligible WHERE actor=0").fetchone()[0] == 10000
conn.execute("INSERT INTO reach VALUES (101,1,0,0,0,1)")
assert conn.execute(author_sql, (0, 0, 7)).fetchone()[0] == 9001
conn.execute("UPDATE listing SET visible=0 WHERE component=0")
assert conn.execute(author_sql, (0, 0, 7)).fetchone()[0] == 9000
conn.execute("UPDATE listing SET visible=0 WHERE component=1")
assert conn.execute(author_sql, (0, 0, 7)).fetchone()[0] == 0


def bench():
    started = time.perf_counter()
    for actor in range(12):
        conn.execute(user_sql, (actor, 0, 7)).fetchone()
        conn.execute(author_sql, (actor, 0, 7)).fetchone()
    return (time.perf_counter() - started) * 1000


measurements = sorted(bench() for _ in range(30))
print(
    f"SQLite ONLY facts={len(reach) + 1} eligible={len(eligible)} union=9000 rows=9000+9000 p95_12x2={measurements[28]:.1f}ms"
)
print("user plan", list(conn.execute("EXPLAIN QUERY PLAN " + user_sql, (0, 0, 7))))
print("author plan", list(conn.execute("EXPLAIN QUERY PLAN " + author_sql, (0, 0, 7))))
print("NOT an HTTP, PostgreSQL, ClickHouse, cursor, retention, source or race benchmark")
