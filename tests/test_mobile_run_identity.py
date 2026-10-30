# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Never let a reused session ID or legacy outbox replace a claimed run."""

import hashlib
import json
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from services import mobile_run_identity as admission

USER = uuid.UUID("11111111-1111-4111-8111-111111111111")
SESSION = "pi-source-123"
HEADER = json.dumps({"type": "session", "id": SESSION, "timestamp": "2026-10-01T12:00:00Z"})
HASH = hashlib.sha256(HEADER.encode()).hexdigest()
RUN = uuid.uuid4()


class Db:
    def __init__(self, existing=None):
        self.existing = existing
        self.inserts = 0
        self.commits = 0

    async def execute(self, sql, params):
        statement = str(sql)
        if "SELECT run_incarnation,header_hash" in statement:
            return SimpleNamespace(first=lambda: self.existing)
        if "INSERT INTO mobile_run_instances" in statement:
            self.inserts += 1
        return SimpleNamespace(first=lambda: None)

    async def commit(self):
        self.commits += 1


class Session:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        return self.db

    async def __aexit__(self, *_args):
        return None


class Reply:
    def __init__(self, present):
        self.present = present

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": [{"1": 1}] if self.present else []}


async def claim(db, **updates):
    values = {
        "project": "default",
        "user": USER,
        "session": SESSION,
        "harness": "pi",
        "start_offset": 0,
        "lines": [HEADER],
        "run_incarnation": RUN,
        "run_header_hash": HASH,
    }
    values.update(updates)
    return await admission.admit_pi_run(**values)


@pytest.mark.asyncio
async def test_fresh_run_claim_is_bound_to_original_source_and_uploader(monkeypatch):
    db = Db()
    query = AsyncMock(return_value=Reply(False))
    monkeypatch.setattr(admission, "async_session", lambda: Session(db))
    monkeypatch.setattr("services.clickhouse.client._query", query)
    await claim(db)
    assert db.inserts == db.commits == 1
    params = query.await_args.args[1]
    assert params["param_user"] == str(USER) and params["param_session"] == SESSION


@pytest.mark.asyncio
async def test_reused_nonce_different_header_legacy_replay_and_other_harness_fail_closed(monkeypatch):
    db = Db(
        SimpleNamespace(
            run_incarnation=RUN,
            header_hash=HASH,
            origin_witness=None,
            parent_session_id=None,
            parent_run_incarnation=None,
            parent_header_hash=None,
        )
    )
    monkeypatch.setattr(admission, "async_session", lambda: Session(db))
    await claim(db, start_offset=8, lines=[])
    for changes in (
        {"run_incarnation": uuid.uuid4()},
        {"run_header_hash": "f" * 64},
        {"lines": [HEADER.replace("2026-10-01", "2026-10-02")]},  # Fake same run hash; altered source.
        {"run_incarnation": None, "run_header_hash": None},
        {"run_origin": "pi_session_start_root_v1"},  # No retroactive promotion.
        {"harness": "codex"},
    ):
        with pytest.raises(HTTPException) as exc:
            await claim(db, **changes)
        assert exc.value.status_code == 409
    assert db.inserts == 0


@pytest.mark.asyncio
async def test_lifecycle_root_witness_only_on_unparented_source_and_immutable_retry(monkeypatch):
    db = Db()
    monkeypatch.setattr(admission, "async_session", lambda: Session(db))
    monkeypatch.setattr("services.clickhouse.client._query", AsyncMock(return_value=Reply(False)))
    await claim(db, run_origin="pi_session_start_root_v1")
    assert db.inserts == 1
    parented = json.dumps(
        {"type": "session", "id": SESSION, "timestamp": "2026-10-01T12:00:00Z", "parentSession": "/tmp/parent.jsonl"}
    )
    with pytest.raises(HTTPException) as exc:
        await claim(
            db,
            lines=[parented],
            run_header_hash=hashlib.sha256(parented.encode()).hexdigest(),
            run_origin="pi_session_start_root_v1",
        )
    assert exc.value.status_code == 409
    db.existing = SimpleNamespace(
        run_incarnation=RUN,
        header_hash=HASH,
        origin_witness="pi_session_start_root_v1",
        parent_session_id=None,
        parent_run_incarnation=None,
        parent_header_hash=None,
    )
    await claim(db, start_offset=2, lines=[], run_origin="pi_session_start_root_v1")
    with pytest.raises(HTTPException):
        await claim(db, start_offset=2, lines=[], run_origin=None)


@pytest.mark.asyncio
async def test_legacy_existing_source_cannot_be_upgraded_or_resumed(monkeypatch):
    db = Db()
    monkeypatch.setattr(admission, "async_session", lambda: Session(db))
    monkeypatch.setattr("services.clickhouse.client._query", AsyncMock(return_value=Reply(True)))
    with pytest.raises(HTTPException) as exc:
        await claim(db)
    assert exc.value.status_code == 409 and db.inserts == 0
    with pytest.raises(HTTPException) as exc:
        await claim(db, start_offset=1, lines=[])
    assert exc.value.status_code == 409 and db.inserts == 0


@pytest.mark.asyncio
async def test_forged_header_mismatch_and_missing_timestamp_are_rejected(monkeypatch):
    db = Db()
    monkeypatch.setattr(admission, "async_session", lambda: Session(db))
    monkeypatch.setattr("services.clickhouse.client._query", AsyncMock(return_value=Reply(False)))
    for line in (HEADER.replace(SESSION, "another-session"), HEADER.replace("2026-10-01T12:00:00Z", "bad")):
        with pytest.raises(HTTPException) as exc:
            await claim(db, lines=[line], run_header_hash=hashlib.sha256(line.encode()).hexdigest())
        assert exc.value.status_code == 409
    assert db.inserts == 0
