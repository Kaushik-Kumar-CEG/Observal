# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A repaired malformed same-line Pi record denies old facts before CH writes."""

import asyncio
import inspect
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from api.routes import ingest as route
from services import session_ingest


@pytest.mark.asyncio
async def test_ignored_replacement_is_queued_even_when_rendered_count_and_highwater_do_not_advance(monkeypatch):
    events = []

    class Database:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def execute(self, statement, params=None):
            events.append(str(statement))
            return SimpleNamespace()

        async def commit(self):
            events.append("COMMIT")

    monkeypatch.setattr(route, "async_session", Database)
    monkeypatch.setattr("services.mobile_run_identity.admit_pi_run", AsyncMock())

    async def accept_repaired_bytes(**_):
        events.append("CH_SOURCE_WRITE")
        return session_ingest.IngestResult(ingested=0, skipped=1, errors=0)

    monkeypatch.setattr(session_ingest, "ingest_session_lines", accept_repaired_bytes)
    monkeypatch.setattr(session_ingest, "advance_session_checkpoint", AsyncMock(return_value=(1, 42)))
    req = route.SessionIngestRequest(
        session_id="repair-session", harness="pi", start_offset=1, lines=['{"type":"unknown"}']
    )
    response = await inspect.unwrap(route.ingest_session)(
        req, None, current_user=SimpleNamespace(id=uuid.uuid4()), auth_db=Database()
    )
    assert response.ingested == 0
    assert response.acknowledged_line == 1
    assert events[0] == "COMMIT", "release cached auth connection before queuing for project lock"
    deny = next(
        i for i, event in enumerate(events) if "UPDATE mobile_session_publications SET status='pending_source'" in event
    )
    write = events.index("CH_SOURCE_WRITE")
    assert deny < write and events[write - 1] == "COMMIT"
    assert any("INSERT INTO mobile_projection_queue" in event for event in events[write:])
    assert any("GREATEST(mobile_source_line_highwater.max_line" in event for event in events[write:])


@pytest.mark.asyncio
async def test_pi_advisory_waiters_are_bounded_before_acquiring_pool_connections(monkeypatch):
    monkeypatch.setattr(route, "_MOBILE_INGEST_SLOTS", asyncio.Semaphore(2))
    admission_active = admission_maximum = 0
    auth_commits = 0

    async def slow_admission(**_):
        nonlocal admission_active, admission_maximum
        assert auth_commits >= admission_active + 1
        admission_active += 1
        admission_maximum = max(admission_maximum, admission_active)
        await asyncio.sleep(0.01)  # real admission awaits CH with a PG connection held
        admission_active -= 1

    async def release_auth():
        nonlocal auth_commits
        auth_commits += 1

    monkeypatch.setattr("services.mobile_run_identity.admit_pi_run", slow_admission)
    active = maximum = 0

    async def fake_gate(*_):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.01)
        active -= 1
        return SimpleNamespace(ingested=0)

    monkeypatch.setattr(route, "_ingest_pi_with_gate", fake_gate)
    req = route.SessionIngestRequest(session_id="bounded", harness="pi", lines=['{"type":"unknown"}'])
    responses = await asyncio.gather(
        *[
            inspect.unwrap(route.ingest_session)(
                req, None, current_user=SimpleNamespace(id=uuid.uuid4()), auth_db=SimpleNamespace(commit=release_auth)
            )
            for _ in range(16)
        ]
    )
    assert len(responses) == 16 and maximum == 2 and admission_maximum == 2
    assert auth_commits == len(responses)
