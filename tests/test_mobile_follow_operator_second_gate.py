# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A disable after the first write commit precedes subject locking/admission."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes import mobile_follow_write as write
from services import mobile_follow_enablement


@pytest.mark.asyncio
async def test_normal_operation_rechecks_gate_after_commit_before_subject_lock(monkeypatch):
    events = []
    body = SimpleNamespace(subject_id=uuid.uuid4(), operation_id=uuid.uuid4(), owner_generation=1)
    request = SimpleNamespace(state=SimpleNamespace(normal_follow_router=True))

    class DB:
        async def commit(self):
            events.append("first-commit")

        async def scalar(self, *_args, **_kwargs):
            events.append("subject-lock")
            raise AssertionError("disabled request took subject lock")

    db = DB()
    monkeypatch.setattr(write, "_write", AsyncMock(return_value=object()))
    monkeypatch.setattr(write, "_body", AsyncMock(return_value=body))

    async def disabled(session):
        assert session is db and events == ["first-commit"]
        events.append("second-gate")
        raise HTTPException(404, "operator disabled")

    monkeypatch.setattr(mobile_follow_enablement, "require_operator_approval", disabled)
    with pytest.raises(HTTPException) as error:
        await write.operations(request, "Bearer token", db)
    assert error.value.status_code == 404
    assert events == ["first-commit", "second-gate"]
