# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes import mobile_follow_write as writes
from services.mobile_follow_enablement import RISK_ACK_VALUE


@pytest.mark.asyncio
async def test_risk_cannot_follow_a_nonselected_subject(monkeypatch):
    body = SimpleNamespace(subject_id=uuid.uuid4())
    selected = [str(uuid.uuid4()), str(uuid.uuid4())]
    result = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: selected))
    db = SimpleNamespace(
        commit=AsyncMock(), scalar=AsyncMock(return_value=RISK_ACK_VALUE), execute=AsyncMock(return_value=result)
    )
    monkeypatch.setattr(writes, "_write", AsyncMock(return_value=SimpleNamespace()))
    monkeypatch.setattr(writes, "_body", AsyncMock(return_value=body))
    admit = AsyncMock()
    monkeypatch.setattr(writes.store, "admit_operation", admit)
    request = SimpleNamespace(state=SimpleNamespace(normal_follow_router=False))
    with pytest.raises(HTTPException) as denied:
        await writes.operations(request, "already-authenticated-fixture", db)
    assert denied.value.status_code == 403
    admit.assert_not_awaited()
