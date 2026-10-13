# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Uploader identity is part of every snapshot acknowledgement and read."""

import inspect
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from api.routes.layer_snapshot import (
    LayerSnapshotRequest,
    diff_layer_snapshots,
    get_layer_snapshot,
    upload_layer_snapshot,
)
from services.insights.version_impact import build_version_impact_data


@pytest.mark.asyncio
async def test_colliding_hashes_are_independent_uploads_and_private_reads(monkeypatch):
    first = str(uuid.UUID("11111111-1111-4111-8111-111111111111"))
    second = str(uuid.UUID("22222222-2222-4222-8222-222222222222"))
    stored: dict[tuple[str, str], str] = {}
    hash_value = "1234567890abcdef"

    class Response:
        def __init__(self, rows):
            self.rows = rows

        def raise_for_status(self):
            pass

        def json(self):
            return {"data": self.rows}

    async def query(sql, params):
        user = params["param_user_id"]
        assert "user_id = {user_id:String}" in sql
        if "count() as cnt" in sql:
            return Response([{"cnt": int((user, hash_value) in stored)}])
        hashes = [params.get("param_hash")] if "param_hash" in params else [hash_value, "anotherhash12345"]
        rows = [
            {"hash": key, "harness": "pi", "content": stored[(user, key)], "file_count": 1, "total_size": 1}
            for key in hashes
            if (user, key) in stored
        ]
        return Response(rows)

    async def insert(row):
        stored[(row["user_id"], row["hash"])] = row["content"]

    monkeypatch.setattr("services.clickhouse.client._query", query)
    monkeypatch.setattr("services.clickhouse.insert.insert_layer_snapshot", insert)
    monkeypatch.setattr("services.secrets_redactor.redact_secrets", lambda value: value)
    req = LayerSnapshotRequest.model_validate({"hash": hash_value, "harnesses": {"pi": []}})
    uploader = inspect.unwrap(upload_layer_snapshot)
    getter = inspect.unwrap(get_layer_snapshot)
    differ = inspect.unwrap(diff_layer_snapshots)
    assert (await uploader(req, SimpleNamespace(), SimpleNamespace(id=uuid.UUID(first)))).stored
    assert (await uploader(req, SimpleNamespace(), SimpleNamespace(id=uuid.UUID(second)))).stored
    assert not (await uploader(req, SimpleNamespace(), SimpleNamespace(id=uuid.UUID(first)))).stored
    assert len(stored) == 2
    assert (await getter(hash_value, SimpleNamespace(), SimpleNamespace(id=uuid.UUID(first)))).hash == hash_value
    del stored[(second, hash_value)]
    with pytest.raises(HTTPException) as exc:
        await getter(hash_value, SimpleNamespace(), SimpleNamespace(id=uuid.UUID(second)))
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException) as exc:
        await differ(hash_value, "anotherhash12345", SimpleNamespace(), SimpleNamespace(id=uuid.UUID(second)))
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_insights_never_reads_content_from_cross_user_hash_cohorts(monkeypatch):
    groups = [
        {"layer_hash": "1234567890abcdef", "sessions": 20, "users": 2, "success_proxy": 0.9, "tool_error_rate": 0.01},
        {"layer_hash": "fedcba9876543210", "sessions": 20, "users": 2, "success_proxy": 0.1, "tool_error_rate": 0.3},
    ]
    monkeypatch.setattr("services.insights.version_impact.detect_layer_groups", AsyncMock(return_value=groups))
    query = AsyncMock(side_effect=AssertionError("snapshot content read"))
    monkeypatch.setattr("services.insights.version_impact.get_query", query)
    result = await build_version_impact_data("agent", "2026-01-01", "2026-02-01")
    assert result is None
    query.assert_not_awaited()
