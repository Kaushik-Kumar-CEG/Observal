# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Capability response preparation is correlated without logging bearer material."""

import uuid

import pytest
from fastapi import FastAPI, HTTPException, Request
from httpx import ASGITransport, AsyncClient
from loguru import logger
from starlette.responses import JSONResponse

from api.middleware.audit import AuditMiddleware
from api.middleware.request_id import RequestIDMiddleware

PATH = "/api/v1/mobile-activity/v1/capabilities"


@pytest.mark.asyncio
async def test_capability_response_prepared_outcomes_have_response_request_id_and_no_secrets():
    app = FastAPI()
    state = {"outcome": "source_qualified"}

    @app.get(PATH)
    async def capability(request: Request):
        if state["outcome"] in ("unauthorized", "denied", "error"):
            raise HTTPException({"unauthorized": 401, "denied": 403, "error": 500}[state["outcome"]], "private")
        request.state.mobile_capability_ingress = state["outcome"]
        return JSONResponse({"synthetic_test_cohort": state["outcome"] == "source_qualified"})

    # Match middleware.py: Starlette executes the last registered middleware first.
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(AuditMiddleware)
    messages = []
    sink = logger.add(lambda record: messages.append(record), format="{message}")
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            for outcome, status in (
                ("source_qualified", 200),
                ("partial_source", 200),
                ("closed", 200),
                ("unauthorized", 401),
                ("denied", 403),
                ("error", 500),
            ):
                state["outcome"] = outcome
                request_id = str(uuid.uuid4())
                response = await client.get(
                    PATH,
                    headers={"Authorization": "Bearer secret-must-not-log", "X-Request-ID": request_id},
                )
                assert response.status_code == status
                assert response.headers["x-request-id"] == request_id
                assert any(
                    f"mobile_capability_ingress: request_id={request_id} stage=response_prepared outcome={outcome}"
                    in message
                    for message in messages
                )
    finally:
        logger.remove(sink)
    assert all("secret-must-not-log" not in message for message in messages)
    assert all("outcome=aborted" not in message for message in messages)
