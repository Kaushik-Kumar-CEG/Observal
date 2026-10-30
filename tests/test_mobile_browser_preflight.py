# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A direct device-confirm API probe cannot prove the Chrome approval UI exists."""

import httpx
import pytest

from tests.integration_mobile.test_https_mobile_journey import _assert_browser_approval_page


@pytest.mark.asyncio
async def test_disposable_api_only_proxy_fails_before_inviting_android():
    async with httpx.AsyncClient(
        base_url="https://localhost:18446",
        transport=httpx.MockTransport(lambda request: httpx.Response(404, json={"detail": "Not Found"})),
    ) as client:
        with pytest.raises(AssertionError):
            await _assert_browser_approval_page(client)


@pytest.mark.asyncio
async def test_disposable_approval_route_requires_same_origin_javascript():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/login", "/device"):
            return httpx.Response(
                200,
                text='<html><div id="root"></div><script type="module" src="/assets/app.js"></script></html>',
                headers={"content-type": "text/html"},
            )
        assert request.url.path == "/assets/app.js"
        return httpx.Response(404)

    async with httpx.AsyncClient(base_url="https://localhost:18446", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AssertionError):
            await _assert_browser_approval_page(client)


@pytest.mark.asyncio
async def test_disposable_approval_page_and_asset_preflight_pass():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/login", "/device"):
            return httpx.Response(
                200,
                text='<html><div id="root"></div><script type="module" src="/assets/app.js"></script></html>',
                headers={"content-type": "text/html"},
            )
        assert request.url.path == "/assets/app.js"
        return httpx.Response(200, text="export {};", headers={"content-type": "application/javascript"})

    async with httpx.AsyncClient(base_url="https://localhost:18446", transport=httpx.MockTransport(handler)) as client:
        await _assert_browser_approval_page(client)
