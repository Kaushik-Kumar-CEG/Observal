# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Subscription channels may not bypass per-event trace/review permission."""

from types import SimpleNamespace

import pytest

from api.graphql import Subscription


def _info(token=None):
    params = {"authorization": f"Bearer {token}"} if token else {}
    return SimpleNamespace(context={"connection_params": params, "request": SimpleNamespace(headers={})})


@pytest.mark.asyncio
@pytest.mark.parametrize("listing", [None, "12345678-1234-4234-8234-123456789abc"])
async def test_review_global_and_listing_subscription_fail_closed(listing, monkeypatch):
    async def subscribe(channel):
        raise AssertionError(f"unscoped channel opened: {channel}")
        yield

    monkeypatch.setattr("api.graphql.subscribe", subscribe)
    for info in (_info(), _info("ordinary"), _info("admin")):
        with pytest.raises(ValueError, match="Review ID required"):
            await anext(Subscription().review_updated(info, listing_id=listing))


@pytest.mark.asyncio
@pytest.mark.parametrize("session_id", [None, "shared-session"])
async def test_session_global_and_item_deny_non_admin_and_recheck_revocation(session_id, monkeypatch):
    calls = 0
    allowed = False

    async def check(token):
        nonlocal calls
        calls += 1
        return allowed and token == "admin" and calls <= 2

    async def subscribe(channel):
        assert channel == (f"sessions:{session_id}:updated" if session_id else "sessions:updated")
        yield {"session_id": "shared-session", "event_name": "session_push"}
        yield {"session_id": "shared-session", "event_name": "session_push"}

    monkeypatch.setattr("api.graphql._trace_admin_allowed", check)
    monkeypatch.setattr("api.graphql.subscribe", subscribe)
    with pytest.raises(ValueError, match="Authentication required"):
        await anext(Subscription().session_updated(_info(), session_id=session_id))
    with pytest.raises(ValueError, match="Trace access required"):
        await anext(Subscription().session_updated(_info("ordinary"), session_id=session_id))
    allowed = True
    calls = 0
    events = [event async for event in Subscription().session_updated(_info("admin"), session_id=session_id)]
    assert len(events) == 1
    assert calls == 3
