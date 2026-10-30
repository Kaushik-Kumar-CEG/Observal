# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Retry classification must not confuse ordinary throttles with full-capacity leases."""

from api.routes.mobile_follow_read import lease_retry_seconds


def test_capacity_retry_hint_is_distinct_from_ordinary_page_throttle():
    assert lease_retry_seconds(0) == "1"
    assert lease_retry_seconds(999) == "1"
    assert lease_retry_seconds(1000) == "60"
