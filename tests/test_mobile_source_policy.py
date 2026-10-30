# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Shortened whole-row TTL cannot turn a surviving Pi prefix into a full zero."""

import hashlib
from datetime import UTC, datetime, timedelta

from jobs.mobile_evidence import _policy_source_complete, _revision, _source_retained_until


def _rows(times, *, accepted):
    return [
        {
            "line_offset": offset,
            "line_hash": f"xxh128-{offset}",
            "source_sha256": hashlib.sha256(f"source {offset}".encode()).hexdigest(),
            "raw_line": f"source {offset}",
            "raw_line_truncated": False,
            "timestamp": stamp.isoformat(),
            "ingested_at": accepted.isoformat(),
        }
        for offset, stamp in enumerate(times)
    ]


def _final_hash(rows):
    return hashlib.sha256("".join(row["source_sha256"] + "\n" for row in rows).encode()).hexdigest()


def test_expired_terminal_tool_call_never_becomes_a_complete_tool_free_prefix():
    now = datetime.now(UTC)
    # The later source line has an older CH event timestamp and expires
    # FIRST at the 7-day UTC-midnight whole-row boundary.
    complete = _rows(
        [now - timedelta(days=1), now - timedelta(days=1), now - timedelta(days=10)], accepted=now - timedelta(days=11)
    )
    original_digest = _revision(complete)
    assert original_digest is not None
    surviving = complete[:2]
    surviving_digest = _revision(surviving)
    assert surviving_digest != original_digest
    since = now - timedelta(hours=1)
    assert not _policy_source_complete(surviving, surviving_digest, original_digest, None, None, since)
    assert not _policy_source_complete(surviving, surviving_digest, None, None, 2, since)
    assert not _policy_source_complete(surviving, surviving_digest, original_digest, 2, 2, since)
    assert _source_retained_until(complete, original_digest, retention_days=7) < now
    # Old digests by themselves never establish finality: the pre-067 worker
    # could have projected only the prefix it happened to see. An authorized
    # full-file replay must provide a fresh server-hashed final receipt.
    assert not _policy_source_complete(complete, original_digest, original_digest, None, None, since)
    assert not _policy_source_complete(surviving, surviving_digest, surviving_digest, None, None, since)
    assert _policy_source_complete(complete, original_digest, original_digest, None, 2, since, 2, _final_hash(complete))


def test_new_complete_source_after_verified_epoch_is_usable_even_after_prior_short_ttl():
    now = datetime.now(UTC)
    since = now - timedelta(minutes=2)
    complete = _rows([now - timedelta(seconds=3), now - timedelta(seconds=2)], accepted=now)
    digest = _revision(complete)
    assert digest is not None
    full_hash = _final_hash(complete)
    assert _policy_source_complete(complete, digest, None, None, 1, since, 1, full_hash)
    assert not _policy_source_complete(complete, digest, None, None, 1, since)  # no final
    assert not _policy_source_complete(complete, digest, None, None, 1, since, 0, full_hash)
    assert not _policy_source_complete(complete, digest, None, None, 1, since, 1, _final_hash(complete[:1]))
    assert not _policy_source_complete(complete[:1], _revision(complete[:1]), None, None, 1, since, 1, full_hash)
    assert not _policy_source_complete(complete, digest, None, None, None, since, 1, full_hash)
    assert not _policy_source_complete(complete, digest, None, None, 1, now + timedelta(seconds=1), 1, full_hash)
    assert not _policy_source_complete(complete, digest, None, None, 1, None, 1, full_hash)
    assert not _policy_source_complete(complete, None, None, None, 1, since)
    assert _source_retained_until(complete, digest, retention_days=7) > now


def test_missing_header_and_wrong_or_unknown_ingest_clock_are_not_qualification():
    now = datetime.now(UTC)
    rows = _rows([now], accepted=now)
    digest = _revision(rows)
    rows[0]["line_offset"] = 1
    assert not _policy_source_complete(rows, digest, None, None, 1, now - timedelta(seconds=1), 1, _final_hash(rows))
    rows[0]["line_offset"] = 0
    del rows[0]["ingested_at"]
    assert not _policy_source_complete(rows, digest, None, None, 0, now - timedelta(seconds=1), 0, _final_hash(rows))
