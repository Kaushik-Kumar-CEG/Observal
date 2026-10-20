# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed PostgreSQL publication commit time for mobile event-time approval.

A trigger and a column default run *before* commit. Even clock_timestamp() can
predate a Pi event if the reviewer holds the transaction open after updating a
version. Only the row's actual commit can establish approval at event time.
PostgreSQL must boot with track_commit_timestamp=on to produce positive typed
facts; unavailable/expired commit history yields infinity (Not recorded).
"""


def committed_at(alias: str) -> str:
    if alias not in {"pe", "e", "later", "uncertain"}:
        raise ValueError("Untrusted mobile publication SQL alias")
    return (
        "(CASE WHEN current_setting('track_commit_timestamp')::boolean "
        f"THEN COALESCE(pg_xact_commit_timestamp({alias}.xmin), 'infinity'::timestamptz) "
        "ELSE 'infinity'::timestamptz END)"
    )
