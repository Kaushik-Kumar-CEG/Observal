# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Read-only mobile session unions over the existing published component cohorts.

Do not reinterpret presence, installs or available skills as use. All validity
checks (source revision, publication generation, identity and harness support)
come from the same session SQL as the owner-facing activity API.
"""

import re
from datetime import datetime

from services.component_activity import hook_queries, queries, skill_queries

_TYPES = {
    "mcp": (queries._SESSIONS, queries._activity_params, "calls > 0"),
    "skill": (skill_queries._SKILL_SESSIONS, skill_queries._params, "confirmed_loads > 0 OR invocations > 0"),
    "hook": (
        hook_queries._HOOK_SESSIONS,
        hook_queries._params,
        "runs_with_output + silent_runs + failures + blocks > 0",
    ),
}


def metric(row: dict) -> dict:
    """Zero requires a measured cohort; uncertainty never becomes zero."""
    complete = int(row.get("complete", 0))
    unknown = int(row.get("unknown", 0))
    observed = int(row.get("observed", 0))
    if not complete:
        return {"value": None, "state": "not_recorded"}
    return {"value": observed, "state": "partial" if unknown else "complete"}


def _branch(kind: str, identifier: str, period: tuple[datetime, datetime], project: str, users: list[str] | None):
    sql, params_fn, observed = _TYPES[kind]
    if kind == "mcp":
        params = params_fn(project, kind, identifier, None, period)
    else:
        params = params_fn(project, identifier, None, period)
    # Reuse the actual per-type session expression, not a new matcher or raw
    # activity read. A publication without current source is excluded there.
    restriction = ""
    if users is not None:
        restriction = "WHERE has({mobile_users:Array(String)}, user_id)"
        params["param_mobile_users"] = queries._clickhouse_array(users)
    unknown = "projection_state != 'complete' OR collision_count > 0 OR unmatched_count > 0"
    # Claude's silent hooks are not recorded; skill loads do not prove invocation.
    if kind == "hook":
        unknown += " OR harness = 'claude-code' OR eligibility NOT IN ('eligible', 'headless', 'agent_inactive')"
    branch = (
        "SELECT user_id, harness, session_id, "
        "projection_state = 'complete' AS complete, "
        f"({unknown}) AS unknown, "
        f"(projection_state = 'complete' AND ({observed})) AS observed "
        f"FROM ({sql}) {restriction}"
    )
    return branch, params


def union_sql(
    components: list[tuple[str, str]], project: str, period: tuple[datetime, datetime], users: list[str] | None
):
    branches, bound = [], {}
    for index, (kind, identifier) in enumerate(components):
        if kind not in _TYPES:
            continue
        branch, params = _branch(kind, identifier, period, project, users)
        # ClickHouse parameters must be unique per branch/component. Rename only
        # placeholders, never interpolate caller-controlled values into SQL.
        branch = re.sub(r"\{(\w+):", lambda m, index=index: "{" + m[1] + f"_{index}:", branch)
        bound.update({key + f"_{index}": value for key, value in params.items()})
        branches.append(branch)
    if not branches:
        return None, {}
    return (
        "SELECT uniqExactIf((user_id, harness, session_id), observed) AS observed, "
        "countIf(complete) AS complete, countIf(unknown) AS unknown FROM ("
        + " UNION ALL ".join(branches)
        + ") FORMAT JSON",
        bound,
    )


async def usage(
    components: list[tuple[str, str]], project: str, period: tuple[datetime, datetime], users: list[str] | None
):
    sql, params = union_sql(components, project, period, users)
    if sql is None:
        return {"value": None, "state": "not_recorded"}
    # _rows raises on HTTP/query failure: the route returns 503, never a zero.
    rows = await queries._rows(sql, params)
    if not rows:
        raise RuntimeError("Missing mobile aggregate")
    return metric(rows[0])
