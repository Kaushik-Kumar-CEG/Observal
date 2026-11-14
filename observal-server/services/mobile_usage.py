# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Session unions over main's published component cohorts, never installs.

Use the same source, generation, identity, evidence and harness validity checks
as owner-facing activity. Three set-based branches, not one query per component
or hydrated transcript/session sets. Private SQL expressions are covered by
parity tests: any upstream structural change must update this adapter.
"""

import re
from datetime import datetime

from services.component_activity import hook_queries, queries, skill_queries

SUPPORTED_TYPES = ("mcp", "skill", "hook")
_TYPES = {
    "mcp": (queries._SESSIONS, queries._activity_params, "calls > 0", "a"),
    "skill": (skill_queries._SKILL_SESSIONS, skill_queries._params, "confirmed_loads > 0 OR invocations > 0", "e"),
    "hook": (
        hook_queries._HOOK_SESSIONS,
        hook_queries._params,
        "runs_with_output + silent_runs + failures + blocks > 0",
        "e",
    ),
}


def metric(row: dict) -> dict:
    """Zero requires a measured present cohort; uncertainty never becomes zero."""
    complete = int(row.get("complete", 0))
    if not complete:
        return {"value": None, "state": "not_recorded"}
    return {"value": int(row.get("observed", 0)), "state": "partial" if int(row.get("unknown", 0)) else "complete"}


def _many_components(sql: str, alias: str) -> str:
    """Lift the canonical single-component cohort to a keyed component set.

    All validity predicates are unchanged. Carry component_id through presence
    and evidence grouping, then add it to the evidence join so two components in
    the same session cannot exchange their counts. Source/publication joins stay
    bound to user+harness+session exactly as in main.
    """
    replacements = {
        "SELECT c.user_id AS user_id": "SELECT c.component_id AS component_id, c.user_id AS user_id",
        "s.layer_hash AS layer_hash, s.last_event_time AS last_event_time": "s.layer_hash AS layer_hash, s.last_event_time AS last_event_time, present.component_id AS component_id",
        "SELECT DISTINCT c.project_id, c.user_id, c.layer_hash, c.harness": "SELECT DISTINCT c.project_id, c.user_id, c.layer_hash, c.harness, c.component_id",
        "SELECT a.user_id AS user_id": "SELECT a.component_id AS component_id, a.user_id AS user_id",
        "GROUP BY a.user_id, a.harness, a.session_id": "GROUP BY a.component_id, a.user_id, a.harness, a.session_id",
        f"c.session_id = {alias}.session_id": f"c.session_id = {alias}.session_id AND c.component_id = {alias}.component_id",
    }
    for old, new in replacements.items():
        if old not in sql:
            raise RuntimeError("Component activity SQL changed; mobile parity update required")
        sql = sql.replace(old, new)
    # Both mapping validity (including current snapshot conflicts) and evidence
    # membership now bind to the same authorized set of UUIDs.
    return re.sub(
        r"(?P<column>(?:[ac]\.)?component_id) = \{component_id:String\}",
        lambda m: "has({component_ids:Array(String)}, " + m["column"] + ")",
        sql,
    )


def _branch(kind: str, identifiers: list[str], window, project, users):
    sql, params_fn, observed, alias = _TYPES[kind]
    params = (
        params_fn(project, kind, identifiers[0], None, window)
        if kind == "mcp"
        else params_fn(project, identifiers[0], None, window)
    )
    params["param_component_ids"] = queries._clickhouse_array(identifiers)
    sql = _many_components(sql, alias)
    restriction = ""
    if users is not None:
        restriction = "WHERE has({mobile_users:Array(String)}, user_id)"
        params["param_mobile_users"] = queries._clickhouse_array(users)
    unknown = "projection_state != 'complete' OR collision_count > 0 OR unmatched_count > 0"
    if kind == "hook":
        unknown += " OR harness = 'claude-code' OR eligibility NOT IN ('eligible', 'headless', 'agent_inactive')"
    return (
        f"SELECT '{kind}' AS component_type, component_id, user_id, harness, session_id, "
        "projection_state = 'complete' AS complete, "
        f"({unknown}) AS unknown, (projection_state = 'complete' AND ({observed})) AS observed "
        f"FROM ({sql}) {restriction}",
        params,
    )


def union_sql(
    components: list[tuple[str, str]],
    project: str,
    window: tuple[datetime, datetime],
    users: list[str] | None,
    *,
    by_component: bool = False,
):
    branches, bound = [], {}
    for kind in SUPPORTED_TYPES:
        identifiers = sorted({identifier for component_type, identifier in components if component_type == kind})
        if not identifiers:
            continue
        branch, params = _branch(kind, identifiers, window, project, users)
        branch = re.sub(r"\{(\w+):", lambda m, kind=kind: "{" + m[1] + f"_{kind}:", branch)
        bound.update({key + f"_{kind}": value for key, value in params.items()})
        branches.append(branch)
    if not branches:
        return None, {}
    keys = "component_type, component_id, " if by_component else ""
    group = " GROUP BY component_type, component_id" if by_component else ""
    return (
        f"SELECT {keys}uniqExactIf((user_id, harness, session_id), observed) AS observed, "
        "countIf(complete) AS complete, countIf(unknown) AS unknown FROM ("
        + " UNION ALL ".join(branches)
        + ")"
        + group
        + " FORMAT JSON",
        bound,
    )


async def usage(components, project, window, users):
    sql, params = union_sql(components, project, window, users)
    if sql is None:
        return {"value": None, "state": "not_recorded"}
    rows = await queries._rows(sql, params)  # HTTP/query failures propagate, never become zero.
    if not rows:
        raise RuntimeError("Missing mobile aggregate")
    result = metric(rows[0])
    if result["value"] is not None and any(kind not in SUPPORTED_TYPES for kind, _ in components):
        result["state"] = "partial"
    return result


async def component_usage(components, project, window, users):
    sql, params = union_sql(components, project, window, users, by_component=True)
    rows = await queries._rows(sql, params) if sql else []
    # Only current verified present cohorts appear. Absent components have no
    # attributable evidence, not a fabricated install/usage count.
    return {(row["component_type"], row["component_id"]): metric(row) for row in rows}
