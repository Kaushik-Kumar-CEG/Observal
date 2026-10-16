# SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Pi harness adapter for agent config generation.

Pi is harness-centric: `observal pull` writes AGENTS.md which becomes pi's
entire system prompt, effectively reconfiguring the whole agent runtime.
MCP servers are written to ~/.pi/agent/mcp.json (read by pi-mcp-adapter).
Skills go to .pi/skills/ or ~/.pi/agent/skills/.
"""

from __future__ import annotations

from loguru import logger as optic

from observal_shared.harness_registry import HARNESS_REGISTRY
from services.harness import BaseHarnessAdapter, ConfigContext, register_adapter

PI_HOOKS_SCHEMA = "observal-pi-hooks/v1"


def pi_hook_entries(configs: list[dict], scope: str) -> tuple[list[dict], list[str]]:
    """Only Pi command hooks whose runtime event and binding can be verified."""
    entries: list[dict] = []
    warnings: list[str] = []
    events = {"PreToolUse": "tool_call", "PostToolUse": "tool_result"}
    for hook in configs:
        config = hook.get("handler_config")
        command = config.get("command") if isinstance(config, dict) else None
        if (
            scope != "user"
            or hook.get("event") not in events
            or hook.get("handler_type") != "command"
            or hook.get("tool_filter") is not None
            or hook.get("script_content")
            or hook.get("script_filename")
            or not isinstance(command, str)
            or not command.strip()
            or not hook.get("registry_id")
            or not hook.get("registry_version")
        ):
            warnings.append(
                "A Pi hook was not installed: only unfiltered user-scope inline Pre/PostToolUse commands run."
            )
            continue
        timeout = config.get("timeout", 60)
        if type(timeout) is not int or not 1 <= timeout <= 600:
            timeout = 60
        entries.append(
            {
                "name": hook.get("name") or "hook",
                "event": events[hook["event"]],
                "type": "command",
                "command": command,
                "timeout": timeout,
                "id": hook["registry_id"],
                "version": hook["registry_version"],
            }
        )
    if (
        len(entries) > 64
        or len({entry["name"] for entry in entries}) != len(entries)
        or len({(e["event"], e["command"]) for e in entries}) != len(entries)
    ):
        return [], ["Pi hooks were not installed: ambiguous or oversized hook profile."]
    return entries, warnings


class PiAdapter(BaseHarnessAdapter):
    """Pi harness adapter - harness-centric config generation."""

    @property
    def harness_name(self) -> str:
        return "pi"

    def format_config(self, ctx: ConfigContext) -> dict:
        """Format config for Pi.

        Pi uses isolated profile directories for agents:
        - ~/.pi/agent/agents/{agent}/AGENTS.md
        - ~/.pi/agent/agents/{agent}/mcp.json
        - ~/.pi/agent/agents/{agent}/skills/{name}/SKILL.md
        """
        optic.debug("PiAdapter.format_config: agent={}", ctx.safe_name)
        options = ctx.options
        scope = options.get("scope", HARNESS_REGISTRY["pi"]["default_scope"])
        agent_name = ctx.safe_name

        result: dict = {}

        def _rewrite_path(p: str) -> str:
            # Rewrite ~/.pi/agent/... to ~/.pi/agent/agents/{agent_name}/...
            if p.startswith("~/.pi/agent/"):
                return p.replace("~/.pi/agent/", f"~/.pi/agent/agents/{agent_name}/", 1)
            elif p.startswith(".pi/"):
                return p.replace(".pi/", f".pi/agents/{agent_name}/", 1)
            return p

        # ── Rules / Agent file (AGENTS.md) ──
        if ctx.rules_content:
            rules_spec = HARNESS_REGISTRY["pi"]["agent_profile"]
            rules_path = rules_spec.get(scope, rules_spec.get("user", "AGENTS.md"))
            result["agent_profile"] = {
                "path": _rewrite_path(rules_path),
                "content": ctx.rules_content,
            }

        # ── MCP config (for pi-mcp-adapter) ──
        if ctx.mcp_configs:
            mcp_path_spec = HARNESS_REGISTRY["pi"]["mcp_config"]
            mcp_path = mcp_path_spec.get(scope, mcp_path_spec.get("user"))
            if mcp_path:
                result["mcp_config"] = {
                    "path": _rewrite_path(mcp_path),
                    "content": {"mcpServers": ctx.mcp_configs},
                }

        # ── Skills ──
        if ctx.skill_configs:
            skill_path_spec = HARNESS_REGISTRY["pi"]["skills"]
            skill_path = skill_path_spec.get(scope, skill_path_spec.get("user"))
            rewritten_skills = []
            for skill in ctx.skill_configs:
                skill_copy = dict(skill)
                name = skill_copy.get("name")
                if skill_path and name:
                    skill_copy["path"] = _rewrite_path(skill_path.format(name=name))
                rewritten_skills.append(skill_copy)
            result["skill_components"] = rewritten_skills

        if ctx.hook_configs:
            entries, warnings = pi_hook_entries(ctx.hook_configs, scope)
            if entries:
                result["hooks_config"] = {
                    "path": f"~/.pi/agent/agents/{agent_name}/observal-hooks.json",
                    "content": {"schema": PI_HOOKS_SCHEMA, "agent": agent_name, "hooks": entries},
                }
            if warnings:
                result["_warnings"] = warnings

        return result


register_adapter(PiAdapter())
