def generate_hook_telemetry_config(
    hook_listing, ide: str, server_url: str = "http://localhost:8000", platform: str = ""
) -> dict:
    if ide in ("kiro", "kiro-cli"):
        event = str(hook_listing.event)
        # Map Claude Code PascalCase events to Kiro camelCase
        kiro_event_map = {
            "SessionStart": "agentSpawn",
            "UserPromptSubmit": "userPromptSubmit",
            "PreToolUse": "preToolUse",
            "PostToolUse": "postToolUse",
            "Stop": "stop",
        }
        kiro_event = kiro_event_map.get(event, event)

        if kiro_event == "stop":
            stop_cmd = f"observal-kiro-stop-hook --url {server_url}/api/v1/telemetry/hooks"
            return {"hooks": {kiro_event: [{"command": stop_cmd}]}}

        cmd = f"observal-kiro-hook --url {server_url}/api/v1/telemetry/hooks"
        hook_entry = {"command": cmd}
        if kiro_event in ("preToolUse", "postToolUse"):
            hook_entry["matcher"] = "*"
        return {"hooks": {kiro_event: [hook_entry]}}

    hook_entry = {
        "type": "http",
        "url": f"{server_url}/api/v1/telemetry/hooks",
        "timeout": 10,
    }

    if ide == "claude-code":
        hook_entry["allowedEnvVars"] = ["OBSERVAL_API_KEY"]
    elif ide != "cursor":
        return {"comment": f"IDE '{ide}' requires manual hook setup. See Observal docs for configuration."}

    event = str(hook_listing.event)
    return {"hooks": {event: [{"matcher": "*", "hooks": [hook_entry]}]}}
