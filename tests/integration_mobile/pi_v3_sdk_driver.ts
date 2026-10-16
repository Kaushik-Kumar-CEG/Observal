// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0
/** No-model Pi SDK transcript + installed Observal extension lifecycle.
 * Opt-in; caller supplies an isolated HOME, SDK entry point and short-lived
 * desktop credential. Never run this driver against a real-person instance.
 */
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

const required = (key: string): string => {
  const value = process.env[key];
  if (!value) throw new Error(`Missing ${key}`);
  return value;
};
const home = required("PI_PROBE_HOME");
const origin = required("PI_PROBE_ORIGIN");
const sdkFile = required("PI_PROBE_SDK_ENTRY");
const token = required("PI_PROBE_ACCESS_TOKEN");
const mcpId = required("PI_PROBE_MCP_ID");
const skillId = required("PI_PROBE_SKILL_ID");
const hookId = required("PI_PROBE_HOOK_ID");
const skillContent = fs.readFileSync(required("PI_PROBE_SKILL_CONTENT_FILE"), "utf8");
const hookCommand = required("PI_PROBE_HOOK_COMMAND");
const { SessionManager } = await import(pathToFileURL(sdkFile).href);
assert.equal(os.homedir(), home);
assert.equal(path.dirname(home), path.resolve(path.dirname(home)));
const cwd = path.join(home, "project");
const piDir = path.join(home, ".pi", "agent");
const obsDir = path.join(home, ".observal");
fs.mkdirSync(cwd, { recursive: true });
fs.mkdirSync(obsDir, { recursive: true, mode: 0o700 });
const skillPath = path.join(piDir, "skills", "review", "SKILL.md");
fs.mkdirSync(path.dirname(skillPath), { recursive: true });
fs.writeFileSync(skillPath, skillContent, { mode: 0o600 });
fs.writeFileSync(path.join(piDir, "mcp.json"), JSON.stringify({ mcpServers: { alpha: { command: "synthetic-no-launch" } } }));
fs.writeFileSync(path.join(piDir, "observal-hooks.json"), JSON.stringify({ schema: "observal-pi-hooks/v1",
  agent: "synthetic", hooks: [{ id: hookId, version: "1.0.0", name: "pre-tool", event: "tool_call",
    type: "command", command: hookCommand, timeout: 5 }] }));
fs.writeFileSync(path.join(obsDir, "config.json"), JSON.stringify({ server_url: origin, access_token: token }), { mode: 0o600 });
fs.writeFileSync(path.join(obsDir, "lockfile.json"), JSON.stringify({ registries: { [origin]: { harnesses: {
  pi: { agents: [], standalone: [
    { type: "mcp", id: mcpId, version: "1.0.0", local_name: "alpha" },
    { type: "skill", id: skillId, version: "1.0.0", local_name: "review", scope: "user" },
  ] },
} } } }), { mode: 0o600 });

// The SDK, not the test, serializes the header, message tree and custom entry.
const manager = SessionManager.create(cwd, path.join(home, "sessions"));
const context = { cwd, sessionManager: manager, hasUI: false };
const handlers = new Map<string, (event: any, ctx: any) => Promise<any>>();
const pi = { on: (event: string, handler: any) => handlers.set(event, handler),
  registerCommand() {}, appendEntry: (name: string, data: unknown) => manager.appendCustomEntry(name, data) };
const extension = await import("../../packages/pi-extension/extensions/observal.ts");
extension.default(pi as any);
await handlers.get("session_start")!({ reason: "startup" }, context);
const now = Date.now();
manager.appendMessage({ role: "system", content: "", timestamp: now,
  sections: { skills: `<available_skills><skill><name>review</name><description>isolated</description>` +
    `<location>${skillPath}</location></skill></available_skills>` } });
const call = `mcp-${crypto.randomUUID()}`;
const read = `read-${crypto.randomUUID()}`;
manager.appendMessage({ role: "assistant", api: "test-no-model", provider: "local", model: "deterministic",
  usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
  stopReason: "toolUse", timestamp: Date.now(), content: [
    { type: "toolCall", id: read, name: "read", arguments: { path: skillPath } },
    { type: "toolCall", id: call, name: "mcp", arguments: { server: "alpha", tool: "fetch" } },
  ] });
const result = await handlers.get("tool_call")!({ toolCallId: call, toolName: "mcp", input: {} }, context);
assert.equal(result, undefined, "the configured synthetic hook must not block the tool");
manager.appendMessage({ role: "toolResult", toolCallId: read, toolName: "read", isError: false,
  content: [{ type: "text", text: skillContent }], timestamp: Date.now() });
manager.appendMessage({ role: "toolResult", toolCallId: call, toolName: "mcp", isError: false,
  details: { mode: "call", server: "alpha", tool: "fetch" },
  content: [{ type: "text", text: "synthetic response" }], timestamp: Date.now() });
await handlers.get("agent_end")!({}, context);
await handlers.get("session_shutdown")!({}, context);
const lines = fs.readFileSync(manager.getSessionFile(), "utf8").trim().split("\n").map(JSON.parse);
const receipts = lines.filter((line: any) => line.customType === "observal-hook-run");
assert.equal(receipts.length, 1, "Pi persisted exactly one hook run");
assert.equal(receipts[0].data.outcome, "ran");
assert(!JSON.stringify(receipts).includes(hookCommand));
// IDs only; token and source path are not printed by this driver.
console.log(JSON.stringify({ session: manager.getSessionId(), root: lines[0].id,
  line_count: lines.length, receipt_count: receipts.length }));
