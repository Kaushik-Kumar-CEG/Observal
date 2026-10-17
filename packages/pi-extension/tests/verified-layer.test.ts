// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

const home = fs.mkdtempSync(path.join(os.tmpdir(), "observal-pi-verified-"));
process.env.HOME = home;
const observalDir = path.join(home, ".observal");
const piHome = path.join(home, ".pi", "agent");
fs.mkdirSync(piHome, { recursive: true });
fs.mkdirSync(observalDir, { recursive: true });
const sentinel = "private-setting-value-do-not-send";
fs.writeFileSync(path.join(piHome, "settings.json"), JSON.stringify({ token: sentinel }));
fs.writeFileSync(path.join(piHome, "mcp.json"), JSON.stringify({ mcpServers: { alpha: { command: "synthetic" } } }));
const id = "a11c01d1-1111-4111-8111-111111111111";
const pin = { id, type: "mcp", name: sentinel, version: "1.2.3", local_name: "alpha", secret: sentinel };
const sessionFile = path.join(home, "session.jsonl");
fs.writeFileSync(sessionFile, `${JSON.stringify({ type: "session", id: "pi-v2", timestamp: new Date().toISOString() })}\n`);
const canonical = JSON.stringify([[id, "1.2.3", "alpha"]]);
const v2 = `v2_${crypto.createHash("sha256").update(canonical).digest("hex")}`;
const manifestRequests: string[] = [];
const snapshotRequests: string[] = [];
const ingestPayloads: Array<Record<string, any>> = [];
let accept = true;
const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.method === "GET") {
    res.end(JSON.stringify({ session_id: "pi-v2", harness: "pi", acknowledged_line: -1, acknowledged_offset: 0 }));
    return;
  }
  const chunks: Buffer[] = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf-8");
    const payload = JSON.parse(body);
    if (req.url === "/api/v1/layer-snapshots") {
      snapshotRequests.push(body);
      res.end(JSON.stringify({ hash: payload.hash }));
    } else if (req.url === "/api/v1/mobile-evidence/v1/layers") {
      manifestRequests.push(body);
      res.end(JSON.stringify({ hash: accept ? v2 : "bad", mapped_components: 1 }));
    } else {
      ingestPayloads.push(payload);
      res.end(JSON.stringify({ acknowledged_line: payload.start_offset + payload.lines.length - 1,
        acknowledged_offset: payload.end_byte_offsets?.at(-1) ?? 0 }));
    }
  });
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
const address = server.address();
assert(address && typeof address === "object");
const origin = `http://127.0.0.1:${address.port}`;
fs.writeFileSync(path.join(observalDir, "config.json"),
  JSON.stringify({ server_url: origin, access_token: "desktop-token", user_id: "user" }));
fs.writeFileSync(path.join(observalDir, "lockfile.json"),
  JSON.stringify({ registries: { [origin]: { harnesses: { pi: { agents: [], standalone: [pin] } } } } }));
const handlers = new Map<string, (event: unknown, ctx: unknown) => Promise<void>>();
const extension = await import(`../extensions/observal.ts?verified=${Date.now()}`);
extension.default({ on: (event: string, handler: any) => handlers.set(event, handler), registerCommand() {} } as any);
let activeSessionFile = sessionFile;
let activeSessionId = "pi-v2";
const context = { cwd: home, hasUI: false, sessionManager: {
  getSessionFile: () => activeSessionFile, getSessionId: () => activeSessionId,
  getHeader: () => JSON.parse(fs.readFileSync(activeSessionFile, "utf-8").split("\n")[0]),
} };
await handlers.get("session_start")!({ reason: "startup" }, context);
await handlers.get("agent_end")!({}, context);
assert.equal(manifestRequests.length, 1);
assert.deepEqual(JSON.parse(manifestRequests[0]), { harness: "pi", components: [{ id, version: "1.2.3", alias: "alpha" }] });
assert(!manifestRequests[0].includes(sentinel), "sender must not expose local secret or unreviewed pin fields");
assert(snapshotRequests.length > 0);
assert(snapshotRequests.every((body) => !body.includes(sentinel)), "legacy snapshot must omit secret-bearing lockfile names and local file contents");
assert.deepEqual(JSON.parse(snapshotRequests[0]).pinned_versions, { agents: [], standalone: [] });
assert.equal(ingestPayloads[0].layer_hash, v2, "only acknowledged mapping is eligible for v2");
assert.match(String(ingestPayloads[0].run_incarnation), /^[0-9a-f-]{36}$/);
assert.match(String(ingestPayloads[0].run_header_hash), /^[0-9a-f]{64}$/);
assert.equal(ingestPayloads[0].run_origin, "pi_session_start_root_v1",
  "only a fresh Pi runtime session_start plus unparented header may claim root origin");
const cached = JSON.parse(fs.readFileSync(path.join(observalDir, "layer_snapshot.json"), "utf-8"));
assert.equal(cached.uploaded_to, crypto.createHash("sha256").update(origin).digest("hex"));
assert.ok(!fs.readFileSync(path.join(observalDir, "layer_snapshot.json"), "utf-8").includes(origin),
  "do not persist server URL or any embedded URL credentials in cache");
assert.equal(cached.uploaded_by, "user");
assert.equal(fs.statSync(path.join(observalDir, "layer_snapshot.json")).mode & 0o077, 0,
  "snapshot cache carries account binding and must remain private");
const acknowledgedSnapshots = snapshotRequests.length;
await handlers.get("session_start")!({ reason: "reload" }, context);
assert.equal(snapshotRequests.length, acknowledgedSnapshots, "same account and digest reuse acknowledged snapshot");
fs.writeFileSync(path.join(observalDir, "config.json"),
  JSON.stringify({ server_url: origin, access_token: "desktop-token", user_id: "different-user" }));
await handlers.get("session_start")!({ reason: "reload" }, context);
assert.equal(snapshotRequests.length, acknowledgedSnapshots + 1,
  "same local hash must be uploaded for a different authenticated account");
fs.writeFileSync(path.join(observalDir, "config.json"),
  JSON.stringify({ server_url: origin, access_token: "desktop-token", user_id: "user" }));
accept = false;
await handlers.get("session_start")!({ reason: "reload" }, context);
fs.appendFileSync(sessionFile, `${JSON.stringify({ type: "message", message: { role: "user", content: "next" } })}\n`);
await handlers.get("agent_end")!({}, context);
assert.equal(ingestPayloads.at(-1)?.layer_hash?.startsWith("v2_"), false, "bad receipt stays legacy");
assert.equal(ingestPayloads.at(-1)?.run_incarnation, ingestPayloads[0].run_incarnation,
  "same retained source keeps a single incarnation across reconnects");
assert.equal(ingestPayloads.at(-1)?.run_origin, "pi_session_start_root_v1",
  "a retry retains exactly its original witness rather than minting a new claim");

accept = true;
const uploaded = manifestRequests.length;
fs.rmSync(path.join(piHome, "mcp.json"));
await handlers.get("session_start")!({ reason: "reload" }, context);
fs.appendFileSync(sessionFile, `${JSON.stringify({ type: "message", message: { role: "user", content: "stale pin" } })}\n`);
await handlers.get("agent_end")!({}, context);
assert.equal(manifestRequests.length, uploaded, "a stale lockfile without active Pi MCP must not qualify");
assert.equal(ingestPayloads.at(-1)?.layer_hash?.startsWith("v2_"), false);

fs.writeFileSync(path.join(piHome, "mcp.json"), JSON.stringify({ mcpServers: { alpha: { command: "synthetic" } } }));
fs.writeFileSync(path.join(observalDir, "lockfile.json"), JSON.stringify({ registries: {
  [origin]: { harnesses: { pi: { agents: [], standalone: [] }, "claude-code": { agents: [], standalone: [pin] } } },
} }));
await handlers.get("session_start")!({ reason: "reload" }, context);
fs.appendFileSync(sessionFile, `${JSON.stringify({ type: "message", message: { role: "user", content: "other harness" } })}\n`);
await handlers.get("agent_end")!({}, context);
assert.equal(manifestRequests.length, uploaded, "a different harness's pin must not qualify Pi");
assert.equal(ingestPayloads.at(-1)?.layer_hash?.startsWith("v2_"), false);
activeSessionId = "pi-resumed";
activeSessionFile = path.join(home, "resumed.jsonl");
fs.writeFileSync(activeSessionFile, `${JSON.stringify({ type: "session", id: activeSessionId,
  timestamp: new Date().toISOString() })}\n`);
await handlers.get("session_start")!({ reason: "resume" }, context);
await handlers.get("agent_end")!({}, context);
assert.equal(ingestPayloads.at(-1)?.run_origin, undefined,
  "a fresh-looking unclaimed source resumed by Pi is not an interactive new-root witness");
activeSessionId = "pi-child";
activeSessionFile = path.join(home, "child.jsonl");
fs.writeFileSync(activeSessionFile, `${JSON.stringify({ type: "session", id: activeSessionId,
  timestamp: new Date().toISOString(), parentSession: sessionFile })}\n`);
await handlers.get("session_start")!({ reason: "new" }, context);
await handlers.get("agent_end")!({}, context);
assert.equal(ingestPayloads.at(-1)?.run_origin, undefined, "a parented child must not claim a root");
assert.equal(ingestPayloads.at(-1)?.parent_session_id, "pi-v2");
assert.equal(ingestPayloads.at(-1)?.parent_run_incarnation, ingestPayloads[0].run_incarnation);
assert.equal(ingestPayloads.at(-1)?.parent_header_hash, ingestPayloads[0].run_header_hash);
server.close();
fs.rmSync(home, { recursive: true, force: true });
console.log("verified layer sender ok");
