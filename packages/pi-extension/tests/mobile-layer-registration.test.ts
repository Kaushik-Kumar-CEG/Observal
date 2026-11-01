// SPDX-FileCopyrightText: 2026 Observal Contributors
// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0
// Real extension sender: the old v2 snapshot/session with no /layers registration
// left the worker pending_mapping. The corrected run registers those same bytes
// and the three active verified pins before it pushes any source lines.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "observal-pi-mobile-map-")));
process.env.HOME = home;
const piHome = path.join(home, ".pi/agent"), store = path.join(home, ".observal");
fs.mkdirSync(piHome, { recursive: true }); fs.mkdirSync(store);
const session = path.join(home, "session.jsonl");
fs.writeFileSync(session, JSON.stringify({ type: "session", id: "pi-mobile-root", timestamp: new Date().toISOString() }) + "\n");
const events: string[] = [];
let snapshot: any, registration: any, source: any;
const server = http.createServer((request, response) => {
  const chunks: Buffer[] = []; request.on("data", chunk => chunks.push(chunk));
  request.on("end", () => {
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/api/v1/layer-snapshots") {
      events.push("snapshot"); snapshot = body; response.end(JSON.stringify({ hash: body.hash }));
    } else if (request.url === "/api/v1/mobile-evidence/v1/layers") {
      events.push("typed"); registration = body;
      response.end(JSON.stringify({ hash: body.source_layer_hash, mapped_components: 3 }));
    } else if (request.url === "/api/v1/ingest/session") {
      events.push("source"); source = body;
      response.end(JSON.stringify({ acknowledged_line: body.start_offset + body.lines.length - 1,
        acknowledged_offset: body.end_byte_offsets?.at(-1) ?? 0 }));
    } else {
      response.statusCode = 404; response.end("{}");
    }
  });
});
await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
const address = server.address(); assert(address && typeof address === "object");
const origin = `http://127.0.0.1:${address.port}`;
fs.writeFileSync(path.join(store, "config.json"), JSON.stringify({ server_url: origin, access_token: "test", user_id: "synthetic" }));
const ext = await import(`../extensions/observal.ts?mobile=${Date.now()}`);
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333"];
const config = { command: "node", args: [path.join(home, "ping.cjs")] };
fs.writeFileSync(path.join(piHome, "mcp.json"), JSON.stringify({ mcpServers: { rc: config } }));
const skill = "---\nname: rc\ndescription: disposable\n---\nRead the whole skill.\n";
fs.mkdirSync(path.join(piHome, "skills/rc"), { recursive: true });
fs.writeFileSync(path.join(piHome, "skills/rc/SKILL.md"), skill);
const hook = { name: "guard", event: "tool_call", type: "command", command: "true", timeout: 5 };
fs.writeFileSync(path.join(piHome, "observal-hooks.json"), JSON.stringify({ schema: "observal-pi-hooks/v1", agent: "synthetic", hooks: [hook] }));
const lock = { registries: { [origin]: { harnesses: { pi: { agents: [], standalone: [
  { type: "mcp", name: "rc", id: ids[0], version: "1.0.0", scope: "user", local_name: "rc",
    mcp_integrity: ext.mcpEntryFingerprint(config) },
  { type: "skill", name: "rc", id: ids[1], version: "1.0.0", scope: "user", local_name: "rc",
    skill_integrity: "sha256-" + sha(skill) },
  { type: "hook", name: "guard", id: ids[2], version: "1.0.0", scope: "user", local_name: "guard",
    hook_event: "tool_call", hook_command: "true", hook_config: "user:observal-hooks.json",
    hook_profile: "synthetic", hook_integrity: ext.piHookIntegrity("synthetic", hook) },
] } } } } };
fs.writeFileSync(path.join(store, "lockfile.json"), JSON.stringify(lock));
const handlers = new Map<string, (event: unknown, ctx: unknown) => Promise<void>>();
ext.default({ on: (name: string, handler: any) => handlers.set(name, handler), registerCommand() {} } as any);
const context = { cwd: home, hasUI: false, sessionManager: { getSessionFile: () => session, getSessionId: () => "pi-mobile-root" } };
try {
  await handlers.get("session_start")!({ reason: "startup" }, context);
  await handlers.get("session_shutdown")!({}, context);
  assert.deepEqual(events.slice(0, 3), ["snapshot", "typed", "source"]);
  assert.match(snapshot.hash, /^v2_[0-9a-f]{60}$/);
  assert.deepEqual(snapshot.drift.mcp_verifications.map((x: any) => x.status), ["verified"]);
  assert.deepEqual(snapshot.drift.skill_verifications.map((x: any) => x.status), ["verified"]);
  assert.deepEqual(snapshot.drift.hook_verifications.map((x: any) => x.status), ["verified"]);
  assert.equal(registration.source_layer_hash, snapshot.hash);
  assert.deepEqual([registration.components[0].id, registration.skills[0].id, registration.hooks[0].id], ids);
  assert.equal(registration.skills[0].content_sha256, sha(skill));
  assert.equal(registration.hooks[0].binding_sha256, ext.piHookBinding("tool_call", "true"));
  assert.equal(source.layer_hash, snapshot.hash, "worker joins exactly the registered source hash");
  assert.match(source.run_incarnation, /^[0-9a-f]{8}-[0-9a-f-]{27}$/);
  assert.equal(source.run_header_hash, sha(fs.readFileSync(session, "utf8").split("\n")[0]!));
  assert.equal(source.run_origin, "pi_session_start_root_v1", "root requires actual session_start witness");
  assert(!JSON.stringify(registration).includes("test"), "no credential in typed pin registration");
  const claims = fs.readdirSync(path.join(store, "pi_run_identity"));
  assert.equal(claims.length, 1, "fresh root nonce persisted for identical retries");
  const saved = JSON.parse(fs.readFileSync(path.join(store, "pi_run_identity", claims[0]!), "utf8"));
  assert.equal(saved.run_incarnation, source.run_incarnation);
  assert.equal(saved.run_header_hash, source.run_header_hash);

  // An old partially-delivered Pi session cannot be retroactively promoted.
  const legacyFile = path.join(home, "legacy.jsonl");
  const legacyHeader = JSON.stringify({ type: "session", id: "pi-legacy", timestamp: new Date().toISOString() }) + "\n";
  fs.writeFileSync(legacyFile, legacyHeader + JSON.stringify({ type: "message", index: 1 }) + "\n");
  const cursors = JSON.parse(fs.readFileSync(path.join(store, "sync_state.json"), "utf8"));
  cursors["pi-legacy"] = { offset: Buffer.byteLength(legacyHeader), line_count: 1 };
  fs.writeFileSync(path.join(store, "sync_state.json"), JSON.stringify(cursors));
  const legacyContext = { ...context, sessionManager: { getSessionFile: () => legacyFile, getSessionId: () => "pi-legacy" } };
  await handlers.get("session_start")!({ reason: "resume" }, legacyContext);
  await handlers.get("session_shutdown")!({}, legacyContext);
  assert.equal(source.start_offset, 1);
  assert.equal(source.run_incarnation, undefined, "prior legacy source must never gain a nonce");
  assert.equal(source.run_origin, undefined);
  assert.equal(fs.readdirSync(path.join(store, "pi_run_identity")).length, 1);
} finally {
  server.close(); fs.rmSync(home, { recursive: true, force: true });
}
console.log("mobile typed Pi registration precedes source delivery");
