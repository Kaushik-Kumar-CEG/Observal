// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

const home = fs.mkdtempSync(path.join(os.tmpdir(), "observal-pi-hook-"));
process.env.HOME = home;
const local = path.join(home, ".observal");
const piHome = path.join(home, ".pi", "agent");
fs.mkdirSync(local, { recursive: true });
fs.mkdirSync(piHome, { recursive: true });
const secret = "do-not-upload-command-stderr-or-arguments";
const command = `echo ${secret} >&2; exit 7`;
const hookFile = path.join(piHome, "observal-hooks.json");
const id = "a11c01d1-1111-4111-8111-111111111111";
const entry = { name: "checker", event: "tool_call", type: "command", command, timeout: 5,
  id, version: "1.0.0" };
fs.writeFileSync(hookFile, JSON.stringify({ schema: "observal-pi-hooks/v1", agent: "default", hooks: [entry] }));
const sha = (value: string) => crypto.createHash("sha256").update(value).digest("hex");
const pin = { id, version: "1.0.0", scope: "user", alias: "checker",
  binding_sha256: sha(`tool_call\0${command}`) };
const hash = `v3_${sha(JSON.stringify([["hook", id, "1.0.0", "user", "checker", pin.binding_sha256]]))}`;
const session = path.join(home, "session.jsonl");
const header = { type: "session", id: "hook-sender", cwd: home, timestamp: new Date().toISOString() };
fs.writeFileSync(session, `${JSON.stringify(header)}\n`);
const received: Array<Record<string, any>> = [];
const ingests: Array<Record<string, any>> = [];
const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  if (req.method === "GET") {
    res.end(JSON.stringify({ session_id: header.id, harness: "pi", acknowledged_line: -1, acknowledged_offset: 0 }));
    return;
  }
  const chunks: Buffer[] = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (req.url === "/api/v1/layer-snapshots") res.end(JSON.stringify({ hash: payload.hash }));
    else if (req.url === "/api/v1/mobile-evidence/v1/layers") {
      received.push(payload);
      res.end(JSON.stringify({ hash, mapped_components: 1 }));
    } else {
      ingests.push(payload);
      res.end(JSON.stringify({ acknowledged_line: payload.start_offset + payload.lines.length - 1,
        acknowledged_offset: payload.end_byte_offsets?.at(-1) ?? 0 }));
    }
  });
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const addr = server.address();
assert(addr && typeof addr === "object");
const origin = `http://127.0.0.1:${addr.port}`;
fs.writeFileSync(path.join(local, "config.json"), JSON.stringify({ server_url: origin, access_token: "desktop-token" }));
const handlers = new Map<string, (event: any, ctx: any) => Promise<any>>();
const receipts: Array<Record<string, any>> = [];
const extension = await import(`../extensions/observal.ts?hook=${Date.now()}`);
extension.default({ on: (event: string, handler: any) => handlers.set(event, handler),
  appendEntry: (type: string, data: Record<string, any>) => {
    receipts.push(data);
    fs.appendFileSync(session, `${JSON.stringify({ type: "custom", customType: type, data,
      timestamp: new Date().toISOString() })}\n`);
  }, registerCommand() {} } as any);
const ctx = { cwd: home, hasUI: false, sessionManager: {
  getSessionFile: () => session, getSessionId: () => header.id, getHeader: () => header,
} };
await handlers.get("session_start")!({ reason: "startup" }, ctx);
assert.deepEqual(received, [{ harness: "pi", components: [], hooks: [pin] }]);
fs.appendFileSync(session, `${JSON.stringify({ type: "message", timestamp: new Date().toISOString(),
  message: { role: "assistant", content: [{ type: "toolCall", id: "call-1", name: "bash", arguments: {} }] } })}\n`);
const event = { toolCallId: "call-1", toolName: "bash", input: { password: secret } };
assert.equal(await handlers.get("tool_call")!(event, ctx), undefined);
assert.deepEqual(receipts[0], { v: 1, event: "tool_call", tool_call_id: "call-1",
  binding: pin.binding_sha256, outcome: "failed", exit_code: 7 });
await handlers.get("tool_call")!(event, ctx);
assert.equal(receipts.length, 1, "retry or duplicate extension cannot claim a second run");
await handlers.get("agent_end")!({}, ctx);
assert.equal(ingests[0]?.layer_hash, hash);
assert(ingests[0].lines.some((line: string) => line.includes("observal-hook-run")));
const receiptLines = ingests[0].lines.filter((line: string) => line.includes("observal-hook-run"));
assert(!JSON.stringify(received).includes(secret) && !JSON.stringify(receiptLines).includes(secret));
assert(!JSON.stringify(received).includes(command) && !JSON.stringify(receiptLines).includes(command));

// A changed profile is neither run nor attributed under the old generation.
fs.writeFileSync(hookFile, JSON.stringify({ schema: "observal-pi-hooks/v1", agent: "default", hooks: [
  { ...entry, command: "exit 0" },
] }));
await handlers.get("tool_call")!({ ...event, toolCallId: "call-2" }, ctx);
assert.equal(receipts.length, 1);
server.close();
fs.rmSync(home, { recursive: true, force: true });
console.log("verified Pi hook sender ok");
