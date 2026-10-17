// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

/** Deterministic sender network/outbox assertions plus opt-in no-model timing. */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

const home = fs.mkdtempSync(path.join(os.tmpdir(), "observal-pi-cost-"));
process.env.HOME = home;
const piHome = path.join(home, ".pi", "agent");
const local = path.join(home, ".observal");
fs.mkdirSync(piHome, { recursive: true });
fs.mkdirSync(local, { recursive: true });
for (let i = 0; i < (process.env.OBSERVAL_PI_BENCH === "1" ? 1400 : 12); i++) {
  fs.mkdirSync(path.join(piHome, "npm", "cache", `package-${i}`), { recursive: true });
}
fs.writeFileSync(path.join(piHome, "settings.json"), JSON.stringify({ token: "not-a-real-credential" }));
const id = "a11c01d1-1111-4111-8111-111111111111";
const sha = (value: string) => crypto.createHash("sha256").update(value).digest("hex");
const hook = { id, version: "1.0.0", name: "intentional", event: "tool_call", type: "command", command: "exit 0", timeout: 3 };
const hookFile = path.join(piHome, "observal-hooks.json");
const session = path.join(home, "session.jsonl");
let requests: string[] = [];
let bytes: number[] = [];
const snapshots: Array<Record<string, any>> = [];
const server = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (part) => chunks.push(part));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf-8");
    const body = raw ? JSON.parse(raw) : {};
    requests.push(req.url ?? "");
    bytes.push(Buffer.byteLength(raw));
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/api/v1/layer-snapshots") {
      snapshots.push(body);
      res.end(JSON.stringify({ hash: body.hash }));
    } else if (req.url === "/api/v1/mobile-evidence/v1/layers") {
      const pins = (body.hooks ?? []).map((pin: any) => ["hook", pin.id, pin.version, pin.scope, pin.alias, pin.binding_sha256]);
      res.end(JSON.stringify({ hash: `v3_${sha(JSON.stringify(pins))}`, mapped_components: pins.length }));
    } else if (req.url === "/api/v1/ingest/session") {
      res.end(JSON.stringify({ acknowledged_line: body.start_offset + body.lines.length - 1,
        acknowledged_offset: body.end_byte_offsets?.at(-1) ?? 0 }));
    } else {
      res.statusCode = 404;
      res.end("{}");
    }
  });
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert(address && typeof address === "object");
fs.writeFileSync(path.join(local, "config.json"), JSON.stringify({
  server_url: `http://127.0.0.1:${address.port}`, access_token: "test-only", user_id: "test-user",
}));
const extension = await import(`../extensions/observal.ts?cost=${Date.now()}`);
const handlers = new Map<string, (event: any, ctx: any) => Promise<any>>();
let receipts = 0;
extension.default({
  on: (name: string, handler: any) => handlers.set(name, handler),
  appendEntry: (name: string, data: Record<string, unknown>) => {
    receipts++;
    fs.appendFileSync(session, `${JSON.stringify({ type: "custom", customType: name, data,
      timestamp: new Date().toISOString() })}\n`);
  },
  registerCommand() {},
} as any);
const ctx = { cwd: home, hasUI: false, sessionManager: {
  getSessionFile: () => session,
  getSessionId: () => JSON.parse(fs.readFileSync(session, "utf-8").split("\n")[0]).id,
  getHeader: () => JSON.parse(fs.readFileSync(session, "utf-8").split("\n")[0]),
} };
function p95(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor((sorted.length - 1) * 0.95)];
}
async function scenario(withHook: boolean, n: number) {
  if (withHook) fs.writeFileSync(hookFile, JSON.stringify({ schema: "observal-pi-hooks/v1", agent: "default", hooks: [hook] }));
  else if (fs.existsSync(hookFile)) fs.unlinkSync(hookFile);
  const plain = performance.now();
  fs.writeFileSync(session, `${JSON.stringify({ type: "session", id: withHook ? "hook-run" : "plain-run",
    cwd: home, timestamp: new Date().toISOString() })}\n`);
  const baselineStartup = performance.now() - plain;
  const baselineSamples: number[] = [];
  for (let i = 0; i < n; i++) {
    const start = performance.now();
    await Promise.resolve();
    baselineSamples.push(performance.now() - start);
  }
  requests = [];
  bytes = [];
  const start = performance.now();
  await handlers.get("session_start")!({ reason: "startup" }, ctx);
  const startup = performance.now() - start;
  const startupRequests = requests.length;
  const samples: number[] = [];
  for (let i = 0; i < n; i++) {
    const begin = performance.now();
    const event = { toolCallId: `${withHook ? "hook" : "plain"}-${i}`, toolName: "read", input: {} };
    await handlers.get("tool_call")!(event, ctx);
    await handlers.get("tool_result")!({ ...event, isError: false }, ctx);
    samples.push(performance.now() - begin);
  }
  assert.equal(requests.length, startupRequests, "no network request is allowed on a tool event");
  const beforeEnd = requests.length;
  await handlers.get("agent_end")!({}, ctx);
  const counts = { startupRequests, toolRequests: beforeEnd - startupRequests,
    ingestRequests: requests.filter((url) => url === "/api/v1/ingest/session").length,
    totalRequests: requests.length, bytesSent: bytes.reduce((sum, value) => sum + value, 0) };
  assert.equal(counts.ingestRequests, 1, "retain one acknowledged batch at turn end");
  assert.equal(counts.toolRequests, 0);
  assert.equal(receipts, withHook ? n : 0, "execute only intentionally installed hook commands");
  const outbox = path.join(local, "pi_session_outbox");
  assert.equal(fs.existsSync(outbox) ? fs.readdirSync(outbox).filter((file) => file.endsWith(".json")).length : 0, 0,
    "acknowledged delivery must clear its durable outbox");
  return { scenario: withHook ? "intentional_hooks" : "no_hooks", baselineStartupMs: baselineStartup,
    baselineToolP95Ms: p95(baselineSamples), enabledStartupMs: startup, enabledToolP95Ms: p95(samples), ...counts };
}
try {
  const noHooks = await scenario(false, 100);
  assert.equal(noHooks.startupRequests, 1, "first snapshot is sent once");
  assert.equal(snapshots[0]?.harnesses?.pi?.length, 1, "ignore unrelated npm cache but retain actual Pi settings file");
  assert.equal(snapshots[0]?.harnesses?.pi?.[0]?.content, undefined, "never send local settings contents");
  const withHooks = await scenario(true, 40);
  assert.equal(withHooks.startupRequests, 1, "unchanged snapshot is reused; intentional hook mapping is acknowledged");
  assert.equal(receipts, 40);
  if (process.env.OBSERVAL_PI_BENCH === "1") {
    console.log(JSON.stringify(noHooks));
    console.log(JSON.stringify(withHooks));
  }
  console.log("sender cost and intentional-hook delivery assertions passed");
} finally {
  server.close();
  fs.rmSync(home, { recursive: true, force: true });
}
