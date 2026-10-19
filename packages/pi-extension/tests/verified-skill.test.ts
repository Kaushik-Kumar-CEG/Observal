// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

const home = fs.mkdtempSync(path.join(os.tmpdir(), "observal-pi-skill-"));
process.env.HOME = home;
const local = path.join(home, ".observal");
const piHome = path.join(home, ".pi", "agent");
const alias = "review";
const skill = path.join(piHome, "skills", alias, "SKILL.md");
const secret = "secret-install-metadata-must-never-leave-the-device";
fs.mkdirSync(path.dirname(skill), { recursive: true });
fs.mkdirSync(local, { recursive: true });
const content = "---\nname: review\ndescription: Review code\n---\n# Review\n";
fs.writeFileSync(skill, content);
const id = "a11c01d1-1111-4111-8111-111111111111";
const pin = { id, type: "skill", version: "1.2.3", local_name: alias, scope: "user", secret };
const file = path.join(home, "session.jsonl");
const header = { type: "session", id: "skill-sender", cwd: home, timestamp: new Date().toISOString() };
fs.writeFileSync(file, `${JSON.stringify(header)}\n`);
const sha = (value: string) => crypto.createHash("sha256").update(value).digest("hex");
const expected = { id, version: "1.2.3", scope: "user", alias,
  location_sha256: sha(skill), content_sha256: sha(content) };
const hash = `v3_${sha(JSON.stringify([["skill", id, "1.2.3", "user", alias,
  expected.location_sha256, expected.content_sha256]]))}`;
const manifests: Array<Record<string, any>> = [];
const ingests: Array<Record<string, any>> = [];
let acknowledge = true;
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
      manifests.push(payload);
      res.end(JSON.stringify({ hash: acknowledge ? hash : "invalid", mapped_components: 1 }));
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
fs.writeFileSync(path.join(local, "lockfile.json"), JSON.stringify({ registries: {
  [origin]: { harnesses: { pi: { standalone: [pin], agents: [
    { id: "b11c01d1-1111-4111-8111-111111111111", components: [
      { id: "c11c01d1-1111-4111-8111-111111111111", type: "skill", version: "1.2.3" },
    ] },
  ] } } },
} }));
const handlers = new Map<string, (event: any, ctx: any) => Promise<void>>();
const extension = await import(`../extensions/observal.ts?skill=${Date.now()}`);
extension.default({ on: (event: string, handler: any) => handlers.set(event, handler), registerCommand() {} } as any);
const ctx = { cwd: home, hasUI: false, sessionManager: {
  getSessionFile: () => file, getSessionId: () => header.id, getHeader: () => header,
} };
await handlers.get("session_start")!({ reason: "startup" }, ctx);
await handlers.get("agent_end")!({}, ctx);
assert.deepEqual(manifests, [{ harness: "pi", components: [], skills: [expected] }],
  "unverified agent-profile skill cannot suppress independently verified standalone skill");
assert.equal(ingests[0]?.layer_hash, hash);
assert(!JSON.stringify(manifests).includes(secret));
assert(!JSON.stringify(manifests).includes(content));
assert(!JSON.stringify(manifests).includes(skill), "path digest only, never absolute location");

acknowledge = false;
await handlers.get("session_start")!({ reason: "reload" }, ctx);
fs.appendFileSync(file, `${JSON.stringify({ type: "message", message: { role: "user", content: "retry" } })}\n`);
await handlers.get("agent_end")!({}, ctx);
assert(!String(ingests.at(-1)?.layer_hash).startsWith("v3_"), "invalid mapping receipt cannot qualify");

acknowledge = true;
fs.rmSync(skill);
await handlers.get("session_start")!({ reason: "reload" }, ctx);
fs.appendFileSync(file, `${JSON.stringify({ type: "message", message: { role: "user", content: "missing" } })}\n`);
await handlers.get("agent_end")!({}, ctx);
assert.equal(manifests.length, 2, "stale installation must not emit a pin");
assert(!String(ingests.at(-1)?.layer_hash).startsWith("v3_"));
server.close();
fs.rmSync(home, { recursive: true, force: true });
console.log("verified Pi skill sender ok");
