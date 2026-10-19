// SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
// SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
// SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

/**
 * Observal session telemetry extension for Pi.
 *
 * Reads the session JSONL file incrementally on lifecycle events and POSTs
 * raw lines to the Observal ingest API. Zero runtime dependencies - uses
 * only node:* built-ins.
 *
 * Design principles:
 * - Fail-open: never throw, never crash pi
 * - 5s timeout on all HTTP calls
 * - Generation counter for async safety
 * - Durable batches before network delivery
 * - Cursor advancement only after contiguous server acknowledgement
 * - Chunk at 500 lines per POST to avoid 413
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import * as crypto from "node:crypto";
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as os from "node:os";
import * as path from "node:path";

// ─── Types ───────────────────────────────────────────────────────────────────

interface ObservalConfig {
  server_url: string;
  access_token: string;
  user_id?: string;
  agent_id?: string;
  agent_version?: string;
}

export interface PendingBatch {
  session_id: string;
  destination: string;
  user_id?: string;
  payload: Record<string, unknown>;
  end_line: number;
  end_offset: number;
  final: boolean;
}

interface CursorEntry {
  offset: number;
  line_count: number;
  run_incarnation?: string;
  run_header_hash?: string;
  run_origin?: "pi_session_start_root_v1";
  parent_session_id?: string;
  parent_run_incarnation?: string;
  parent_header_hash?: string;
  source_identity?: string;
  finalized?: boolean;
  last_pushed_at?: number;
  local_valid?: boolean;
}

interface LayerFileEntry {
  path: string;
  hash: string;
  size: number;
  source: string;
  content?: string;
}

interface LayerSnapshot {
  hash: string;
  harnesses: Record<string, LayerFileEntry[]>;
  lockfile_hash: string;
  pinned_versions: Record<string, unknown>;
  drift: Record<string, unknown>;
}

interface ObservalState {
  config: ObservalConfig | null;
  sessionFile: string | null;
  sessionId: string;
  cwd: string;
  byteOffset: number;
  lineCount: number;
  generation: number;
  layerHash: string | null;
  layerSnapshot: LayerSnapshot | null;
  runIncarnation?: string;
  runHeaderHash?: string;
  runOrigin?: "pi_session_start_root_v1";
  parentSessionId?: string;
  parentRunIncarnation?: string;
  parentHeaderHash?: string;
  freshRootStart?: boolean;
  identityConflict?: boolean;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const OBSERVAL_DIR = path.join(os.homedir(), ".observal");
const CONFIG_PATH = path.join(OBSERVAL_DIR, "config.json");
const SYNC_STATE_PATH = path.join(OBSERVAL_DIR, "sync_state.json");
const LAYER_SNAPSHOT_PATH = path.join(OBSERVAL_DIR, "layer_snapshot.json");
const LOCKFILE_PATH = path.join(OBSERVAL_DIR, "lockfile.json");
const OUTBOX_DIR = path.join(OBSERVAL_DIR, "pi_session_outbox");
// Written by `observal discover use` and the install commands; read here so the
// session payload can say which registry resources this session relied on.
const CAPABILITY_LOCK_PATH = path.join(OBSERVAL_DIR, "capability_lock.jsonl");
const CAPABILITY_LEAD_MS = 15 * 60 * 1000;
const CAPABILITY_FALLBACK_MS = 24 * 60 * 60 * 1000;
const MAX_CAPABILITIES_PER_PUSH = 200;
const TIMEOUT_MS = 5_000;
const MAX_LINES_PER_CHUNK = 500;
const RECOVERY_MAX_SESSIONS = 5;
const RECOVERY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_LAYER_FILE_SIZE = 512 * 1024;
const MAX_OUTBOX_BYTES = 256 * 1024 * 1024;
const HOOK_SCHEMA = "observal-pi-hooks/v1";
const HOOK_FILE = "observal-hooks.json";
const HOOK_CLAIMS = Symbol.for("observal.pi.mobile-hook-claims");
interface RegistryHook { id: string; version: string; name: string; event: "tool_call" | "tool_result";
  command: string; timeout: number; binding: string }

export function acknowledgementCovers(acknowledgement: unknown, pending: PendingBatch): boolean {
  if (!acknowledgement || typeof acknowledgement !== "object") return false;
  const acknowledgedLine = (acknowledgement as Record<string, unknown>).acknowledged_line;
  return Number.isInteger(acknowledgedLine) && Number(acknowledgedLine) >= pending.end_line;
}

// ─── Extension Entry ─────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  let state: ObservalState | null = null;

  let hookRuntime: { hash: string; entries: RegistryHook[] } | null = null;
  pi.on("session_start", async (event, ctx) => {
    state = initState(ctx, event.reason);
    hookRuntime = loadRegistryHooks();

    if (state.config && state.layerSnapshot) {
      // Never report a v2 identity until the legacy snapshot and uploader-bound
      // allowlisted mapping have both been acknowledged by this server/account.
      try {
        const snapshotOk = await uploadLayerSnapshot(state.config, state.layerSnapshot);
        if (snapshotOk) await uploadVerifiedLayer(state.config, state);
        else if (ctx.hasUI) ctx.ui.notify("Layer snapshot upload failed", "warning");
      } catch {
        // Offline sessions continue with the legacy unqualified hash.
      }
    }

    // On fresh startup, attempt crash recovery (fire-and-forget)
    if (event.reason === "startup" && state.config) {
      recoverStaleSessions(state, ctx).catch(() => {});
    }

    if (state.config && ctx.hasUI) {
      const theme = ctx.ui.theme;
      ctx.ui.setStatus("observal", theme.fg("dim", "● observal"));
    }
  });

  pi.on("agent_end", async (_event, _ctx) => {
    if (!state?.config || !state.sessionFile) return;
    await pushNewLines(state, { final: false });
  });

  pi.on("session_shutdown", async (_event, _ctx) => {
    if (!state?.config || !state.sessionFile) return;
    await pushNewLines(state, { final: true });
    state = null;
  });

  // The commands execute locally, but ONLY the bounded, non-content receipt
  // goes into Pi's source JSONL. The session uploader retries that JSONL.
  async function runHook(entry: RegistryHook, input: string, cwd: string): Promise<number | null> {
    return new Promise((resolve) => {
      let settled = false;
      let child: ReturnType<typeof spawn>;
      let timer: NodeJS.Timeout | undefined;
      const finish = (code: number | null) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve(code);
      };
      try {
        child = spawn("/bin/sh", ["-c", entry.command], {
          cwd, env: process.env, detached: true, stdio: ["pipe", "ignore", "ignore"],
        });
      } catch { finish(null); return; }
      timer = setTimeout(() => {
        try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { /* already gone */ }
        finish(null);
      }, entry.timeout * 1000);
      child.on("error", () => finish(null));
      child.on("close", (code) => finish(typeof code === "number" ? code : null));
      child.stdin?.on("error", () => { /* local command need not read input */ });
      child.stdin?.end(input);
    });
  }

  async function runRegistryHooks(event: "tool_call" | "tool_result", payload: Record<string, any>,
    ctx: ExtensionContext): Promise<{ block: true; reason: string } | undefined> {
    const session = state;
    const runtime = hookRuntime;
    const callId = payload.toolCallId;
    if (!session || !runtime || typeof callId !== "string" || !callId || callId.length > 256 ||
        !runtime.entries.some((entry) => entry.event === event)) return undefined;
    // Detect active-file drift; a changed command cannot retain the old pin.
    if (loadRegistryHooks()?.hash !== runtime.hash) return undefined;
    const claims = (globalThis as any)[HOOK_CLAIMS] ??= new Set<string>();
    const key = `${session.sessionId}\0${event}\0${callId}`;
    if (claims.has(key)) return undefined;
    claims.add(key);
    if (claims.size > 4096) claims.delete(claims.values().next().value);
    const input = JSON.stringify({ hook_event_name: event === "tool_call" ? "PreToolUse" : "PostToolUse",
      pi_event: event, session_id: session.sessionId, cwd: ctx.cwd,
      tool_name: payload.toolName, tool_call_id: callId, tool_input: payload.input ?? {},
      ...(event === "tool_result" ? { tool_response: { is_error: payload.isError === true } } : {}) });
    for (const entry of runtime.entries.filter((item) => item.event === event)) {
      const code = await runHook(entry, input, ctx.cwd);
      const outcome = code === 0 ? "ran" : code === 2 && event === "tool_call" ? "blocked" : "failed";
      try {
        pi.appendEntry("observal-hook-run", { v: 1, event, tool_call_id: callId,
          binding: entry.binding, outcome, exit_code: code });
      } catch { /* Never break Pi because the receipt cannot be persisted. */ }
      if (outcome === "blocked") return { block: true, reason: "Blocked by a registry hook" };
    }
    return undefined;
  }

  pi.on("tool_call", async (event, ctx) => {
    try { return await runRegistryHooks("tool_call", event as Record<string, any>, ctx); }
    catch { return undefined; }
  });
  pi.on("tool_result", async (event, ctx) => {
    try { await runRegistryHooks("tool_result", event as Record<string, any>, ctx); }
    catch { /* Sender must not change tool results on reporting errors. */ }
    return undefined;
  });

  // ─── /obs-sync command ─────────────────────────────────────────────────

  pi.registerCommand("agent", {
    description: "Manage and swap active Observal agents",
    handler: async (args, ctx) => {
      const agentId = args.trim();
      const PI_HOME = path.join(os.homedir(), ".pi", "agent");
      const AGENTS_DIR = path.join(PI_HOME, "agents");

      function backupDefault() {
        if (!fs.existsSync(AGENTS_DIR)) fs.mkdirSync(AGENTS_DIR, { recursive: true });
        const defaultDir = path.join(AGENTS_DIR, "default");
        if (fs.existsSync(defaultDir)) return; // already backed up

        fs.mkdirSync(defaultDir, { recursive: true });

        const filesToCopy = [
          { name: "AGENTS.md", isDir: false },
          { name: "SYSTEM.md", isDir: false },
          { name: "mcp.json", isDir: false },
          { name: HOOK_FILE, isDir: false },
          { name: "skills", isDir: true },
          { name: "sandboxes", isDir: true }
        ];

        for (const f of filesToCopy) {
          const src = path.join(PI_HOME, f.name);
          const dest = path.join(defaultDir, f.name);
          if (fs.existsSync(src)) {
            fs.cpSync(src, dest, { recursive: true });
          }
        }
      }

      function applyProfile(name: string) {
        const profileDir = path.join(AGENTS_DIR, name);
        if (!fs.existsSync(profileDir)) throw new Error(`Profile ${name} not found`);

        const activeItems = ["AGENTS.md", "SYSTEM.md", "mcp.json", HOOK_FILE, "skills", "sandboxes"];
        for (const f of activeItems) {
          const target = path.join(PI_HOME, f);
          if (fs.existsSync(target)) {
            fs.rmSync(target, { recursive: true, force: true });
          }
        }

        for (const f of activeItems) {
          const src = path.join(profileDir, f);
          const dest = path.join(PI_HOME, f);
          if (fs.existsSync(src)) {
            fs.cpSync(src, dest, { recursive: true });
          }
        }
      }

      if (!fs.existsSync(AGENTS_DIR)) {
        fs.mkdirSync(AGENTS_DIR, { recursive: true });
      }

      // Automatically populate AGENTS_DIR from normal .pi/agent files if it's currently holding an active agent but no profile exists for it
      // but primarily we rely on observal agent pull populating agents/.
      backupDefault();

      let choice = agentId;

      if (!choice) {
        const profiles = fs.readdirSync(AGENTS_DIR).filter(d => fs.statSync(path.join(AGENTS_DIR, d)).isDirectory());
        if (profiles.length === 0) {
          ctx.ui.notify("No agents installed yet. Use the Observal skill or 'observal agent pull <agent> --harness pi' to install one.", "info");
          return;
        }

        const selected = await ctx.ui.select("Select agent to swap to:", profiles);
        if (!selected) return;
        choice = selected;
      }

      try {
        applyProfile(choice);

        if (state?.config) {
          const binding = resolvePiAgentBinding(choice);
          state.config.agent_id = choice === "default" ? undefined : binding.id;
          state.config.agent_version = choice === "default" ? undefined : binding.version;
          try {
            const configRaw = fs.readFileSync(CONFIG_PATH, "utf-8");
            const configJson = JSON.parse(configRaw);
            if (choice === "default") {
              delete configJson.active_agent;
            } else {
              configJson.active_agent = {
                id: binding.id,
                name: binding.name,
                ...(binding.version ? { version: binding.version } : {}),
              };
            }
            fs.writeFileSync(CONFIG_PATH, JSON.stringify(configJson, null, 2));
          } catch (err) {
            // ignore
          }

          state.layerSnapshot = buildPiLayerSnapshot();
          state.layerHash = state.layerSnapshot.hash;
          hookRuntime = loadRegistryHooks();
          if (await uploadLayerSnapshot(state.config, state.layerSnapshot)) {
            await uploadVerifiedLayer(state.config, state);
          } else {
            ctx.ui.notify("Layer snapshot upload failed", "warning");
          }
        }

        const ok = await ctx.ui.confirm("Agent Swapped", `Swapped to ${choice}. Reload session now?`);
        if (ok) {
          await ctx.reload();
        }
      } catch (e: any) {
        ctx.ui.notify(`Error swapping agent: ${e.message}`, "error");
      }
    },
  });

  pi.registerCommand("obs-sync", {
    description: "Observal telemetry sync status",
    handler: async (args, ctx) => {
      const sub = args.trim();
      if (sub === "flush") {
        if (!state?.config || !state.sessionFile) {
          ctx.ui.notify("No active session or config", "warning");
          return;
        }
        await pushNewLines(state, { final: false });
        ctx.ui.notify(`Flushed (${state.lineCount} lines total)`, "info");
      } else if (sub === "config") {
        ctx.ui.notify(
          `Config: ${CONFIG_PATH}\nServer: ${state?.config?.server_url ?? "not configured"}`,
          "info",
        );
      } else {
        const synced = state?.lineCount ?? 0;
        const server = state?.config?.server_url ?? "not configured";
        ctx.ui.notify(`Observal: ${synced} lines pushed\nServer: ${server}`, "info");
      }
    },
  });

  // ─── Helpers ─────────────────────────────────────────────────────────────

  function initState(ctx: ExtensionContext, reason: "startup" | "reload" | "new" | "resume" | "fork"): ObservalState {
    const config = loadConfig();
    const sessionFile = ctx.sessionManager.getSessionFile() ?? null;
    const sessionId = ctx.sessionManager.getSessionId();

    let byteOffset = 0;
    let lineCount = 0;

    if (sessionId) {
      const cursor = readCursor(sessionId);
      byteOffset = cursor.offset;
      lineCount = cursor.line_count;
    }

    const header = ctx.sessionManager.getHeader?.() ?? null;
    const started = header && Date.parse(header.timestamp);
    const freshRootStart = Boolean(
      (reason === "startup" || reason === "new") &&
      header?.id === sessionId && !header.parentSession && Number.isFinite(started) &&
      started! <= Date.now() + 10_000 && Date.now() - started! <= 30_000 &&
      lineCount === 0 && !readCursor(sessionId).run_incarnation
    );
    const layerSnapshot = buildPiLayerSnapshot();
    const layerHash = layerSnapshot.hash;

    // Tools Pi runs (the bash tool included) inherit this process's environment,
    // so `observal discover use` can record the exact Pi session it ran in.
    if (sessionId) process.env.OBSERVAL_SESSION_ID = sessionId;
    process.env.OBSERVAL_HARNESS = "pi";

    return { config, sessionFile, sessionId, cwd: ctx.cwd, byteOffset, lineCount, generation: 0,
      layerHash, layerSnapshot, freshRootStart };
  }

  // ─── Capability attribution ───────────────────────────────────────────────

  function isSameOrUnder(candidate: string, root: string): boolean {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
  }

  function firstLineTimestampMs(sessionFile: string): number | null {
    // Pi transcripts open with {"type":"session", "timestamp": ...}. ctime is
    // not used: on Linux it moves with every write.
    try {
      const fd = fs.openSync(sessionFile, "r");
      try {
        const buffer = Buffer.alloc(4096);
        const read = fs.readSync(fd, buffer, 0, buffer.length, 0);
        const first = buffer.toString("utf-8", 0, read).split("\n")[0] ?? "";
        const record = JSON.parse(first);
        const value = record?.timestamp ?? record?.ts ?? record?.created_at;
        const parsed = typeof value === "number" ? (value > 1e11 ? value : value * 1000) : Date.parse(String(value ?? ""));
        return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return null;
    }
  }

  function sessionStartedAtMs(sessionFile: string | null): number {
    if (sessionFile) {
      try {
        const stat = fs.statSync(sessionFile);
        if (stat.birthtimeMs > 0) return stat.birthtimeMs - CAPABILITY_LEAD_MS;
      } catch { }
      const first = firstLineTimestampMs(sessionFile);
      if (first !== null) return first - CAPABILITY_LEAD_MS;
    }
    return Date.now() - CAPABILITY_FALLBACK_MS;
  }

  /** Capability-lock uses that belong to this session, shaped for the ingest payload. Best effort. */
  function capabilitiesForSession(s: ObservalState): Array<Record<string, unknown>> {
    try {
      if (!fs.existsSync(CAPABILITY_LOCK_PATH)) return [];
      const since = sessionStartedAtMs(s.sessionFile);
      const latest = new Map<string, Record<string, unknown>>();
      for (const line of fs.readFileSync(CAPABILITY_LOCK_PATH, "utf-8").split("\n")) {
        if (!line.trim()) continue;
        let use: Record<string, unknown>;
        try { use = JSON.parse(line); } catch { continue; }
        if (typeof use.ts !== "string" || typeof use.kind !== "string") continue;
        const exact = typeof use.session_hint === "string" && use.session_hint === s.sessionId;
        if (!exact) {
          if (typeof use.harness === "string" && use.harness !== "pi") continue;
          if (typeof use.cwd === "string" && use.cwd && s.cwd && !isSameOrUnder(use.cwd, s.cwd)) continue;
          const at = Date.parse(use.ts);
          if (Number.isNaN(at) || at < since) continue;
        }
        const key = (use.identifier as string) || `${use.kind}:${use.component_id ?? use.native_ref ?? ""}`;
        const previous = latest.get(key);
        if (!previous || String(previous.used_at) <= String(use.ts)) {
          latest.set(key, {
            identifier: use.identifier ?? null,
            kind: use.kind,
            component_id: use.component_id ?? null,
            native_ref: use.native_ref ?? null,
            version: use.version ?? null,
            digest: use.digest ?? null,
            mode: use.mode ?? "context",
            source: use.source ?? "unknown",
            used_at: use.ts,
            confidence: exact ? "exact" : s.sessionFile ? "window" : "loose",
          });
        }
      }
      return [...latest.values()]
        .sort((a, b) => String(b.used_at).localeCompare(String(a.used_at)))
        .slice(0, MAX_CAPABILITIES_PER_PUSH);
    } catch {
      return [];
    }
  }

  function loadConfig(): ObservalConfig | null {
    try {
      if (!fs.existsSync(CONFIG_PATH)) return null;
      const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
      const data = JSON.parse(raw);
      const accessToken = data.api_key || data.access_token;
      if (!data.server_url || !accessToken) return null;
      const config: ObservalConfig = {
        server_url: data.server_url,
        access_token: accessToken,
        user_id: data.user_id || undefined,
      };
      // A delegated child (ADR 0002) runs as the agent it was delegated to, whatever agent Pi has selected.
      const delegatedAgent = process.env.OBSERVAL_DELEGATION_TASK_ID ? process.env.OBSERVAL_AGENT_ID : undefined;
      if (delegatedAgent) {
        config.agent_id = delegatedAgent;
        if (process.env.OBSERVAL_AGENT_VERSION) config.agent_version = process.env.OBSERVAL_AGENT_VERSION;
      } else if (data.active_agent?.id) {
        const binding = resolvePiAgentBinding(String(data.active_agent.id), data.active_agent.name, data.active_agent.version);
        config.agent_id = binding.id;
        if (binding.version) config.agent_version = binding.version;
      }
      return config;
    } catch {
      return null;
    }
  }

  function currentRegistryLockfile(): Record<string, any> | null {
    try {
      const config = loadConfig();
      if (!config || !fs.existsSync(LOCKFILE_PATH)) return null;
      const url = new URL(config.server_url);
      url.hash = "";
      url.search = "";
      url.pathname = url.pathname.replace(/\/$/, "");
      const key = url.toString().replace(/\/$/, "");
      const data = JSON.parse(fs.readFileSync(LOCKFILE_PATH, "utf-8"));
      return data.registries?.[key] ?? null;
    } catch {
      return null;
    }
  }

  function resolvePiAgentBinding(agent: string, rawName?: unknown, rawVersion?: unknown): { id: string; name: string; version?: string } {
    const name = typeof rawName === "string" && rawName.trim() ? rawName.trim() : agent;
    const entry = findPiLockfileAgent(agent, name);
    return {
      id: typeof entry?.id === "string" && entry.id.trim() ? entry.id : agent,
      name: typeof entry?.name === "string" && entry.name.trim() ? entry.name : name,
      version: normalizeAgentVersion(entry?.version) ?? normalizeAgentVersion(rawVersion),
    };
  }

  function findPiLockfileAgent(agent: string, name: string): Record<string, any> | null {
    try {
      const agents = currentRegistryLockfile()?.harnesses?.pi?.agents;
      if (!Array.isArray(agents)) return null;
      const keys = new Set([agent, name, safeAgentName(agent), safeAgentName(name)].filter(Boolean));
      return agents.find((item) => keys.has(String(item?.id ?? "")))
        ?? agents.find((item) => keys.has(String(item?.name ?? "")) || keys.has(safeAgentName(String(item?.name ?? ""))))
        ?? null;
    } catch {
      return null;
    }
  }

  function normalizeAgentVersion(version: unknown): string | undefined {
    if (typeof version !== "string") return undefined;
    const trimmed = version.trim();
    return trimmed && trimmed !== "latest" ? trimmed : undefined;
  }

  function safeAgentName(name: string): string {
    return name.replace(/[^a-zA-Z0-9_-]/g, "-");
  }

  function buildPiLayerSnapshot(): LayerSnapshot {
    const piHome = path.join(os.homedir(), ".pi", "agent");
    const files = discoverPiLayerFiles(piHome);
    const manifest: LayerFileEntry[] = [];

    for (const file of files) {
      try {
        const rel = path.relative(piHome, file).split(path.sep).join("/");
        const content = fs.readFileSync(file);
        const entry: LayerFileEntry = {
          path: `user:${rel}`,
          hash: `sha256-${sha256(content)}`,
          size: content.length,
          source: "user",
        };
        // Never transmit user configuration contents: they may include API
        // keys. Hashes preserve change detection without leaking file bytes.
        // A future content-based extractor needs a separately reviewed,
        // allowlisted redaction policy before it can claim coverage.
        manifest.push(entry);
      } catch {
        continue;
      }
    }

    manifest.sort((a, b) => a.path.localeCompare(b.path));
    const hashEntries = manifest.map((entry) => [`pi/${entry.path}`, entry.hash] as [string, string]);
    const layerHash = hashEntries.length === 0 ? "0".repeat(16) : sha256(Buffer.from(pyJsonPairs(hashEntries))).slice(0, 16);

    return {
      hash: layerHash,
      harnesses: { pi: manifest },
      lockfile_hash: computeLockfileHash(),
      // Free-form lockfile names can contain user secrets. Verified identity
      // pins travel only in the independently allowlisted v2 manifest.
      pinned_versions: { agents: [], standalone: [] },
      drift: { is_canonical: true, drifted_files: [] },
    };
  }

  function discoverPiLayerFiles(root: string): string[] {
    if (!fs.existsSync(root)) return [];
    let rootReal: string;
    try {
      rootReal = fs.realpathSync(root);
    } catch {
      return [];
    }
    const found: string[] = [];

    function mayContainPiLayerFile(rel: string): boolean {
      const parts = rel.split("/");
      if (rel === "skills" || rel === "agents" || rel === "sandboxes" || rel.startsWith("sandboxes/")) return true;
      if (parts[0] === "skills") return parts.length === 2;
      if (parts[0] !== "agents") return false;
      if (parts.length === 2) return true;
      if (parts[2] === "sandboxes") return true;
      return parts[2] === "skills" && parts.length <= 4;
    }

    function walk(dir: string): void {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        const rel = path.relative(root, abs).split(path.sep).join("/");
        if (entry.isDirectory()) {
          // Do not descend into unrelated extension/package trees at every
          // session start. Only the file shapes below affect Pi's layer hash.
          if (mayContainPiLayerFile(rel)) walk(abs);
          continue;
        }
        if (!entry.isFile() || !isPiLayerFile(rel)) continue;

        try {
          const stat = fs.statSync(abs);
          if (stat.size > MAX_LAYER_FILE_SIZE) continue;
          const real = fs.realpathSync(abs);
          if (real !== rootReal && !real.startsWith(`${rootReal}${path.sep}`)) continue;
          found.push(abs);
        } catch {
          continue;
        }
      }
    }

    try {
      walk(root);
    } catch {
      return [];
    }

    return found.sort().slice(0, 200);
  }

  function isPiLayerFile(rel: string): boolean {
    return ["AGENTS.md", "SYSTEM.md", "APPEND_SYSTEM.md", "mcp.json", "settings.json"].includes(rel)
      || /^skills\/[^/]+\/SKILL\.md$/.test(rel)
      || rel.startsWith("sandboxes/")
      || /^agents\/[^/]+\/(AGENTS\.md|SYSTEM\.md|APPEND_SYSTEM\.md|mcp\.json)$/.test(rel)
      || /^agents\/[^/]+\/skills\/[^/]+\/SKILL\.md$/.test(rel)
      || /^agents\/[^/]+\/sandboxes\//.test(rel);
  }

  function sha256(content: Buffer): string {
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  function pyJsonPairs(entries: [string, string][]): string {
    return `[${entries.map(([left, right]) => `[${JSON.stringify(left)}, ${JSON.stringify(right)}]`).join(", ")}]`;
  }

  function computeLockfileHash(): string {
    const registry = currentRegistryLockfile();
    return registry ? sha256(Buffer.from(JSON.stringify(registry))).slice(0, 16) : "0".repeat(16);
  }

  function canonicalMcpEntry(value: any): string {
    if (Array.isArray(value)) return `[${value.map(canonicalMcpEntry).join(",")}]`;
    if (value !== null && typeof value === "object") {
      return `{${Object.keys(value).sort().map((key) =>
        `${JSON.stringify(key)}:${canonicalMcpEntry(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  }

  function registeredMcpPins(): Array<{ id: string; version: string; alias: string }> {
    // An explicit adapter config path may replace the global MCP definition.
    // Programmatic in-memory adapter configs cannot be attested by this sender;
    // such SDK integrations must not claim independently verified execution.
    if (process.argv.some((arg) => arg === "--mcp-config" || arg.startsWith("--mcp-config=")) ||
        (typeof pi.getFlag === "function" && pi.getFlag("mcp-config"))) return [];
    if (process.env.PI_CODING_AGENT_DIR &&
        path.resolve(process.env.PI_CODING_AGENT_DIR) !== path.join(os.homedir(), ".pi", "agent")) return [];
    const section = currentRegistryLockfile()?.harnesses?.pi;
    if (!section || typeof section !== "object") return [];
    // A lockfile may also contain Claude/Codex registrations. Only aliases
    // present in the ACTIVE Pi config can qualify a Pi session's v2 identity.
    let active: Record<string, unknown>;
    try {
      const configPath = path.join(os.homedir(), ".pi", "agent", "mcp.json");
      if (fs.statSync(configPath).size > MAX_LAYER_FILE_SIZE) return [];
      const parsed = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      active = parsed?.mcpServers;
      if (!active || typeof active !== "object" || Array.isArray(active)) return [];
    } catch {
      return [];
    }
    // Project MCP files outrank the global Pi config in pi-mcp-adapter. A
    // same-named project entry can otherwise execute unrelated code while
    // the sender claims the global registry pin. Fail closed for that alias,
    // including unreadable/oversized/symlinked project configs.
    const overridden = new Set<string>();
    let directory = process.cwd();
    for (;;) {
      for (const relative of [".mcp.json", path.join(".pi", "mcp.json")]) {
        const candidate = path.join(directory, relative);
        try {
          const stat = fs.lstatSync(candidate);
          if (!stat.isFile() || stat.size > MAX_LAYER_FILE_SIZE) return [];
          const project = JSON.parse(fs.readFileSync(candidate, "utf-8"));
          if (!project || typeof project !== "object" || project.imports || project.plugins ||
              !project.mcpServers ||
              typeof project.mcpServers !== "object" || Array.isArray(project.mcpServers)) return [];
          for (const name of Object.keys(project.mcpServers)) overridden.add(name);
        } catch (error: any) {
          if (error?.code !== "ENOENT") return [];
        }
      }
      const parent = path.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
    const pins: Array<{ id: string; version: string; alias: string }> = [];
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const alias = /^[A-Za-z0-9_-]{1,128}$/;
    const version = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$/;
    // Agent pulls write isolated Pi profiles, not the active global adapter
    // config; their lock entries lack a verified local alias/digest. Never
    // let one unverified profile erase otherwise valid standalone MCP pins.
    for (const pin of section.standalone ?? []) {
      if (pin.type !== "mcp") continue;
      const native = pin.local_name;
      if (typeof pin.id !== "string" || !uuid.test(pin.id) ||
          typeof pin.version !== "string" || !version.test(pin.version) ||
          typeof native !== "string" || !alias.test(native) ||
          typeof pin.config_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(pin.config_sha256) ||
          !Object.hasOwn(active, native) || overridden.has(native) ||
          sha256(Buffer.from(canonicalMcpEntry(active[native]))) !== pin.config_sha256) return [];
      pins.push({ id: pin.id.toLowerCase(), version: pin.version, alias: native });
    }
    const unique = [...new Map(pins.map((pin) => [pin.id, pin])).values()];
    if (unique.length !== pins.length || unique.length > 100 ||
        new Set(unique.map((pin) => pin.alias)).size !== unique.length) return [];
    return unique.sort((a, b) => {
      const left = JSON.stringify([a.id, a.version, a.alias]);
      const right = JSON.stringify([b.id, b.version, b.alias]);
      return left < right ? -1 : left > right ? 1 : 0;
    });
  }

  function loadRegistryHooks(): { hash: string; entries: RegistryHook[] } | null {
    if (process.platform === "win32") return null;
    const file = path.join(os.homedir(), ".pi", "agent", HOOK_FILE);
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.size > MAX_LAYER_FILE_SIZE) return null;
      const bytes = fs.readFileSync(file);
      const profile = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (profile?.schema !== HOOK_SCHEMA || typeof profile.agent !== "string" ||
          !profile.agent || !Array.isArray(profile.hooks) || profile.hooks.length > 64) return null;
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      const version = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$/;
      const alias = /^[A-Za-z0-9_-]{1,128}$/;
      const entries: RegistryHook[] = [];
      for (const item of profile.hooks) {
        if (!item || typeof item !== "object" || !uuid.test(item.id) || !version.test(item.version) ||
            !alias.test(item.name) || !["tool_call", "tool_result"].includes(item.event) ||
            item.type !== "command" || typeof item.command !== "string" || !item.command.trim() ||
            !Number.isInteger(item.timeout) || item.timeout < 1 || item.timeout > 600) return null;
        entries.push({ id: item.id.toLowerCase(), version: item.version, name: item.name,
          event: item.event, command: item.command, timeout: item.timeout,
          binding: sha256(Buffer.from(`${item.event}\0${item.command}`)) });
      }
      if (new Set(entries.map((entry) => entry.id)).size !== entries.length ||
          new Set(entries.map((entry) => entry.name)).size !== entries.length ||
          new Set(entries.map((entry) => entry.binding)).size !== entries.length) return null;
      return { hash: sha256(bytes), entries };
    } catch { return null; }
  }

  function registeredHookPins(): Array<{ id: string; version: string; scope: "user"; alias: string;
    binding_sha256: string }> {
    return (hookRuntime?.entries ?? []).map(({ id, version, name, binding }) =>
      ({ id, version, scope: "user", alias: name, binding_sha256: binding }));
  }

  function registeredSkillPins(s: ObservalState): Array<{
    id: string; version: string; scope: "user" | "project"; alias: string;
    location_sha256: string; content_sha256: string;
  }> {
    const section = currentRegistryLockfile()?.harnesses?.pi;
    if (!section || typeof section !== "object") return [];
    // Isolated agent-profile skills are not active global/project skills.
    // Their lock entries do not prove Pi loaded those files; exclude them
    // without suppressing independently verified standalone skill pins.
    const entries = (section.standalone ?? []).filter((pin: any) => pin.type === "skill");
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const alias = /^[A-Za-z0-9_-]{1,128}$/;
    const version = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,49}$/;
    const result: Array<{ id: string; version: string; scope: "user" | "project"; alias: string;
      location_sha256: string; content_sha256: string }> = [];
    for (const pin of entries) {
      if (typeof pin.id !== "string" || !uuid.test(pin.id) ||
          typeof pin.version !== "string" || !version.test(pin.version) ||
          typeof pin.local_name !== "string" || !alias.test(pin.local_name) ||
          (pin.scope !== "user" && pin.scope !== "project")) return [];
      if (pin.scope === "project" && pin.directory !== s.cwd) continue;
      const root = pin.scope === "user" ? path.join(os.homedir(), ".pi", "agent") : s.cwd;
      const location = path.join(root, pin.scope === "user" ? "skills" : ".pi/skills", pin.local_name, "SKILL.md");
      try {
        // Never follow a symlink to an unrelated file. Content stays local;
        // the server checks its digest against the approved exact version.
        const directory = path.dirname(location);
        if (fs.realpathSync(directory) !== directory || fs.realpathSync(location) !== location) continue;
        const stat = fs.statSync(location);
        if (!stat.isFile() || stat.size > MAX_LAYER_FILE_SIZE) continue;
        const bytes = fs.readFileSync(location);
        result.push({ id: pin.id.toLowerCase(), version: pin.version, scope: pin.scope,
          alias: pin.local_name, location_sha256: sha256(Buffer.from(location)), content_sha256: sha256(bytes) });
      } catch { /* Not an active Pi installation. */ }
    }
    if (result.length > 100 || new Set(result.map((pin) => pin.id)).size !== result.length ||
        new Set(result.map((pin) => pin.alias)).size !== result.length) return [];
    return result.sort((a, b) => {
      const left = JSON.stringify([a.id, a.version, a.scope, a.alias]);
      const right = JSON.stringify([b.id, b.version, b.scope, b.alias]);
      return left < right ? -1 : left > right ? 1 : 0;
    });
  }

  async function uploadVerifiedLayer(config: ObservalConfig, s: ObservalState): Promise<void> {
    const components = registeredMcpPins();
    const skills = registeredSkillPins(s);
    const hooks = registeredHookPins();
    if (!components.length && !skills.length && !hooks.length) return;
    const canonical = skills.length || hooks.length
      ? [...components.map((pin) => ["mcp", pin.id, pin.version, pin.alias]),
          ...skills.map((pin) => ["skill", pin.id, pin.version, pin.scope, pin.alias,
            pin.location_sha256, pin.content_sha256]),
          ...hooks.map((pin) => ["hook", pin.id, pin.version, pin.scope, pin.alias,
            pin.binding_sha256])].sort((a, b) => {
            const left = JSON.stringify(a);
            const right = JSON.stringify(b);
            return left < right ? -1 : left > right ? 1 : 0;
          })
      : components.map((pin) => [pin.id, pin.version, pin.alias]);
    const hash = `${skills.length || hooks.length ? "v3" : "v2"}_${sha256(Buffer.from(JSON.stringify(canonical)))}`;
    const receipt = await postJsonWithTimeout(config, "/api/v1/mobile-evidence/v1/layers",
      JSON.stringify({ harness: "pi", components, ...(skills.length ? { skills } : {}), ...(hooks.length ? { hooks } : {}) }));
    if (receipt?.hash === hash && receipt?.mapped_components === components.length + skills.length + hooks.length) s.layerHash = hash;
  }

  function needsLayerUpload(config: ObservalConfig, hash: string): boolean {
    try {
      if (!config.user_id || !fs.existsSync(LAYER_SNAPSHOT_PATH)) return true;
      const data = JSON.parse(fs.readFileSync(LAYER_SNAPSHOT_PATH, "utf-8"));
      // The CLI's older hash-only cache cannot attest an acknowledgement by
      // this account on this server. Reupload after login/server switches.
      return data.hash !== hash || data.uploaded_to !== crypto.createHash("sha256").update(config.server_url).digest("hex")
        || data.uploaded_by !== config.user_id;
    } catch {
      return true;
    }
  }

  function saveLayerSnapshot(snapshot: LayerSnapshot, config: ObservalConfig): void {
    let temporary: string | undefined;
    try {
      const serialized = JSON.stringify({ ...snapshot,
        uploaded_to: crypto.createHash("sha256").update(config.server_url).digest("hex"),
        uploaded_by: config.user_id }, null, 2);
      if (serialized.length > 5 * 1024 * 1024) return;
      fs.mkdirSync(OBSERVAL_DIR, { recursive: true });
      temporary = `${LAYER_SNAPSHOT_PATH}.${process.pid}.${crypto.randomUUID()}.tmp`;
      fs.writeFileSync(temporary, `${serialized}\n`, { mode: 0o600, flag: "wx" });
      fs.renameSync(temporary, LAYER_SNAPSHOT_PATH);
    } catch {
      if (temporary) { try { fs.unlinkSync(temporary); } catch { /* Nothing to clean. */ } }
    }
  }

  async function uploadLayerSnapshot(config: ObservalConfig, snapshot: LayerSnapshot): Promise<boolean> {
    if (!needsLayerUpload(config, snapshot.hash)) return true;
    const result = await postJsonWithTimeout(config, "/api/v1/layer-snapshots", JSON.stringify(snapshot));
    if (result?.hash !== snapshot.hash) return false;
    saveLayerSnapshot(snapshot, config);
    return true;
  }

  function readCursor(sessionId: string): CursorEntry {
    try {
      if (!fs.existsSync(SYNC_STATE_PATH)) return { offset: 0, line_count: 0, local_valid: false };
      const data = JSON.parse(fs.readFileSync(SYNC_STATE_PATH, "utf-8"));
      const entry = data[sessionId];
      if (!entry || !Number.isInteger(entry.offset) || !Number.isInteger(entry.line_count)
        || entry.offset < 0 || entry.line_count < 0) {
        return { offset: 0, line_count: 0, local_valid: false };
      }
      return { ...entry, local_valid: true };
    } catch {
      return { offset: 0, line_count: 0, local_valid: false };
    }
  }

  function writeCursor(sessionId: string, offset: number, lineCount: number, finalized = false, run?: CursorEntry): boolean {
    try {
      fs.mkdirSync(OBSERVAL_DIR, { recursive: true });
      let data: Record<string, CursorEntry> = {};
      if (fs.existsSync(SYNC_STATE_PATH)) {
        data = JSON.parse(fs.readFileSync(SYNC_STATE_PATH, "utf-8"));
      }
      data[sessionId] = { ...data[sessionId], ...run, offset, line_count: lineCount, finalized, last_pushed_at: Date.now() };
      const temporary = `${SYNC_STATE_PATH}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(temporary, JSON.stringify(data, null, 2), { mode: 0o600 });
      fs.renameSync(temporary, SYNC_STATE_PATH);
      return true;
    } catch {
      return false;
    }
  }

  function ensureRunIdentity(s: ObservalState): void {
    if (!s.sessionFile || s.identityConflict) return;
    try {
      const stat = fs.statSync(s.sessionFile);
      if (!stat.isFile()) return;
      const fd = fs.openSync(s.sessionFile, "r");
      let first: string;
      try {
        const buffer = Buffer.alloc(4096);
        const length = fs.readSync(fd, buffer, 0, buffer.length, 0);
        const end = buffer.indexOf(10, 0);
        if (end < 0 || end >= length) return;
        first = buffer.toString("utf-8", 0, end);
      } finally {
        fs.closeSync(fd);
      }
      const header = JSON.parse(first);
      if (header?.type !== "session" || header?.id !== s.sessionId ||
          typeof header.timestamp !== "string" || !Number.isFinite(Date.parse(header.timestamp)) ||
          !/[Zz]|[+-]\d\d:\d\d$/.test(header.timestamp)) return;
      const hash = sha256(Buffer.from(first));
      const identity = sha256(Buffer.from(JSON.stringify([path.resolve(s.sessionFile), stat.ino, hash])));
      const cursor = readCursor(s.sessionId);
      if ((cursor.source_identity && cursor.source_identity !== identity) ||
          (cursor.line_count > 0 && !cursor.run_incarnation) ||
          (s.runIncarnation && s.runIncarnation !== cursor.run_incarnation)) {
        s.identityConflict = true;
        return;
      }
      const run = cursor.run_incarnation ?? crypto.randomUUID();
      if (cursor.run_header_hash && cursor.run_header_hash !== hash) {
        s.identityConflict = true;
        return;
      }
      const runOrigin = cursor.run_origin ??
        (s.freshRootStart && !header.parentSession ? "pi_session_start_root_v1" : undefined);
      let parent: { id: string; run: string; headerHash: string } | null = null;
      if (typeof header.parentSession === "string" && s.sessionFile) {
        try {
          const parentFile = path.resolve(header.parentSession);
          if (isSameOrUnder(parentFile, path.dirname(s.sessionFile)) && parentFile !== path.resolve(s.sessionFile)) {
            const parentStat = fs.statSync(parentFile);
            const parentFd = fs.openSync(parentFile, "r");
            let parentLine: string;
            try {
              const data = Buffer.alloc(4096);
              const read = fs.readSync(parentFd, data, 0, data.length, 0);
              const end = data.indexOf(10, 0);
              parentLine = end >= 0 && end < read ? data.toString("utf-8", 0, end) : "";
            } finally { fs.closeSync(parentFd); }
            const parentHeader = JSON.parse(parentLine);
            const parentHash = sha256(Buffer.from(parentLine));
            const parentCursor = readCursor(parentHeader.id);
            const sourceIdentity = sha256(Buffer.from(JSON.stringify([parentFile, parentStat.ino, parentHash])));
            if (parentHeader.type === "session" && parentHeader.id !== s.sessionId &&
                typeof parentHeader.id === "string" && parentHeader.id.length <= 256 &&
                parentCursor.run_incarnation && parentCursor.run_header_hash === parentHash &&
                parentCursor.source_identity === sourceIdentity &&
                Date.parse(parentHeader.timestamp) <= Date.parse(header.timestamp)) {
              parent = { id: parentHeader.id, run: parentCursor.run_incarnation, headerHash: parentHash };
            }
          }
        } catch { /* No corroborated local parent: never invent a lineage link. */ }
      }
      if (cursor.parent_session_id !== parent?.id || cursor.parent_run_incarnation !== parent?.run ||
          cursor.parent_header_hash !== parent?.headerHash) {
        if (cursor.run_incarnation) { s.identityConflict = true; return; }
      }
      if (!cursor.run_incarnation && !writeCursor(s.sessionId, cursor.offset, cursor.line_count, false,
            { run_incarnation: run, run_header_hash: hash, run_origin: runOrigin,
              parent_session_id: parent?.id, parent_run_incarnation: parent?.run,
              parent_header_hash: parent?.headerHash, source_identity: identity, offset: 0, line_count: 0 })) return;
      s.runIncarnation = run;
      s.runHeaderHash = hash;
      s.runOrigin = runOrigin;
      s.parentSessionId = parent?.id;
      s.parentRunIncarnation = parent?.run;
      s.parentHeaderHash = parent?.headerHash;
    } catch {
      // Missing/invalid source remains legacy-only. Never invent an incarnation.
    }
  }

  function pendingPath(sessionId: string): string {
    return path.join(OUTBOX_DIR, `${sha256(Buffer.from(sessionId))}.json`);
  }

  function readPending(sessionId: string): PendingBatch | null {
    const file = pendingPath(sessionId);
    if (!fs.existsSync(file)) return null;
    const pending = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (pending?.session_id !== sessionId || !pending?.payload) {
      throw new Error(`invalid Pi outbox entry: ${file}`);
    }
    return pending;
  }

  function outboxBytes(exclude: string): number {
    if (!fs.existsSync(OUTBOX_DIR)) return 0;
    let total = 0;
    for (const name of fs.readdirSync(OUTBOX_DIR)) {
      const file = path.join(OUTBOX_DIR, name);
      if (file === exclude || !name.endsWith(".json")) continue;
      try { total += fs.statSync(file).size; } catch { }
    }
    return total;
  }

  function writePending(pending: PendingBatch): boolean {
    try {
      fs.mkdirSync(OUTBOX_DIR, { recursive: true });
      const file = pendingPath(pending.session_id);
      const serialized = JSON.stringify(pending);
      if (outboxBytes(file) + Buffer.byteLength(serialized) > MAX_OUTBOX_BYTES) return false;
      const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(temporary, serialized, { mode: 0o600 });
      fs.renameSync(temporary, file);
      return true;
    } catch {
      return false;
    }
  }

  function removePending(sessionId: string): void {
    try { fs.unlinkSync(pendingPath(sessionId)); } catch { }
  }

  async function deliverPending(
    config: ObservalConfig,
    pending: PendingBatch,
  ): Promise<"delivered" | "repair" | false> {
    if (pending.destination.replace(/\/$/, "") !== config.server_url.replace(/\/$/, "")) return false;
    if (pending.user_id && pending.user_id !== config.user_id) return false;

    const acknowledgement = await postJsonWithTimeout(
      config,
      "/api/v1/ingest/session",
      JSON.stringify(pending.payload),
      TIMEOUT_MS,
    );
    if (Number.isInteger(acknowledgement?.repair_from_line)) {
      const repairFromLine = Number(acknowledgement.repair_from_line);
      const acknowledgedOffset = Number(acknowledgement.acknowledged_offset || 0);
      if (!writeCursor(pending.session_id, acknowledgedOffset, repairFromLine, false)) return false;
      removePending(pending.session_id);
      return "repair";
    }
    if (!acknowledgementCovers(acknowledgement, pending)) return false;
    if (!writeCursor(pending.session_id, pending.end_offset, pending.end_line + 1, pending.final)) return false;
    removePending(pending.session_id);
    return "delivered";
  }

  function hashSessionFile(sessionFile: string): { hash: string; lineCount: number } {
    const content = fs.readFileSync(sessionFile);
    const hasher = crypto.createHash("sha256");
    let lineCount = 0;
    let start = 0;
    for (let index = 0; index < content.length; index++) {
      if (content[index] !== 10) continue;
      const line = content.subarray(start, index).toString("utf-8").replace(/\r$/, "");
      if (line.trim()) {
        hasher.update(crypto.createHash("sha256").update(line, "utf-8").digest("hex"));
        hasher.update("\n");
        lineCount++;
      }
      start = index + 1;
    }
    return { hash: hasher.digest("hex"), lineCount };
  }

  function checkpointByteOffset(sessionFile: string, lineCount: number, serverOffset: number): number | null {
    try {
      const content = fs.readFileSync(sessionFile);
      if (serverOffset > 0) {
        return serverOffset <= content.length && content[serverOffset - 1] === 10 ? serverOffset : null;
      }
      if (lineCount === 0) return 0;
      let seen = 0;
      let start = 0;
      for (let index = 0; index < content.length; index++) {
        if (content[index] !== 10) continue;
        if (content.subarray(start, index).toString("utf-8").trim()) {
          seen++;
          if (seen === lineCount) return index + 1;
        }
        start = index + 1;
      }
    } catch { }
    return null;
  }

  async function recoverCursorFromServer(
    config: ObservalConfig,
    sessionId: string,
    sessionFile: string,
  ): Promise<CursorEntry | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const url = new URL("/api/v1/ingest/session/checkpoint", config.server_url);
      url.searchParams.set("session_id", sessionId);
      url.searchParams.set("harness", "pi");
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${config.access_token}` },
        signal: controller.signal,
      });
      if (!response.ok) return null;
      const checkpoint = await response.json();
      if (!Number.isInteger(checkpoint?.acknowledged_line)) return null;
      const lineCount = checkpoint.acknowledged_line + 1;
      const byteOffset = checkpointByteOffset(
        sessionFile,
        lineCount,
        Number(checkpoint.acknowledged_offset || 0),
      );
      if (byteOffset === null) return null;
      if (!writeCursor(sessionId, byteOffset, lineCount, false)) return null;
      return readCursor(sessionId);
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function pushNewLines(
    s: ObservalState,
    opts: { final: boolean; repairAttempted?: boolean },
  ): Promise<void> {
    if (!s.config || !s.sessionFile) return;
    ensureRunIdentity(s);
    if (s.identityConflict) return; // Same session ID, different source: no replay or overwrite.

    const gen = ++s.generation;

    try {
      let cursor = readCursor(s.sessionId);
      const storedPending = readPending(s.sessionId);
      if (storedPending) {
        const result = await deliverPending(s.config, storedPending);
        if (!result) return;
        if (s.generation !== gen) return;
        cursor = readCursor(s.sessionId);
      }
      if (!cursor.local_valid) {
        cursor = await recoverCursorFromServer(s.config, s.sessionId, s.sessionFile) ?? cursor;
        if (s.generation !== gen) return;
      }
      s.byteOffset = cursor.offset;
      s.lineCount = cursor.line_count;

      const stat = fs.statSync(s.sessionFile);
      const audit = opts.final ? hashSessionFile(s.sessionFile) : null;
      const newBytes = stat.size - s.byteOffset;
      if (newBytes < 0) return;

      let lines: string[] = [];
      let endByteOffsets: number[] = [];
      let consumedBytes = 0;

      if (newBytes > 0) {
        const buffer = Buffer.alloc(newBytes);
        const fd = fs.openSync(s.sessionFile, "r");
        try {
          fs.readSync(fd, buffer, 0, newBytes, s.byteOffset);
        } finally {
          fs.closeSync(fd);
        }

        if (s.generation !== gen) return;
        const rawLines = buffer.toString("utf-8").split("\n");
        for (let i = 0; i < rawLines.length - 1; i++) {
          const line = rawLines[i]!;
          consumedBytes += Buffer.byteLength(line, "utf-8") + 1;
          if (line.trim()) {
            lines.push(line);
            endByteOffsets.push(s.byteOffset + consumedBytes);
          }
        }
        if (endByteOffsets.length > 0) {
          endByteOffsets[endByteOffsets.length - 1] = s.byteOffset + consumedBytes;
        }
      }

      if (lines.length === 0) {
        if (consumedBytes > 0) {
          s.byteOffset += consumedBytes;
          if (!writeCursor(s.sessionId, s.byteOffset, s.lineCount, false)) return;
        }
        if (!opts.final) return;

        const payload: Record<string, unknown> = {
          session_id: s.sessionId,
          harness: "pi",
          agent_id: s.config.agent_id ?? null,
          agent_version: s.config.agent_version ?? null,
          layer_hash: s.layerHash,
          lines: [],
          end_byte_offsets: [],
          start_offset: s.lineCount,
          hook_event: "SessionShutdown",
          final: true,
          total_line_count: s.lineCount,
          total_offset: s.byteOffset,
          session_hash: audit?.hash,
          hashed_line_count: audit?.lineCount,
        };
        if (s.runIncarnation && s.runHeaderHash) {
          payload.run_incarnation = s.runIncarnation;
          payload.run_header_hash = s.runHeaderHash;
          if (s.runOrigin) payload.run_origin = s.runOrigin;
          if (s.parentSessionId && s.parentRunIncarnation && s.parentHeaderHash) {
            payload.parent_session_id = s.parentSessionId;
            payload.parent_run_incarnation = s.parentRunIncarnation;
            payload.parent_header_hash = s.parentHeaderHash;
          }
        }
        const finalCapabilities = capabilitiesForSession(s);
        if (finalCapabilities.length > 0) payload.capabilities_used = finalCapabilities;
        const pending: PendingBatch = {
          session_id: s.sessionId,
          destination: s.config.server_url,
          user_id: s.config.user_id,
          payload,
          end_line: s.lineCount - 1,
          end_offset: s.byteOffset,
          final: true,
        };
        if (!writePending(pending)) return;
        const result = await deliverPending(s.config, pending);
        if (result === "repair" && !opts.repairAttempted) {
          await pushNewLines(s, { final: true, repairAttempted: true });
        }
        return;
      }

      const initialLineCount = s.lineCount;
      const finalOffset = s.byteOffset + consumedBytes;
      for (let offset = 0; offset < lines.length; offset += MAX_LINES_PER_CHUNK) {
        if (s.generation !== gen) return;
        const chunk = lines.slice(offset, offset + MAX_LINES_PER_CHUNK);
        const chunkEndOffsets = endByteOffsets.slice(offset, offset + MAX_LINES_PER_CHUNK);
        const isLastChunk = offset + MAX_LINES_PER_CHUNK >= lines.length;
        const endLine = initialLineCount + offset + chunk.length - 1;
        const endOffset = chunkEndOffsets[chunkEndOffsets.length - 1]!;
        const payload: Record<string, unknown> = {
          session_id: s.sessionId,
          harness: "pi",
          agent_id: s.config.agent_id ?? null,
          agent_version: s.config.agent_version ?? null,
          layer_hash: s.layerHash,
          lines: chunk,
          end_byte_offsets: chunkEndOffsets,
          start_offset: initialLineCount + offset,
          hook_event: opts.final && isLastChunk ? "SessionShutdown" : "AgentEnd",
          final: opts.final && isLastChunk,
          ...(opts.final && isLastChunk
            ? {
                total_line_count: initialLineCount + lines.length,
                total_offset: finalOffset,
                session_hash: audit?.hash,
                hashed_line_count: audit?.lineCount,
              }
            : {}),
        };
        if (s.runIncarnation && s.runHeaderHash) {
          payload.run_incarnation = s.runIncarnation;
          payload.run_header_hash = s.runHeaderHash;
          if (s.runOrigin) payload.run_origin = s.runOrigin;
          if (s.parentSessionId && s.parentRunIncarnation && s.parentHeaderHash) {
            payload.parent_session_id = s.parentSessionId;
            payload.parent_run_incarnation = s.parentRunIncarnation;
            payload.parent_header_hash = s.parentHeaderHash;
          }
        }
        const chunkCapabilities = capabilitiesForSession(s);
        if (chunkCapabilities.length > 0) payload.capabilities_used = chunkCapabilities;
        const pending: PendingBatch = {
          session_id: s.sessionId,
          destination: s.config.server_url,
          user_id: s.config.user_id,
          payload,
          end_line: endLine,
          end_offset: endOffset,
          final: opts.final && isLastChunk,
        };
        if (!writePending(pending)) return;
        const result = await deliverPending(s.config, pending);
        if (!result) return;
        if (result === "repair") {
          if (!opts.repairAttempted) {
            await pushNewLines(s, { final: opts.final, repairAttempted: true });
          }
          return;
        }
        if (s.generation !== gen) return;
        s.byteOffset = endOffset;
        s.lineCount = endLine + 1;
      }
    } catch {
      // Fail-open
    }
  }

  // A rejected token is refreshed once, as the CLI's session hooks do (observal_cli/sessions/base.py);
  // otherwise an expired hooks token or access token would leave every batch in the outbox.
  async function postJsonWithTimeout(
    config: ObservalConfig,
    urlPath: string,
    body: string,
    timeoutMs = TIMEOUT_MS * 2,
  ): Promise<any | null> {
    const token = config.access_token;
    let response = await postJson(config.server_url, urlPath, body, timeoutMs, token);
    // Another request may already have refreshed the token while this one was in flight.
    if (response?.status === 401 && (config.access_token !== token || (await refreshOnce(config)))) {
      response = await postJson(config.server_url, urlPath, body, timeoutMs, config.access_token);
    }
    return response && response.status >= 200 && response.status < 300 ? response.body : null;
  }

  // Refresh tokens are single-use, so concurrent requests share one refresh.
  let refreshing: Promise<boolean> | null = null;
  function refreshOnce(config: ObservalConfig): Promise<boolean> {
    refreshing ??= refreshAccessToken(config).finally(() => {
      refreshing = null;
    });
    return refreshing;
  }

  async function refreshAccessToken(config: ObservalConfig): Promise<boolean> {
    try {
      const saved = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));
      // Never store a token from one server in a config that now points at another.
      if (!saved.refresh_token || saved.server_url !== config.server_url) return false;
      const response = await postJson(
        config.server_url,
        "/api/v1/auth/token/refresh",
        JSON.stringify({ refresh_token: saved.refresh_token }),
        TIMEOUT_MS,
      );
      const accessToken = response?.status === 200 ? response.body?.access_token : undefined;
      if (typeof accessToken !== "string" || !accessToken) return false;
      const current = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));
      // The server just rejected the hooks token: keep it and every later batch would be refused too.
      if (current.api_key && current.api_key === config.access_token) delete current.api_key;
      current.access_token = accessToken;
      if (response.body.refresh_token) current.refresh_token = response.body.refresh_token;
      const temporary = `${CONFIG_PATH}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(temporary, JSON.stringify(current, null, 2), { mode: 0o600 });
      fs.renameSync(temporary, CONFIG_PATH);
      config.access_token = accessToken;
      return true;
    } catch {
      return false;
    }
  }

  function postJson(
    serverUrl: string,
    urlPath: string,
    body: string,
    timeoutMs: number,
    token?: string,
  ): Promise<{ status: number; body: any } | null> {
    return new Promise((resolve) => {
      try {
        const url = new URL(urlPath, serverUrl);
        const mod = url.protocol === "https:" ? https : http;
        const timer = setTimeout(() => {
          req.destroy();
          resolve(null);
        }, timeoutMs);

        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "Content-Length": String(Buffer.byteLength(body)),
        };
        if (token) headers.Authorization = `Bearer ${token}`;
        const req = mod.request(url, { method: "POST", headers }, (res) => {
          clearTimeout(timer);
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            let parsed: any = null;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
            } catch {
              parsed = null;
            }
            resolve({ status: res.statusCode ?? 0, body: parsed });
          });
        });

        req.on("error", () => {
          clearTimeout(timer);
          resolve(null);
        });

        req.write(body);
        req.end();
      } catch {
        resolve(null);
      }
    });
  }


  async function drainStoredOutbox(config: ObservalConfig): Promise<void> {
    if (!fs.existsSync(OUTBOX_DIR)) return;
    for (const name of fs.readdirSync(OUTBOX_DIR)) {
      if (!name.endsWith(".json")) continue;
      try {
        const pending = JSON.parse(fs.readFileSync(path.join(OUTBOX_DIR, name), "utf-8"));
        if (!pending?.session_id || !pending?.payload) continue;
        await deliverPending(config, pending);
      } catch {
        // Keep corrupt or unreachable entries for manual recovery.
      }
    }
  }

  async function recoverStaleSessions(s: ObservalState, ctx: ExtensionContext): Promise<void> {
    try {
      if (!s.config) return;
      await drainStoredOutbox(s.config);
      if (!fs.existsSync(SYNC_STATE_PATH)) return;
      const data: Record<string, CursorEntry> = JSON.parse(
        fs.readFileSync(SYNC_STATE_PATH, "utf-8"),
      );

      const sessionsDir = (ctx.sessionManager as any).getSessionDir?.()
        ?? path.join(os.homedir(), ".pi", "agent", "sessions");
      const projectKey = ctx.cwd.replace(/\//g, "-");
      const fullDir = path.join(sessionsDir, `-${projectKey}-`);
      let recovered = 0;
      const now = Date.now();

      for (const [sessionId, storedEntry] of Object.entries(data)) {
        if (sessionId === s.sessionId || recovered >= RECOVERY_MAX_SESSIONS) continue;
        const entry = storedEntry;
        if (entry.finalized) continue;
        if (!fs.existsSync(fullDir)) continue;

        const files = fs.readdirSync(fullDir).filter((f) => f.includes(sessionId));
        if (files.length === 0) continue;
        const filePath = path.join(fullDir, files[0]!);
        if (!fs.existsSync(filePath)) continue;
        const fileStat = fs.statSync(filePath);
        if (now - fileStat.mtimeMs > RECOVERY_MAX_AGE_MS) continue;

        const recoveryState: ObservalState = {
          ...s,
          sessionFile: filePath,
          sessionId,
          byteOffset: entry.offset,
          lineCount: entry.line_count,
          generation: 0,
          freshRootStart: false,
        };
        await pushNewLines(recoveryState, { final: true });
        if (readCursor(sessionId).finalized) recovered++;
      }

      pruneSyncState();
    } catch {
      // Fail-open
    }
  }

  function pruneSyncState(): void {
    try {
      if (!fs.existsSync(SYNC_STATE_PATH)) return;
      const data: Record<string, CursorEntry> = JSON.parse(
        fs.readFileSync(SYNC_STATE_PATH, "utf-8"),
      );
      const entries = Object.entries(data);
      if (entries.length <= 50) return;

      const required = entries.filter(([, value]) => !value.finalized);
      const recentFinalized = entries
        .filter(([, value]) => value.finalized)
        .sort((a, b) => (b[1].last_pushed_at ?? 0) - (a[1].last_pushed_at ?? 0))
        .slice(0, Math.max(0, 50 - required.length));
      const pruned: Record<string, CursorEntry> = {};
      for (const [key, value] of [...required, ...recentFinalized]) {
        pruned[key] = value;
      }
      const temporary = `${SYNC_STATE_PATH}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(temporary, JSON.stringify(pruned, null, 2), { mode: 0o600 });
      fs.renameSync(temporary, SYNC_STATE_PATH);
    } catch {
      // Fail-open
    }
  }
}
