#!/usr/bin/env node
import { statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, parse, resolve } from "node:path";
import { nowIso } from "../util/clock.js";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";
import { buildInventory, inventoryOfPath } from "../lanes/inventory.js";
import { detectApp, recoveryLane } from "../lanes/recovery.js";
import { buildExposureReport } from "../engine/exposure-report.js";
import { collectPlatformFacts } from "../lanes/platform.js";
import { collectAidsFacts } from "../lanes/aids.js";
import { loadManifest } from "../util/io.js";
import type { Inventory } from "../lanes/types.js";

/**
 * Anti-REA MCP server (v0.8): a hand-rolled, ZERO-dependency JSON-RPC 2.0 server over stdio that exposes
 * the exposure capability to agents, mirroring REA's own agent setup. Newline-delimited messages; stdout
 * carries only protocol messages, logs go to stderr. Strictly read-only: it inspects release bytes, never
 * writes, never executes what it reads. Tools: expose_release, inventory, inspect, analyze_artifact.
 *
 * Register it with, for example: `claude mcp add anti-rea -- node <path>/build/src/mcp/server.js`
 * (`anti-rea mcp-config` prints ready-made snippets).
 */

const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;

interface RpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: unknown;
  params?: Record<string, unknown>;
}

const log = (s: string) => process.stderr.write(`[anti-rea-mcp] ${s}\n`);

/**
 * Paths come from an agent. The inventory walk is unbounded by design (every shipped byte counts), so
 * refuse targets that are plainly not a release: the filesystem root and the home directory itself.
 */
function safeTarget(p: string): string {
  const abs = resolve(p);
  if (abs === parse(abs).root || abs === resolve(homedir())) throw new Error(`refusing to inspect ${abs}: point at a build output (an app, installer or dist directory), not a whole filesystem or home directory`);
  return abs;
}

function inventoryFromArgs(args: Record<string, unknown>): { inv: Inventory; app: { name: string; version: string } } {
  if (typeof args.manifest === "string") {
    const m = loadManifest(args.manifest);
    return { inv: buildInventory(m.value, dirname(resolve(m.path))), app: m.value.application };
  }
  if (typeof args.path === "string") {
    const r = inventoryOfPath(safeTarget(args.path));
    return { inv: r.inventory, app: detectApp(r.inventory, r.label) };
  }
  throw new Error("provide `path` or `manifest`");
}

const TARGET = {
  path: { type: "string", description: "A .app, .apk/.ipa/.exe, a build directory or a single file to inspect." },
  manifest: { type: "string", description: "Alternatively, an Anti-REA manifest whose release closure to inspect." },
};

const TOOLS = [
  {
    name: "expose_release",
    description:
      "Advisory reverse-engineering exposure report for a release: what a REA-class tool would recover and the toolchain settings that reduce it. Read-only; trips no gate. Returns the exposure report (schema anti-rea/exposure/v1). Third-party findings are summarised as counts unless includeThirdParty is true.",
    inputSchema: {
      type: "object",
      properties: { ...TARGET, includeThirdParty: { type: "boolean", description: "Also list each third-party/vendored finding (default false: counts only)." } },
    },
  },
  { name: "inventory", description: "List the release closure (files plus nested container entries) with sha256 and the release id. Read-only.", inputSchema: { type: "object", properties: TARGET } },
  {
    name: "inspect",
    description: "Platform facts (code signing, bundle seals, Electron fuses, PE Authenticode) and reverse-engineering aids (native debug info, debug files, sources, Electron leads). Read-only.",
    inputSchema: { type: "object", properties: TARGET },
  },
  {
    name: "analyze_artifact",
    description: "Run the exposure analyzers over ONE file (an .apk, .ipa or archive counts as one file and is expanded) and return what a REA-class tool would recover from it. Read-only.",
    inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to one file." } }, required: ["path"] },
  },
];

type ToolResult = { content: { type: "text"; text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };

/** A one-line summary plus the JSON itself as text, for clients that predate structuredContent (MCP < 2025-06-18). */
function result(summary: string, data: Record<string, unknown>): ToolResult {
  return { content: [{ type: "text", text: summary }, { type: "text", text: JSON.stringify(data) }], structuredContent: data };
}

function handleToolCall(name: string, args: Record<string, unknown>): ToolResult {
  switch (name) {
    case "expose_release": {
      const { inv, app } = inventoryFromArgs(args);
      const lane = recoveryLane(inv, nowIso(), { app });
      const report = buildExposureReport(lane, lane.profile);
      const data = args.includeThirdParty === true ? report : { ...report, findings: report.findings.filter((f) => f.origin === "owner") };
      const s = report.summary;
      return result(`${report.product.name} ${report.product.version}: highest exposure ${s.maxGrade ?? "none"} (owner ${s.ownerMaxGrade ?? "none"}); ${s.owner} owner, ${s.thirdParty} third-party finding(s); ${report.checklist.length} checklist action(s).`, data as unknown as Record<string, unknown>);
    }
    case "inventory": {
      const { inv } = inventoryFromArgs(args);
      const items = inv.items.map((i) => ({ ...i.ref, kind: i.kind, supported: i.supported, unsupportedReason: i.unsupportedReason }));
      return result(`release ${inv.releaseId.slice(0, 16)}… — ${items.length} artifact(s)`, { releaseId: inv.releaseId, items, notes: inv.notes });
    }
    case "inspect": {
      const { inv } = inventoryFromArgs(args);
      const platform = collectPlatformFacts(inv);
      const aids = collectAidsFacts(inv, { native: {}, debugFiles: {}, sources: {}, electron: {} });
      // Electron facts carry the whole file text for line numbers; never send that.
      const electron = aids.electron.map(({ text: _t, ...e }) => e);
      return result(`${platform.machO.length} Mach-O, ${platform.pe.length} PE, ${aids.native.length} native, ${aids.debugFiles.length} debug file(s), ${aids.sources.length} source file(s)`, { platform, aids: { ...aids, electron } });
    }
    case "analyze_artifact": {
      if (typeof args.path !== "string") throw new Error("`path` is required");
      const abs = safeTarget(args.path);
      if (!statSync(abs).isFile()) throw new Error(`${abs} is not a file; use expose_release for a directory`);
      const r = inventoryOfPath(abs);
      const lane = recoveryLane(r.inventory, nowIso(), { app: detectApp(r.inventory, r.label) });
      return result(`${lane.findings.length} finding(s) for ${r.label}`, { profile: { platforms: lane.profile.platforms, frameworks: lane.profile.frameworks, languages: lane.profile.languages }, findings: lane.findings, opaque: lane.opaque });
    }
    default:
      throw new Error(`unknown tool "${name}"`);
  }
}

function dispatch(req: RpcRequest): object | null {
  const isNotification = !Object.prototype.hasOwnProperty.call(req, "id");
  const reply = (r: unknown) => ({ jsonrpc: "2.0" as const, id: req.id ?? null, result: r });
  const fail = (code: number, message: string) => ({ jsonrpc: "2.0" as const, id: req.id ?? null, error: { code, message } });
  if (typeof req !== "object" || req === null || typeof req.method !== "string") return isNotification ? null : fail(-32600, "invalid request");
  switch (req.method) {
    case "initialize": {
      const asked = req.params?.protocolVersion;
      const version = typeof asked === "string" && (PROTOCOL_VERSIONS as readonly string[]).includes(asked) ? asked : PROTOCOL_VERSIONS[0];
      return reply({ protocolVersion: version, capabilities: { tools: { listChanged: false } }, serverInfo: { name: TOOL_NAME, version: TOOL_VERSION } });
    }
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS });
    case "tools/call": {
      const name = req.params?.name;
      const args = req.params?.arguments;
      try {
        if (typeof name !== "string") throw new Error("`name` is required");
        return reply(handleToolCall(name, args && typeof args === "object" ? (args as Record<string, unknown>) : {}));
      } catch (e) {
        // Tool failures are reported inside the result with isError, per MCP, not as protocol errors.
        return reply({ content: [{ type: "text", text: `error: ${(e as Error).message}` }], isError: true });
      }
    }
    default:
      // Notifications (no id) never get a response, known or not.
      return isNotification ? null : fail(-32601, `method not found: ${req.method}`);
  }
}

function handleLine(line: string): string | null {
  let msg: unknown;
  try {
    msg = JSON.parse(line);
  } catch {
    return JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
  }
  const one = (m: unknown) => {
    try {
      return dispatch(m as RpcRequest);
    } catch (e) {
      return { jsonrpc: "2.0", id: (m as RpcRequest)?.id ?? null, error: { code: -32603, message: (e as Error).message } };
    }
  };
  if (Array.isArray(msg)) {
    // JSON-RPC batch (MCP 2025-03-26): reply with the non-notification responses, or nothing.
    if (msg.length === 0) return JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "empty batch" } });
    const out = msg.map(one).filter((r): r is object => r !== null);
    return out.length ? JSON.stringify(out) : null;
  }
  const r = one(msg);
  return r ? JSON.stringify(r) : null;
}

function main(): void {
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    for (let nl = buffer.indexOf("\n"); nl !== -1; nl = buffer.indexOf("\n")) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      const out = handleLine(line);
      if (out) process.stdout.write(out + "\n");
    }
  });
  process.stdin.on("end", () => process.exit(0));
  log(`ready (${TOOL_NAME} ${TOOL_VERSION}); protocol ${PROTOCOL_VERSIONS.join(", ")}`);
}

main();
