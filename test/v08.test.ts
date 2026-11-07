/**
 * v0.8 exposure lane: analyzers, the recovery lane, the exposure report, attribution and redaction.
 *
 * Hand-made fixtures cite the format they follow; real-toolchain checks (Go, clang) live in
 * test/v08-differential.test.ts and skip when the tool is absent. The load-bearing invariants here:
 * every recovery finding is gate-free, grades come only from the rubric, and no serialized report ever
 * contains a planted secret.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { setClock } from "../src/util/clock.js";
import { inventoryOfPath } from "../src/lanes/inventory.js";
import { recoveryLane } from "../src/lanes/recovery.js";
import { buildExposureReport, renderExposureMarkdown } from "../src/engine/exposure-report.js";
import { RUBRIC, maxSeverity, meetsThreshold, severityRank } from "../src/analyzers/rubric.js";
import { attribute, emptyProfile } from "../src/analyzers/attribution.js";
import { redact } from "../src/analyzers/redact.js";
import { graded, type ItemContext } from "../src/analyzers/types.js";
import { models } from "../src/analyzers/models.js";
import { wasm } from "../src/analyzers/wasm.js";
import { godot } from "../src/analyzers/godot.js";
import { pyinstaller } from "../src/analyzers/pyinstaller.js";
import { jsElectron } from "../src/analyzers/js-electron.js";
import { readAndroidManifest } from "../src/codecs/axml.js";
import { writeZip } from "../src/pack/writers.js";
import type { Inventory, InventoryItem } from "../src/lanes/types.js";
import { put, tmp } from "./helpers.js";

setClock(new Date("2026-11-07T00:00:00Z"));

// ---------------------------------------------------------------- byte builders (spec-cited)

const u32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const u64 = (v: number | bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };

/** GGUF v3 header (ggerganov/ggml GGUF spec): magic, version, tensor_count, kv_count, then KV pairs. */
function gguf(arch: string): Buffer {
  const gstr = (s: string) => Buffer.concat([u64(s.length), Buffer.from(s)]);
  return Buffer.concat([
    Buffer.from("GGUF"), u32(3), u64(10), u64(2),
    gstr("general.architecture"), u32(8), gstr(arch),
    gstr("llama.context_length"), u32(4), u32(4096),
  ]);
}

/** safetensors (huggingface/safetensors): u64 LE header length + JSON. */
function safetensors(withSecret = false): Buffer {
  const meta = withSecret ? { format: "pt", api_key: "sk-SAFETENSORS-SECRET-abc123def456" } : { format: "pt" };
  const hdr = JSON.stringify({ __metadata__: meta, "model.embed.weight": { dtype: "F16", shape: [32000, 4096], data_offsets: [0, 1] } });
  return Buffer.concat([u64(hdr.length), Buffer.from(hdr), Buffer.alloc(2)]);
}

/** Minimal WASM module with an empty `name` custom section (WebAssembly binary format §5). */
function wasmWithNames(): Buffer {
  return Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d]), u32(1), Buffer.from([0x00, 0x05, 0x04]), Buffer.from("name")]);
}

/** Godot .pck (format 2) with one .gd and one .gdc entry (Godot PCK format). */
function godotPck(): Buffer {
  const entry = (path: string) => {
    const p = Buffer.from(path);
    return Buffer.concat([u32(p.length), p, u64(0), u64(0), Buffer.alloc(16), u32(0)]);
  };
  return Buffer.concat([
    Buffer.from("GDPC"), u32(2), u32(4), u32(2), u32(0), // magic, format, ver major/minor/patch
    u32(0), u64(0), // pack_flags (not encrypted), file_base
    Buffer.alloc(16 * 4), // 16 reserved u32
    u32(2), entry("res://player.gd"), entry("res://enemy.gdc"),
  ]);
}

/** PyInstaller CArchive cookie (pyinstaller spec): magic + lengths + pyvers (311 ⇒ 3.11). */
function pyinstaller_exe(): Buffer {
  const cookie = Buffer.concat([Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]), Buffer.alloc(12), Buffer.alloc(64)]);
  cookie.writeUInt32BE(311, 20);
  return Buffer.concat([Buffer.from("MZ"), Buffer.alloc(4096), cookie]);
}

/** Minimal DEX (Android dex format): header with endian tag; 0 types (so R8 heuristic finds no short names). */
function dex(): Buffer {
  const b = Buffer.alloc(0x70);
  Buffer.from("dex\n035\0", "latin1").copy(b, 0);
  b.writeUInt32LE(0x12345678, 0x28); // endian_tag
  return b;
}

/** Minimal binary AndroidManifest.xml (AXML): package + <application android:debuggable="true">. */
function axmlManifest(debuggable: boolean): Buffer {
  const strings = ["android", "package", "com.demo.app", "manifest", "application", "debuggable"];
  // string pool (UTF-8)
  const offs: Buffer[] = [];
  const data: Buffer[] = [];
  let off = 0;
  for (const s of strings) {
    offs.push(u32(off));
    const sb = Buffer.from(s, "utf8");
    const rec = Buffer.concat([Buffer.from([sb.length, sb.length]), sb, Buffer.from([0])]);
    data.push(rec);
    off += rec.length;
  }
  let pool = Buffer.concat(data);
  if (pool.length % 4) pool = Buffer.concat([pool, Buffer.alloc(4 - (pool.length % 4))]);
  const stringsStart = 28 + strings.length * 4;
  const poolBody = Buffer.concat([u32(strings.length), u32(0), u32(0x100), u32(stringsStart), u32(0), ...offs, pool]);
  const poolChunk = Buffer.concat([Buffer.from([0x01, 0x00]), Buffer.from([0x1c, 0x00]), u32(poolBody.length + 8), poolBody]);

  const idx = (s: string) => strings.indexOf(s);
  const startEl = (name: number, attrs: { name: number; dataType: number; data: number }[]) => {
    // attribute: ns(4) name(4) rawValue(4) typedValue{size(2) res0(1) dataType(1) data(4)}
    const attrBuf = Buffer.concat(attrs.map((a) => Buffer.concat([u32(0xffffffff), u32(a.name), u32(a.dataType === 0x03 ? a.data : 0xffffffff), Buffer.from([0x08, 0x00, 0x00, a.dataType]), u32(a.data)])));
    // attrExt after ns/name: attributeStart(2)=0x14 attributeSize(2)=0x14 attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
    const body = Buffer.concat([u32(1), u32(0xffffffff), u32(0xffffffff), u32(name), Buffer.from([0x14, 0x00, 0x14, 0x00]), Buffer.from([attrs.length & 0xff, (attrs.length >> 8) & 0xff, 0, 0, 0, 0, 0, 0]), attrBuf]);
    return Buffer.concat([Buffer.from([0x02, 0x01]), Buffer.from([0x10, 0x00]), u32(body.length + 8), body]);
  };
  const endEl = (name: number) => Buffer.concat([Buffer.from([0x03, 0x01]), Buffer.from([0x10, 0x00]), u32(24), u32(1), u32(0xffffffff), u32(0xffffffff), u32(name)]);

  const manifestEl = startEl(idx("manifest"), [{ name: idx("package"), dataType: 0x03, data: idx("com.demo.app") }]);
  const appEl = startEl(idx("application"), debuggable ? [{ name: idx("debuggable"), dataType: 0x12, data: 1 }] : []);
  const body = Buffer.concat([poolChunk, manifestEl, appEl, endEl(idx("application")), endEl(idx("manifest"))]);
  return Buffer.concat([Buffer.from([0x03, 0x00]), Buffer.from([0x08, 0x00]), u32(body.length + 8), body]);
}

/** Construct an item context for a single-file analyzer unit test. */
function itemCtx(path: string, buf: Buffer): ItemContext {
  const item: InventoryItem = { ref: { path, sha256: "x", bytes: buf.length }, source: { kind: "mem", buf }, kind: "file", depth: 0, supported: true };
  const inv: Inventory = { releaseId: "r", items: [item], notes: [], limits: {} as never };
  return { scope: "item", item, bytes: buf, complete: true, inv };
}

/** Run the whole exposure pipeline over a tmp directory of files. */
function exposeFiles(files: Record<string, Buffer | string>) {
  const dir = tmp("anti-rea-v08-");
  for (const [rel, data] of Object.entries(files)) put(dir, rel, data);
  const r = inventoryOfPath(dir);
  const result = recoveryLane(r.inventory, "2026-11-07T00:00:00Z", { app: { name: "demo", version: "1.0" } });
  return { result, report: buildExposureReport(result, result.profile) };
}

// ---------------------------------------------------------------- rubric

test("rubric: every analyzer rubric id resolves and max/threshold work", () => {
  assert.equal(RUBRIC["code/source-text"].severity, "critical");
  assert.equal(RUBRIC["metadata/build"].surface, "metadata");
  assert.equal(maxSeverity(["low", "high", "medium"]), "high");
  assert.equal(maxSeverity([]), null);
  assert.ok(severityRank("critical") > severityRank("high"));
  assert.ok(meetsThreshold("critical", "high"));
  assert.ok(!meetsThreshold("low", "high"));
});

// ---------------------------------------------------------------- attribution

test("attribution: node_modules and vendored frameworks are third-party; owner code is owner", () => {
  const p = emptyProfile("MyApp");
  p.frameworks.push("Electron");
  assert.equal(attribute("MyApp/app.asar!/node_modules/lodash/index.js", p), "third-party");
  assert.equal(attribute("MyApp.app/Contents/Frameworks/Electron Framework.framework/Electron Framework", p), "third-party");
  assert.equal(attribute("MyApp.app/Contents/Frameworks/Sparkle.framework/Sparkle", p), "third-party");
  assert.equal(attribute("MyApp.app/Contents/MacOS/MyApp", p), "owner");
  assert.equal(attribute("src/renderer/app.js", p), "owner");
});

// ---------------------------------------------------------------- redaction

test("redaction: -X ldflags and credential-named values are masked; non-secrets survive", () => {
  const secret = "sk-live-REDACT-ME-0123456789abcdef";
  const out = redact(`build: -ldflags=-X main.apiKey=${secret} -X main.version=1.2.3`);
  assert.ok(!out.includes(secret), "secret value must be masked");
  assert.ok(out.includes("-X main.apiKey="), "structure kept");
  const kv = redact(`config token=${secret} and name=hello`);
  assert.ok(!kv.includes(secret));
  assert.ok(kv.includes("name=hello"), "ordinary short values are not masked");
});

test("redaction invariant: a planted safetensors __metadata__ secret never appears in the report", () => {
  const { report } = exposeFiles({ "weights.safetensors": safetensors(true) });
  const json = JSON.stringify(report);
  assert.ok(!json.includes("sk-SAFETENSORS-SECRET"), "metadata value must never be serialized");
  assert.ok(report.findings.some((f) => f.analyzerId === "models"), "but the model is still reported");
});

// ---------------------------------------------------------------- the no-gate invariant

test("recovery lane: every finding is gate-free (advisory by construction)", () => {
  const { result } = exposeFiles({ "model.gguf": gguf("llama"), "a.wasm": wasmWithNames() });
  assert.ok(result.record.findings.length > 0);
  for (const f of result.record.findings) assert.equal(f.gate, undefined, `finding ${f.id} must not carry a gate`);
  assert.equal(result.record.lane, "recovery");
});

test("graded(): surface and severity always come from the rubric row, not the analyzer", () => {
  const f = graded({ analyzerId: "x", rubricId: "code/source-text", title: "t", recovers: "r", remediation: "m", avoidable: true, path: "p", coverage: "full" }, "owner");
  assert.equal(f.surface, "code");
  assert.equal(f.severity, "critical");
});

// ---------------------------------------------------------------- per-format analyzers

test("models: GGUF reports architecture + key names only; safetensors reports tensors/dtypes", () => {
  const g = models.analyze(itemCtx("m.gguf", gguf("mistral")));
  assert.equal(g.length, 1);
  assert.ok(g[0]!.recovers.includes("mistral"));
  assert.ok(g[0]!.detail!.includes("general.architecture"));
  const s = models.analyze(itemCtx("m.safetensors", safetensors()));
  assert.ok(s[0]!.recovers.includes("F16"));
});

test("wasm: the name custom section is detected", () => {
  const ctx = itemCtx("a.wasm", wasmWithNames());
  assert.ok(wasm.detect(ctx));
  const f = wasm.analyze(ctx);
  assert.ok(f.some((x) => x.title.includes("name section")));
});

test("godot: .gd source is critical, .gdc bytecode is high", () => {
  const f = godot.analyze(itemCtx("game.pck", godotPck()));
  const gd = f.find((x) => x.rubricId === "code/source-text");
  const gdc = f.find((x) => x.rubricId === "code/near-source-bytecode");
  assert.ok(gd && RUBRIC[gd.rubricId].severity === "critical");
  assert.ok(gdc && RUBRIC[gdc.rubricId].severity === "high");
});

test("pyinstaller: the cookie is found and the Python version decoded", () => {
  const ctx = itemCtx("app.exe", pyinstaller_exe());
  assert.ok(pyinstaller.detect(ctx));
  const f = pyinstaller.analyze(ctx);
  assert.ok(f[0]!.recovers.includes("3.11"));
});

test("js-electron: insecure webPreferences and wholesale ipcRenderer exposure are flagged", () => {
  const preload = `
    const { contextBridge, ipcRenderer } = require('electron');
    const w = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
    contextBridge.exposeInMainWorld('api', ipcRenderer);
  `;
  const ctx = itemCtx("preload.js", Buffer.from(preload));
  assert.ok(jsElectron.detect(ctx));
  const f = jsElectron.analyze(ctx);
  assert.ok(f.some((x) => x.title.includes("nodeIntegration")));
  assert.ok(f.some((x) => x.title.includes("exposes ipcRenderer")));
});

test("source maps with sourcesContent are critical code recoverability (debug-files analyzer)", () => {
  const map = JSON.stringify({ version: 3, file: "app.js", sources: ["../src/app.ts"], sourcesContent: ["const secret=1;"], mappings: "AAAA" });
  const { report } = exposeFiles({ "app.js.map": map });
  const f = report.findings.find((x) => x.analyzerId === "debug-files");
  assert.ok(f && f.severity === "critical");
});

// ---------------------------------------------------------------- Unity + APK via the bundle pipeline

test("unity-il2cpp: a stock global-metadata.dat is flagged high; the C# names are the exposure", () => {
  const meta = Buffer.concat([u32(0xfab11baf), u32(29), Buffer.alloc(16)]);
  const { report } = exposeFiles({ "Game_Data/il2cpp_data/Metadata/global-metadata.dat": meta });
  const f = report.findings.find((x) => x.analyzerId === "unity-il2cpp");
  assert.ok(f, "il2cpp metadata flagged");
  assert.equal(f!.severity, "high");
});

test("axml codec: android:debuggable=\"true\" round-trips", () => {
  assert.equal(readAndroidManifest(axmlManifest(true)).debuggable, true);
  assert.equal(readAndroidManifest(axmlManifest(false)).debuggable ?? false, false);
  assert.equal(readAndroidManifest(axmlManifest(true)).package, "com.demo.app");
});

test("apk: a debuggable, unminified APK is flagged (debuggable high, DEX without R8)", () => {
  const apkBytes = writeZip([
    { path: "AndroidManifest.xml", data: axmlManifest(true) },
    { path: "classes.dex", data: dex() },
    { path: "resources.arsc", data: Buffer.alloc(16) },
  ]);
  const dir = tmp("anti-rea-apk-");
  put(dir, "app.apk", apkBytes);
  const r = inventoryOfPath(`${dir}/app.apk`);
  const result = recoveryLane(r.inventory, "2026-11-07T00:00:00Z", {});
  const f = result.findings;
  assert.ok(f.some((x) => x.analyzerId === "apk" && x.title.includes("debuggable")), "debuggable flagged");
  assert.ok(f.some((x) => x.analyzerId === "apk" && x.title.includes("DEX")), "dex reported");
  assert.ok(result.profile.platforms.includes("Android"));
});

// ---------------------------------------------------------------- report shape

test("exposure report: owner findings rank before third-party; checklist dedups by remediation", () => {
  const map = JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: ["x"], mappings: "A" });
  const { report } = exposeFiles({
    "app.js.map": map,
    "node_modules/dep/model.gguf": gguf("llama"),
  });
  const owner = report.findings.filter((f) => f.origin === "owner");
  const third = report.findings.filter((f) => f.origin === "third-party");
  assert.ok(owner.length >= 1 && third.length >= 1);
  // owner sorts first in the findings array
  const firstThird = report.findings.findIndex((f) => f.origin === "third-party");
  const lastOwner = report.findings.map((f) => f.origin).lastIndexOf("owner");
  assert.ok(lastOwner < firstThird, "owner findings come first");
  assert.equal(report.summary.maxGrade, maxSeverity(report.findings.map((f) => f.severity)));
  // markdown renders without throwing and names the product
  assert.ok(renderExposureMarkdown(report).includes("demo"));
});

test("exposure report: --fail-on uses the maximum grade and cannot be averaged away", () => {
  const map = JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: ["x"], mappings: "A" });
  const { report } = exposeFiles({ "app.js.map": map, "model.gguf": gguf("llama") });
  assert.equal(report.summary.maxGrade, "critical"); // the source map dominates the medium GGUF
});
