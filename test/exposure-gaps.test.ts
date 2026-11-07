/**
 * Exposure gaps closed before the v7 pre-registration (found by code review, not by benchmark data):
 * - PE images: embedded DWARF (`.debug_*` / Go's `.zdebug_*`, long COFF section names) and the COFF
 *   symbol table were not reported;
 * - inline (`data:`) source maps inside shipped scripts were not reported by `expose`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readPe } from "../src/codecs/pe.js";
import { nativePe } from "../src/analyzers/native-pe.js";
import { debugFiles, inlineSourceMaps } from "../src/analyzers/debug-files.js";
import type { ItemContext } from "../src/analyzers/types.js";
import type { Inventory, InventoryItem } from "../src/lanes/types.js";
import { tmp } from "./helpers.js";

function itemCtx(path: string, buf: Buffer): ItemContext {
  const item: InventoryItem = { ref: { path, sha256: "x", bytes: buf.length }, source: { kind: "mem", buf }, kind: "file", depth: 0, supported: true };
  const inv: Inventory = { releaseId: "r", items: [item], notes: [], limits: {} as never };
  return { scope: "item", item, bytes: buf, complete: true, inv };
}

/** A minimal PE32+ with the given section names; names longer than 8 bytes go to the COFF string table. */
function peWithSections(names: string[], symbols = 0): Buffer {
  const b = Buffer.alloc(0x1000);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(0x40, 0x3c);
  b.write("PE\0\0", 0x40, "latin1");
  const coff = 0x44;
  b.writeUInt16LE(0x8664, coff);
  b.writeUInt16LE(names.length, coff + 2);
  b.writeUInt16LE(240, coff + 16);
  b.writeUInt16LE(0x0022, coff + 18);
  const opt = coff + 20;
  b.writeUInt16LE(0x20b, opt);
  b.writeUInt16LE(3, opt + 68);
  b.writeUInt16LE(0x0160, opt + 70); // ASLR + NX + high-entropy
  b.writeUInt32LE(16, opt + 108);
  // Symbol table at 0x800 with `symbols` 18-byte entries; the string table follows it.
  const symPtr = 0x800;
  b.writeUInt32LE(symPtr, coff + 8);
  b.writeUInt32LE(symbols, coff + 12);
  const strTab = symPtr + symbols * 18;
  let strAt = 4;
  names.forEach((n, i) => {
    const sec = opt + 240 + i * 40;
    if (n.length <= 8) b.write(n, sec, "latin1");
    else {
      b.write(`/${strAt}`, sec, "latin1");
      b.write(`${n}\0`, strTab + strAt, "latin1");
      strAt += n.length + 1;
    }
    b.writeUInt32LE(0x1000 * (i + 1), sec + 12);
  });
  b.writeUInt32LE(strAt, strTab);
  return b;
}

test("pe: long COFF section names resolve through the string table", () => {
  const p = readPe(peWithSections([".text", ".debug_info", ".zdebug_line"], 3));
  assert.deepEqual(p.sectionNames, [".text", ".debug_info", ".zdebug_line"]);
  assert.equal(p.symbolCount, 3);
});

test("native-pe: DWARF sections and a COFF symbol table are reported; a clean image is not", () => {
  const titles = (b: Buffer) => nativePe.analyze(itemCtx("rel/app.exe", b)).map((f) => f.title);
  const dirty = titles(peWithSections([".text", ".zdebug_info", ".zdebug_abbrev"], 40));
  assert.ok(dirty.includes("Embedded DWARF debug information"), dirty.join("|"));
  assert.ok(dirty.includes("COFF symbol table shipped"), dirty.join("|"));
  const clean = titles(peWithSections([".text", ".rdata", ".data"], 0));
  assert.ok(!clean.some((t) => /DWARF|COFF symbol/.test(t)), clean.join("|"));
  // A section merely named like "debug" without the DWARF prefix is not DWARF.
  assert.ok(!titles(peWithSections([".text", ".debug"], 0)).includes("Embedded DWARF debug information"));
});

const has = (cmd: string) => spawnSync(cmd, ["version"], { encoding: "utf8" }).status === 0;

test("native-pe differential: real Go windows/amd64 builds agree with debug/pe across -s and -w", { skip: !has("go") }, () => {
  const dir = tmp("anti-rea-gope-");
  writeFileSync(join(dir, "go.mod"), "module x\ngo 1.21\n");
  writeFileSync(join(dir, "main.go"), 'package main\nimport "fmt"\nfunc main(){ fmt.Println("hi") }\n');
  const env = { ...process.env, GOOS: "windows", GOARCH: "amd64", CGO_ENABLED: "0", GOFLAGS: "-mod=mod", GOTOOLCHAIN: "local" };
  for (const [name, ldflags, wantDwarf, wantSyms] of [
    ["default", "", true, true],
    ["w", "-w", false, true],
    ["sw", "-s -w", false, false],
  ] as const) {
    const out = join(dir, `${name}.exe`);
    const r = spawnSync("go", ["build", ...(ldflags ? [`-ldflags=${ldflags}`] : []), "-o", out, "."], { cwd: dir, env, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(existsSync(out));
    const t = nativePe.analyze(itemCtx(`rel/${name}.exe`, readFileSync(out))).map((f) => f.title);
    assert.equal(t.includes("Embedded DWARF debug information"), wantDwarf, `${name}: ${t.join("|")}`);
    assert.equal(t.includes("COFF symbol table shipped"), wantSyms, `${name}: ${t.join("|")}`);
  }
});

test("debug-files: inline data: source maps are decoded and graded (with sources → critical; without → names)", () => {
  const map = (withSources: boolean) =>
    JSON.stringify({ version: 3, sources: ["src/app.ts"], names: ["licenseCheck"], mappings: "AAAA,SAASA", ...(withSources ? { sourcesContent: ["export function licenseCheck() { return true }"] } : {}) });
  const b64 = (s: string) => Buffer.from(s).toString("base64");
  const js = (m: string, enc: "b64" | "pct") =>
    Buffer.from(`console.log(1);\n//# sourceMappingURL=data:application/json;${enc === "b64" ? `charset=utf-8;base64,${b64(m)}` : `,${encodeURIComponent(m)}`}\n`);
  const titles = (path: string, b: Buffer) => {
    const ctx = itemCtx(path, b);
    return debugFiles.detect(ctx) ? debugFiles.analyze(ctx).map((f) => f.title) : [];
  };
  assert.deepEqual(titles("rel/main.js", js(map(true), "b64")), ["Inline source map ships the original source"]);
  assert.deepEqual(titles("rel/main.js", js(map(false), "b64")), ["Inline source map restores original names and layout"]);
  assert.deepEqual(titles("rel/style.css", Buffer.from(`a{}\n/*# sourceMappingURL=data:application/json;base64,${b64(map(true))} */\n`)), ["Inline source map ships the original source"]);
  assert.equal(inlineSourceMaps(js(map(true), "pct")).length, 1);
  // Tooling that BUILDS such a comment (a template, a short stub) is not an embedded map.
  assert.deepEqual(titles("rel/tool.js", Buffer.from("const c = `//# sourceMappingURL=data:application/json;base64,${b64}`;\n")), []);
  assert.deepEqual(titles("rel/stub.js", Buffer.from("x\n//# sourceMappingURL=data:application/json;base64,e30=\n")), []);
  // A non-map JSON payload is not graded.
  assert.deepEqual(titles("rel/other.js", js(JSON.stringify({ hello: "world", padding: "x".repeat(64) }), "b64")), []);
});

// Found by the v7 dev set (dev is therefore tuning data; PREREGISTRATION.md §8): head-only prefilters.
test("debug-files: a multi-megabyte map whose \"mappings\" key comes after sourcesContent is still graded", () => {
  const big = "x".repeat(3 * 1024 * 1024);
  const map = Buffer.from(JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: [big], mappings: "AAAA" }));
  const ctx = itemCtx("rel/resources/app/main.js.map", map);
  assert.ok(debugFiles.detect(ctx));
  assert.deepEqual(debugFiles.analyze(ctx).map((f) => f.title), ["Source map ships the original source"]);
});

test("js-electron: an Electron main bundle larger than 1 MiB, with the entry module at the end, is analyzed", async () => {
  const { jsElectron } = await import("../src/analyzers/js-electron.js");
  const deps = `var dep = ${JSON.stringify("y".repeat(2 * 1024 * 1024))};\n`;
  const entry = `const { BrowserWindow } = require("electron");\nnew BrowserWindow({ webPreferences: { contextIsolation: false } });\nwin.webContents.openDevTools();\n`;
  const ctx = itemCtx("rel/resources/app/main.js", Buffer.from(deps + entry));
  assert.ok(jsElectron.detect(ctx));
  const titles = jsElectron.analyze(ctx).map((f) => f.title);
  assert.ok(titles.includes("Insecure Electron webPreferences: contextIsolation: false"), titles.join("|"));
  assert.ok(titles.includes("Electron DevTools opened from shipped code"), titles.join("|"));
});
