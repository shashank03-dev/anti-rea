/**
 * v0.7: the reverse-engineering-aids lane (see docs/research/V07-CHANGES.md).
 *
 * Every native fact is checked against the platform's own tools on binaries built here by clang:
 * Mach-O stab and local-symbol counts against `dsymutil -s` (the raw nlist table), DWARF sections
 * against `otool -l`, ELF sections and symbols against `llvm-objdump`. JavaScript checks use real
 * esbuild output. Tests that need a tool are skipped where it is missing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, copyFileSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { transformSync } from "esbuild";
import { assure } from "../src/engine/evaluate.js";
import { readNativeSymbols, looksLikeElf } from "../src/codecs/symbols.js";
import { codeOnly, debugFileKind, electronLeads, jsShape, minifyVerdict } from "../src/lanes/aids.js";
import { writeAsar } from "../src/pack/writers.js";
import { validateManifest } from "../src/util/io.js";
import { manifestFor, policyOf, put, tmp } from "./helpers.js";

const DARWIN = process.platform === "darwin";
const has = (bin: string) => spawnSync("/usr/bin/which", [bin]).status === 0;
const CLANG = has("clang");
const MACHO_TOOLS = DARWIN && CLANG && has("dsymutil") && has("strip") && has("otool") && has("lipo");
const OBJDUMP = CLANG && DARWIN && spawnSync("xcrun", ["--find", "llvm-objdump"]).status === 0;
const sh = (cmd: string, args: string[], cwd?: string) => execFileSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"] });

const C_SOURCE = `
static int counter = 4;
static int helper(int x) { return x * 3 + counter; }
static int other_helper(int x) { return helper(x) - 1; }
int api(int y) { return other_helper(y) + helper(y); }
int main(void) { return api(2) == 0; }
`;

/** Oracle: count stabs and local defined symbols in `dsymutil -s`'s dump of the nlist table. */
function dsymutilCounts(file: string, arch: string) {
  let stabs = 0;
  let locals = 0;
  const oso: string[] = [];
  for (const l of sh("dsymutil", ["-s", "-arch", arch, file]).split("\n")) {
    const m = l.match(/^\[\s*\d+\] [0-9a-f]{8} ([0-9a-f]{2}) \(.*\) [0-9a-f]{2} +[0-9a-f]{4} +[0-9a-f]+(?: '(.*)')?$/);
    if (!m) continue;
    const t = parseInt(m[1]!, 16);
    if (t & 0xe0) {
      stabs++;
      if (t === 0x66 && m[2]) oso.push(m[2]);
    } else if (!(t & 1) && (t & 0x0e) === 0x0e && !/^__mh_\w+_header$/.test(m[2] ?? "")) locals++;
  }
  return { stabs, locals, oso };
}

function buildMachO(dir: string, arch: string): { exe: string; obj: string } {
  put(dir, "a.c", C_SOURCE);
  const obj = join(dir, `a-${arch}.o`);
  const exe = join(dir, `app-${arch}`);
  sh("clang", ["-g", "-O0", "-arch", arch, "-c", "a.c", "-o", obj], dir);
  sh("clang", ["-arch", arch, obj, "-o", exe], dir);
  return { exe, obj };
}

// ---------------------------------------------------------------- Mach-O

test("macho symbols: stabs, debug map, sources and locals agree with dsymutil across strip -S, strip -x and strip", { skip: !MACHO_TOOLS }, () => {
  const dir = tmp("anti-rea-sym-");
  const { exe, obj } = buildMachO(dir, "arm64");
  const variants: [string, string[]][] = [["unstripped", []], ["strip-S", ["-S"]], ["strip-x", ["-x"]], ["strip", []]];
  const seen: Record<string, { stabs: number; locals: number }> = {};
  for (const [name, flags] of variants) {
    const f = join(dir, name);
    copyFileSync(exe, f);
    if (name !== "unstripped") sh("strip", [...flags, f]);
    const [s] = readNativeSymbols(readFileSync(f));
    const want = dsymutilCounts(f, "arm64");
    assert.equal(s!.error, undefined);
    assert.equal(s!.stabs, want.stabs, `${name}: stabs`);
    assert.equal(s!.localSymbols, want.locals, `${name}: locals`);
    assert.deepEqual([...s!.debugMapObjects].sort(), [...new Set(want.oso)].sort(), `${name}: debug map`);
    seen[name] = { stabs: s!.stabs, locals: s!.localSymbols };
    if (name === "unstripped") {
      assert.ok(s!.debugMapObjects.includes(obj), "N_OSO names the object file by absolute path");
      assert.ok(s!.sourceFiles.some((p) => p.endsWith("a.c")), "N_SO names the source file");
      assert.ok(s!.localSample.includes("_helper") && s!.localSample.includes("_counter"));
    }
  }
  assert.ok(seen.unstripped!.stabs > 0 && seen.unstripped!.locals >= 3);
  assert.equal(seen["strip-S"]!.stabs, 0, "strip -S removes the debug map");
  assert.equal(seen["strip-x"]!.locals, 0, "strip -x removes local symbols");
  assert.deepEqual(seen.strip, { stabs: 0, locals: 0 });
});

test("macho symbols: embedded DWARF in objects matches otool; fat binaries are read per slice", { skip: !MACHO_TOOLS }, () => {
  const dir = tmp("anti-rea-sym-");
  const a = buildMachO(dir, "arm64");
  const x = buildMachO(dir, "x86_64");
  const [o] = readNativeSymbols(readFileSync(a.obj));
  const otoolSects = [...sh("otool", ["-l", a.obj]).matchAll(/sectname (__\w+)\n\s+segname __DWARF/g)].map((m) => `__DWARF,${m[1]}`).sort();
  assert.equal(o!.filetype, "object");
  assert.ok(otoolSects.length > 0);
  assert.deepEqual([...o!.debugSections].sort(), otoolSects);
  const fat = join(dir, "fat");
  sh("lipo", ["-create", a.exe, x.exe, "-output", fat]);
  const slices = readNativeSymbols(readFileSync(fat));
  assert.deepEqual(slices.map((s) => s.arch).sort(), ["arm64", "x86_64"]);
  for (const s of slices) {
    const want = dsymutilCounts(fat, s.arch);
    assert.equal(s.stabs, want.stabs, `${s.arch} stabs`);
    assert.equal(s.localSymbols, want.locals, `${s.arch} locals`);
  }
});

test("macho symbols: differential against dsymutil on installed applications' Mach-O files", { skip: !(DARWIN && has("dsymutil")) }, () => {
  // Real release binaries (stripped executables, node-gyp addons with debug maps, Swift apps with N_AST).
  const files: string[] = [];
  const walk = (d: string, depth: number) => {
    if (files.length >= 60 || depth > 9) return;
    let names: string[];
    try {
      names = readdirSync(d);
    } catch {
      return;
    }
    for (const n of names.sort()) {
      const p = join(d, n);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(p, depth + 1);
      else if (st.isFile() && st.size > 8192 && st.size < 64 << 20 && (st.mode & 0o100) !== 0) {
        const head = Buffer.alloc(4);
        const fd = openSync(p, "r");
        try {
          readSync(fd, head, 0, 4, 0);
        } finally {
          closeSync(fd);
        }
        const m = head.readUInt32LE(0);
        if (m === 0xfeedfacf || head.readUInt32BE(0) === 0xcafebabe) files.push(p);
      }
      if (files.length >= 60) return;
    }
  };
  for (const app of ["/Applications/Visual Studio Code.app", "/Applications/Claude.app", "/Applications/Ghostty.app", "/System/Applications/Calculator.app"]) if (existsSync(app)) walk(join(app, "Contents"), 0);
  if (files.length === 0) return;
  let slices = 0;
  for (const f of files) {
    for (const s of readNativeSymbols(readFileSync(f))) {
      if (s.error) continue;
      let want;
      try {
        want = dsymutilCounts(f, s.arch);
      } catch {
        continue;
      }
      slices++;
      assert.equal(s.stabs, want.stabs, `${f} (${s.arch}) stabs`);
      assert.equal(s.localSymbols, want.locals, `${f} (${s.arch}) locals`);
    }
  }
  assert.ok(slices >= Math.min(10, files.length));
});

// ---------------------------------------------------------------- ELF

test("elf symbols: debug sections, local symbols and STT_FILE names agree with llvm-objdump on six targets (LE and BE)", { skip: !OBJDUMP }, () => {
  const dir = tmp("anti-rea-elf-");
  put(dir, "a.c", C_SOURCE);
  const objdump = sh("xcrun", ["--find", "llvm-objdump"]).trim();
  const targets = ["x86_64-linux-gnu", "aarch64-linux-gnu", "i386-linux-gnu", "armv7-linux-gnueabihf", "powerpc64-linux-gnu", "s390x-linux-gnu"];
  let checked = 0;
  for (const t of targets)
    for (const g of [true, false]) {
      const out = join(dir, `${t}-${g ? "g" : "n"}.o`);
      if (spawnSync("clang", ["--target=" + t, "-c", g ? "-g" : "-O1", "a.c", "-o", out], { cwd: dir }).status !== 0) continue;
      const b = readFileSync(out);
      assert.ok(looksLikeElf(b));
      const [s] = readNativeSymbols(b);
      assert.equal(s!.error, undefined, t);
      const sections = [...sh(objdump, ["-h", out]).matchAll(/^\s*\d+\s+(\S+)/gm)].map((m) => m[1]!).filter((n) => /^\.z?debug_/.test(n)).sort();
      const syms = sh(objdump, ["-t", out]).split("\n");
      const locals = syms.filter((l) => /^[0-9a-f]+ l\s+[FO] /.test(l)).length;
      const filesyms = syms.filter((l) => /^[0-9a-f]+ l\s+df /.test(l)).map((l) => l.trim().split(/\s+/).pop()!);
      assert.deepEqual([...s!.debugSections].sort(), sections, `${t} -g=${g} sections`);
      assert.equal(s!.localSymbols, locals, `${t} -g=${g} locals`);
      assert.deepEqual([...s!.sourceFiles].sort(), filesyms.sort(), `${t} file symbols`);
      assert.equal(s!.hasSymtab, true);
      if (g) assert.ok(s!.debugSections.includes(".debug_info") && s!.localSymbols >= 2, t);
      checked++;
    }
  assert.ok(checked >= 8, `only ${checked} ELF objects compiled`);
});

// ---------------------------------------------------------------- debug files

test("debug files are recognised by content: MSF/PDB, source maps with and without sourcesContent; look-alikes are not", () => {
  const msf = Buffer.concat([Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "latin1"), Buffer.alloc(64)]);
  assert.equal(debugFileKind("x.pdb", msf), "pdb");
  assert.equal(debugFileKind("renamed.bin", msf), "pdb", "content, not name");
  const map = { version: 3, sources: ["src/a.ts"], names: [], mappings: "AAAA" };
  assert.equal(debugFileKind("a.js.map", Buffer.from(JSON.stringify(map))), "source-map");
  assert.equal(debugFileKind("a.js.map", Buffer.from(JSON.stringify({ ...map, sourcesContent: ["export const k = 1"] }))), "source-map-with-sources");
  assert.equal(debugFileKind("a.js.map", Buffer.from(JSON.stringify({ ...map, sourcesContent: [null] }))), "source-map");
  assert.equal(debugFileKind("idx.map", Buffer.from(JSON.stringify({ version: 3, sections: [{ offset: { line: 0, column: 0 }, map: { ...map, sourcesContent: ["x"] } }] }))), "source-map-with-sources");
  assert.equal(debugFileKind("a.map", Buffer.from(")]}'\n" + JSON.stringify(map))), "source-map", "XSSI prefix");
  for (const [p, b] of [
    ["package.json", JSON.stringify({ name: "x", version: "3.0.0" })],
    ["m.json", JSON.stringify({ version: 3, mappings: 5 })],
    ["geo.map", "not json at all"],
    ["x.pdb", "BSJ"],
  ] as const)
    assert.equal(debugFileKind(p, Buffer.from(b)), null, p);
});

// ---------------------------------------------------------------- JavaScript

test("codeOnly: string, template, regex and comment contents are removed; template expressions and division stay", () => {
  const cases: [string, string][] = [
    [`a = "x//y"; // c\nb`, `a = ""; \nb`],
    ["x = `t ${ y + `in${z}ner` } u`; w", "x = `${ y + `${z}` }`; w"],
    ["r = /a\\/[/]b/g.test(s) / 2", "r = //g.test(s) / 2"],
    ["return /re/.x; a / b / c", "return //.x; a / b / c"],
    ["/* doc */ let q = 1", "  let q = 1"],
    ["s = 'it\\'s'; t", "s = ''; t"],
    ["#!/usr/bin/env node\nlet z", "\nlet z"],
  ];
  for (const [input, want] of cases) assert.equal(codeOnly(input), want, input);
});

/** A real readable module: this repository's own compiled lane (tsc output, full names). */
const READABLE = readFileSync(new URL("../src/lanes/aids.js", import.meta.url), "utf8");

test("minification: readable, whitespace-only and mangled esbuild output are told apart at both levels", () => {
  const ws = transformSync(READABLE, { minifyWhitespace: true, minifySyntax: true, format: "cjs" }).code;
  const mg = transformSync(READABLE, { minify: true, format: "cjs" }).code;
  assert.equal(minifyVerdict(jsShape(READABLE), "whitespace").ok, false);
  assert.equal(minifyVerdict(jsShape(READABLE), "identifiers").ok, false);
  assert.equal(minifyVerdict(jsShape(ws), "whitespace").ok, true);
  assert.equal(minifyVerdict(jsShape(ws), "identifiers").ok, false, "names kept → not mangled");
  assert.equal(minifyVerdict(jsShape(mg), "whitespace").ok, true);
  assert.equal(minifyVerdict(jsShape(mg), "identifiers").ok, true);
  assert.equal(minifyVerdict(jsShape("let a=1;"), "identifiers").ok, null, "too small to judge");
});

test("minification calibration regressions: embedded text, destructuring keys and exports do not make mangled code look readable", () => {
  const mg = transformSync(READABLE, { minify: true, format: "cjs" }).code;
  // (1) Claude/ChatGPT: minified bundles that embed multi-line prose and source in literals.
  const prose = Array.from({ length: 400 }, (_, i) => `let the function of line ${i} be const var readable`).join("\n");
  const withText = `${mg};var D=\`${prose}\`;var E="${"const longName = value; ".repeat(200)}";`;
  assert.equal(minifyVerdict(jsShape(withText), "identifiers").ok, true);
  // (2) destructured parameters: keys are API names, the bindings are the short ones.
  const icons = Array.from({ length: 40 }, (_, i) => `export const Icon${i} = ({ color = "c", size = 24, strokeWidth = 2, className = "", children, ...rest }, ref) => { const scaled = size * strokeWidth; return [color, scaled, className, children, rest, ref]; };`).join("\n");
  const destr = transformSync(icons, { minify: true, format: "esm" }).code;
  assert.equal(jsShape(destr).shortShare >= 0.7, true, `shortShare ${jsShape(destr).shortShare}`);
  // (3) exported names are kept by every minifier: a small rspack chunk (ChatGPT) with 4 exports and 8 mangled locals.
  const pad = Array.from({ length: 30 }, (_, i) => `k${i}:e.string().optional()`).join(",");
  const chunk =
    "export const __rspack_esm_id=100308;export const __rspack_esm_ids=[100308];export const __webpack_modules__={uWA4(t,n,o){" +
    `var e=o("ASxG");let i=e.object({${pad}});let a=(r,l)=>r+l;function s(c,d){return c*d}var u=o("x"),f=o("y");n.d({},{B9:i,Bp:a,Cq:s,Dr:u,Es:f})}};export const __rspack_chunk__=1;`;
  const shape = jsShape(chunk);
  assert.ok(shape.bytes >= 1024 && shape.declared >= 8, JSON.stringify(shape));
  assert.equal(minifyVerdict(shape, "identifiers").ok, true, JSON.stringify(shape));
});

test("electron: insecure webPreferences in minified and readable forms; nested objects and other keys are not leads", () => {
  const readable = `new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: false, webSecurity: false, preload } });`;
  const min = `new _({show:!1,webPreferences:{webSecurity:!1,backgroundThrottling:!1,nodeIntegration:!0,webviewTag:!0,contextIsolation:!1,preload:p}});w.webContents.openDevTools()`;
  const keys = (t: string) => electronLeads(t).insecure.map((l) => `${l.key}:${l.value}`).sort();
  assert.deepEqual(keys(readable), ["contextIsolation:false", "nodeIntegration:true", "sandbox:false", "webSecurity:false"]);
  assert.deepEqual(keys(min), ["contextIsolation:!1", "nodeIntegration:!0", "webSecurity:!1"]);
  assert.equal(electronLeads(min).devTools.length, 1);
  // secure values, keys outside webPreferences, and keys of nested objects are not leads
  assert.deepEqual(keys(`webPreferences:{nodeIntegration:!1,contextIsolation:!0,sandbox:!0}`), []);
  assert.deepEqual(keys(`({sandbox:!1,nodeIntegration:!0})`), []);
  assert.deepEqual(keys(`webPreferences:{extra:{sandbox:!1},defaultFontFamily:{standard:"x"}}`), []);
});

// ---------------------------------------------------------------- manifest

test("manifest: reAids is validated", () => {
  const base = { schema: "anti-rea/manifest/v1", application: { name: "a", version: "1" }, releaseClosure: { roots: ["r"] }, assets: [] };
  const bad = [
    { reAids: [] },
    { reAids: { nope: true } },
    { reAids: { native: { maxLocalSymbols: -1 } } },
    { reAids: { native: { forbidDebugMap: "yes" } } },
    { reAids: { sources: { extensions: ["ts"] } } },
    { reAids: { minified: { include: [] } } },
    { reAids: { minified: { include: ["**/*.js"], level: "max" } } },
    { reAids: { electron: false } },
  ];
  for (const b of bad) assert.throws(() => validateManifest({ ...base, ...b }), /reAids/, JSON.stringify(b));
  assert.doesNotThrow(() => validateManifest({ ...base, reAids: {} }));
  assert.doesNotThrow(() => validateManifest({ ...base, reAids: { native: false, sources: false, debugFiles: false } }));
});

// ---------------------------------------------------------------- end to end

function release(dir: string, fixed: boolean) {
  const mainSrc = fixed
    ? `new BrowserWindow({ webPreferences: { preload: join(__dirname, "preload.js") } });`
    : `new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, preload: join(__dirname, "preload.js") } }); win.webContents.openDevTools();`;
  const renderer = fixed ? transformSync(READABLE, { minify: true, format: "cjs" }).code : READABLE;
  const files = [
    { path: "main.js", data: Buffer.from(fixed ? transformSync(mainSrc, { minify: true }).code : mainSrc) },
    { path: "dist/renderer.js", data: Buffer.from(renderer) },
    { path: "node_modules/dep/src/index.ts", data: Buffer.from("export const third = 'party';\n") },
  ];
  if (!fixed) {
    files.push({ path: "dist/renderer.js.map", data: Buffer.from(JSON.stringify({ version: 3, sources: ["../src/pricing.ts"], sourcesContent: ["export function price() {}"], names: [], mappings: "AAAA" })) });
    files.push({ path: "src/pricing.ts", data: Buffer.from("export function price(q: number) { return q * 42; }\n") });
  }
  put(dir, "rel/App.app/Contents/Resources/app.asar", writeAsar(files));
  if (!fixed) put(dir, "rel/App.app/Contents/Resources/native.pdb", Buffer.concat([Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "latin1"), Buffer.alloc(32)]));
}

test("aids lane end to end: a vulnerable release blocks on each aid; the fixed release passes", () => {
  const reAids = { minified: { include: ["**/dist/**/*.js"] }, electron: { forbidDevTools: true } };
  const policy = policyOf({ requiredLanes: ["inventory", "aids"] });
  const UI = [{ id: "ui", placement: "public-by-design" as const }];

  const bad = tmp("anti-rea-aids-");
  release(bad, false);
  const rep = assure({ manifest: manifestFor(bad, { releaseClosure: { roots: ["rel"] }, assets: UI, reAids }), policy });
  assert.equal(rep.decision, "block");
  assert.equal(rep.coverage.lanes.aids, "concluded");
  const ids = rep.evidence.find((e) => e.lane === "aids")!.findings.map((f) => f.id);
  const has = (re: RegExp) => assert.ok(ids.some((i) => re.test(i)), `${re} in ${ids.join(" | ")}`);
  has(/^aids\/debug-file\/.*renderer\.js\.map$/);
  has(/^aids\/debug-file\/.*native\.pdb$/);
  has(/^aids\/source\/.*!\/src\/pricing\.ts$/);
  has(/^aids\/unminified\/.*dist\/renderer\.js$/);
  has(/^aids\/electron-webpreferences\/.*main\.js\/nodeIntegration@/);
  has(/^aids\/electron-webpreferences\/.*main\.js\/contextIsolation@/);
  has(/^aids\/electron-devtools\//);
  assert.ok(!ids.some((i) => i.includes("node_modules")), "third-party sources are excluded by default");
  const map = rep.evidence.find((e) => e.lane === "aids")!.findings.find((f) => f.id.endsWith("renderer.js.map"))!;
  assert.equal(map.severity, "critical");
  assert.ok(rep.blockingReasons.some((r) => r.startsWith("[reverseEngineeringAidShipped]")));

  const good = tmp("anti-rea-aids-");
  release(good, true);
  const ok = assure({ manifest: manifestFor(good, { releaseClosure: { roots: ["rel"] }, assets: UI, reAids }), policy });
  assert.deepEqual(ok.evidence.find((e) => e.lane === "aids")!.findings.map((f) => f.id), []);
  assert.equal(ok.decision, "pass", ok.blockingReasons.join("\n"));
});

test("aids lane end to end: native binaries block until stripped; a shipped dSYM is a debug file; exclusions and thresholds apply", { skip: !MACHO_TOOLS }, () => {
  const UI = [{ id: "ui", placement: "public-by-design" as const }];
  const policy = policyOf({ requiredLanes: ["inventory", "aids"] });
  const dir = tmp("anti-rea-aids-native-");
  const { exe } = buildMachO(join(dir, "build"), "arm64");
  put(dir, "rel/App.app/Contents/MacOS/app", readFileSync(exe));
  sh("dsymutil", [exe, "-o", join(dir, "rel/App.app.dSYM")]);
  const run = (reAids: object) => {
    const r = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, reAids }), policy });
    return { r, ids: r.evidence.find((e) => e.lane === "aids")!.findings.map((f) => f.id) };
  };
  let { r, ids } = run({});
  assert.equal(r.decision, "block");
  assert.ok(ids.some((i) => /^aids\/debug-map\/.*MacOS\/app\/arm64$/.test(i)), ids.join(" | "));
  assert.ok(ids.some((i) => /^aids\/local-symbols\/.*MacOS\/app\/arm64$/.test(i)));
  assert.ok(ids.some((i) => /^aids\/debug-file\/.*\.dSYM\/Contents\/Resources\/DWARF\/app-arm64$/.test(i)), "dSYM by content");
  assert.ok(!ids.some((i) => /debug-info\/.*\.dSYM/.test(i)), "a dSYM is reported once, as a debug file");
  // owner thresholds and exclusions are honoured
  ({ ids } = run({ native: { maxLocalSymbols: 1000, forbidDebugMap: false }, debugFiles: { exclude: ["**/*.dSYM/**"] } }));
  assert.deepEqual(ids, []);
  // after `strip` and removing the dSYM, the release passes
  const stripped = join(dir, "rel/App.app/Contents/MacOS/app");
  sh("strip", [stripped]);
  sh("rm", ["-rf", join(dir, "rel/App.app.dSYM")]);
  ({ r, ids } = run({}));
  assert.deepEqual(ids, []);
  assert.equal(r.decision, "pass", r.blockingReasons.join("\n"));
});
