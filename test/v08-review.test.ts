/**
 * v0.8 review regressions: one test per defect found in the pre-commit review, each built from bytes
 * that follow the cited format, so the bug cannot quietly return.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { setClock } from "../src/util/clock.js";
import { inventoryOfPath } from "../src/lanes/inventory.js";
import { recoveryLane } from "../src/lanes/recovery.js";
import { buildExposureReport, renderExposureMarkdown } from "../src/engine/exposure-report.js";
import { attribute, emptyProfile, sameVendor } from "../src/analyzers/attribution.js";
import { apkSigningSchemes } from "../src/analyzers/apk.js";
import { readGoBuildInfo } from "../src/analyzers/go.js";
import { jsElectron } from "../src/analyzers/js-electron.js";
import { pyinstaller } from "../src/analyzers/pyinstaller.js";
import { nativeElf } from "../src/analyzers/native-elf.js";
import { readPe } from "../src/codecs/pe.js";
import { readAndroidManifest } from "../src/codecs/axml.js";
import { redact } from "../src/analyzers/redact.js";
import { writeZip } from "../src/pack/writers.js";
import type { ItemContext } from "../src/analyzers/types.js";
import type { Inventory, InventoryItem } from "../src/lanes/types.js";
import { put, tmp } from "./helpers.js";

setClock(new Date("2026-11-07T00:00:00Z"));

const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const u64 = (v: number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };

function itemCtx(path: string, buf: Buffer): ItemContext {
  const item: InventoryItem = { ref: { path, sha256: "x", bytes: buf.length }, source: { kind: "mem", buf }, kind: "file", depth: 0, supported: true };
  const inv: Inventory = { releaseId: "r", items: [item], notes: [], limits: {} as never };
  return { scope: "item", item, bytes: buf, complete: true, inv };
}

function apkFindings(bytes: Buffer, name = "app.apk") {
  const dir = tmp("anti-rea-review-");
  put(dir, name, bytes);
  const r = inventoryOfPath(`${dir}/${name}`);
  return recoveryLane(r.inventory, "2026-11-07T00:00:00Z", {}).findings.filter((f) => f.analyzerId === "apk");
}

/** Insert an APK Signing Block (source.android.com "APK Signature Scheme v2") right before the central directory. */
function withSigningBlock(zip: Buffer, blockId: number): Buffer {
  let eocd = -1;
  for (let i = zip.length - 22; i >= 0; i--) if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  const cd = zip.readUInt32LE(eocd + 16);
  const value = Buffer.alloc(32, 0xab);
  const pairs = Buffer.concat([u64(4 + value.length), u32(blockId), value]);
  const size = pairs.length + 8 + 16;
  const block = Buffer.concat([u64(size), pairs, u64(size), Buffer.from("APK Sig Block 42", "latin1")]);
  const out = Buffer.concat([zip.subarray(0, cd), block, zip.subarray(cd)]);
  out.writeUInt32LE(cd + block.length, eocd + block.length + 16);
  return out;
}

const MANIFEST_STUB = Buffer.alloc(8); // the signing verdict does not depend on the manifest

test("apk: a v2-signed APK is not reported unsigned (signing block parsed)", () => {
  const zip = writeZip([{ path: "AndroidManifest.xml", data: MANIFEST_STUB }, { path: "classes.dex", data: Buffer.alloc(0x70) }]);
  const signed = withSigningBlock(zip, 0x7109871a);
  assert.deepEqual([...apkSigningSchemes(signed)], ["v2"]);
  assert.deepEqual([...apkSigningSchemes(zip)], []);
  const f = apkFindings(signed);
  assert.ok(!f.some((x) => /unsigned|v1 \(JAR\)/.test(x.title)), f.map((x) => x.title).join("; "));
});

test("apk: v1-only and unsigned are told apart; an AAB gets no signing verdict", () => {
  const base = [{ path: "AndroidManifest.xml", data: MANIFEST_STUB }];
  const v1 = writeZip([...base, { path: "META-INF/CERT.RSA", data: Buffer.alloc(8) }, { path: "META-INF/CERT.SF", data: Buffer.from("Signature-Version: 1.0\n") }]);
  assert.ok(apkFindings(v1).some((x) => x.title.includes("v1 (JAR) signing only")));
  const unsigned = writeZip(base);
  assert.ok(apkFindings(unsigned).some((x) => x.title === "APK is unsigned"));
  // A .RSA without its .SF is not a v1 signature.
  const half = writeZip([...base, { path: "META-INF/CERT.RSA", data: Buffer.alloc(8) }]);
  assert.ok(apkFindings(half).some((x) => x.title === "APK is unsigned"));
  const aab = writeZip([{ path: "base/manifest/AndroidManifest.xml", data: MANIFEST_STUB }, { path: "BundleConfig.pb", data: Buffer.alloc(4) }]);
  assert.ok(!apkFindings(aab, "app.aab").some((x) => /signed|signing/.test(x.title)));
});

/** Minimal PE32+ (Microsoft PE/COFF spec): one section holding a CodeView RSDS debug record. */
function pe(dllChars: number): Buffer {
  const b = Buffer.alloc(0x800);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(0x40, 0x3c);
  b.write("PE\0\0", 0x40, "latin1");
  const coff = 0x44;
  b.writeUInt16LE(0x8664, coff); // machine
  b.writeUInt16LE(1, coff + 2); // sections
  b.writeUInt16LE(240, coff + 16); // SizeOfOptionalHeader
  b.writeUInt16LE(0x0022, coff + 18); // executable, large-address-aware
  const opt = coff + 20;
  b.writeUInt16LE(0x20b, opt);
  b.writeUInt16LE(3, opt + 68); // console
  b.writeUInt16LE(dllChars, opt + 70);
  b.writeUInt32LE(16, opt + 108);
  b.writeUInt32LE(0x1000, opt + 112 + 6 * 8); // debug directory RVA
  b.writeUInt32LE(28, opt + 112 + 6 * 8 + 4);
  const sec = opt + 240;
  b.write(".rdata", sec, "latin1");
  b.writeUInt32LE(0x200, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x200, sec + 16);
  b.writeUInt32LE(0x400, sec + 20);
  b.writeUInt32LE(2, 0x400 + 12); // IMAGE_DEBUG_TYPE_CODEVIEW
  b.writeUInt32LE(0x60, 0x400 + 16);
  b.writeUInt32LE(0x420, 0x400 + 24);
  b.write("RSDS", 0x420, "latin1");
  Buffer.from("00112233445566778899aabbccddeeff", "hex").copy(b, 0x424);
  b.writeUInt32LE(7, 0x434);
  b.write("C:\\build\\acme\\Release\\acme.pdb\0", 0x438, "latin1");
  return b;
}

test("pe codec: RSDS GUID/age/path and mitigations decode; the input buffer is not mutated", () => {
  const b = pe(0x0040 | 0x0100 | 0x4000);
  const before = Buffer.from(b);
  const info = readPe(b);
  assert.ok(b.equals(before), "readPe must not modify its input");
  assert.equal(info.machineName, "x86_64");
  assert.ok(info.aslr && info.nxCompat && info.guardCf);
  assert.equal(info.debug[0]!.guid, "33221100554477668899aabbccddeeff");
  assert.equal(info.debug[0]!.age, 7);
  assert.equal(info.debug[0]!.pdbPath, "C:\\build\\acme\\Release\\acme.pdb");
  // Reading twice gives the same GUID (it was reversed in place before the fix).
  assert.equal(readPe(b).debug[0]!.guid, info.debug[0]!.guid);
  const off = readPe(pe(0));
  assert.ok(!off.aslr && !off.nxCompat && !off.guardCf);
});

test("attribution: the release-root label is not a path segment; vendorRoots and bundle-id prefixes decide", () => {
  const p = emptyProfile();
  // A root directory literally named "vendor" (or "node_modules") must not make the whole release third-party.
  assert.equal(attribute("vendor/Acme.app/Contents/MacOS/Acme", p), "owner");
  assert.equal(attribute("dist/node_modules/left-pad/index.js", p), "third-party");
  // flutter_assets is the app's own Dart output, not a vendored engine.
  assert.equal(attribute("app/Runner.app/Frameworks/App.framework/flutter_assets/kernel_blob.bin", p), "owner");
  assert.equal(attribute("app/Runner.app/Frameworks/Flutter.framework/Flutter", p), "third-party");
  const withRoots = { ...p, vendorRoots: ["r/Acme.app/Contents/Frameworks/Other.framework"] };
  assert.equal(attribute("r/Acme.app/Contents/Frameworks/Other.framework/Other", withRoots), "third-party");
  assert.equal(attribute("r/Acme.app/Contents/Frameworks/OtherKit.framework/OtherKit", withRoots), "owner");
  assert.ok(sameVendor("com.acme.helper", "com.acme"));
  assert.ok(!sameVendor("com.acmecorp.helper", "com.acme"));
});

test("js-electron: process.versions is not wholesale exposure; a { ipcRenderer } object is", () => {
  const benign = `const { contextBridge } = require('electron');
    contextBridge.exposeInMainWorld('versions', { node: () => process.versions.node, chrome: () => process.versions.chrome });`;
  assert.ok(!jsElectron.analyze(itemCtx("preload.js", Buffer.from(benign))).some((x) => x.title.startsWith("Preload exposes")));
  const bad = `const { contextBridge, ipcRenderer } = require('electron');
    contextBridge.exposeInMainWorld('api', { ipcRenderer });`;
  assert.ok(jsElectron.analyze(itemCtx("preload.js", Buffer.from(bad))).some((x) => x.title === "Preload exposes ipcRenderer to the renderer"));
  // Not Electron at all: a plain web bundle mentioning "electron" in prose is not analysed.
  assert.ok(!jsElectron.detect(itemCtx("app.js", Buffer.from("// works in electron and browsers\nconsole.log(1)"))));
});

test("pyinstaller: the bootloader's own magic constant before the cookie does not mislead the parser", () => {
  const MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);
  const entry = (type: string, name: string) => {
    const n = Buffer.from(name + "\0");
    const size = 18 + n.length;
    const e = Buffer.alloc(18);
    e.writeUInt32BE(size, 0);
    e.write(type, 17, "latin1");
    return Buffer.concat([e, n]);
  };
  const toc = Buffer.concat([entry("s", "pyiboot01_bootstrap"), entry("s", "main"), entry("m", "acme.core")]);
  const data = Buffer.alloc(64);
  const cookie = Buffer.alloc(88);
  MAGIC.copy(cookie, 0);
  const pkgLen = data.length + toc.length + cookie.length;
  cookie.writeUInt32BE(pkgLen, 8);
  cookie.writeUInt32BE(data.length, 12); // TOC offset within the package
  cookie.writeUInt32BE(toc.length, 16);
  cookie.writeUInt32BE(312, 20);
  cookie.write("python312.dll", 24, "latin1");
  const exe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100), MAGIC, Buffer.alloc(9), Buffer.alloc(512), data, toc, cookie]);
  const f = pyinstaller.analyze(itemCtx("app.exe", exe));
  const all = f.map((x) => `${x.recovers} ${x.detail ?? ""}`).join(" ");
  assert.ok(all.includes("3.12"), all);
  assert.ok(all.includes("main") && !all.includes("pyiboot01_bootstrap"), all);
});

/** ELF64 header only (System V gABI): enough for the analyzer's machine/type gate. */
function elfHeader(machine: number, type = 2): Buffer {
  const b = Buffer.alloc(64);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(b, 0);
  b.writeUInt16LE(type, 16);
  b.writeUInt16LE(machine, 18);
  b.writeUInt32LE(1, 20);
  b.writeUInt16LE(64, 52);
  b.writeUInt16LE(56, 54);
  b.writeUInt16LE(64, 58);
  return b;
}

test("native-elf: CUDA cubins, relocatable objects and core dumps are not graded as host executables", () => {
  assert.ok(nativeElf.detect(itemCtx("a", elfHeader(62))));
  assert.ok(!nativeElf.detect(itemCtx("k.cubin", elfHeader(190))));
  assert.ok(!nativeElf.detect(itemCtx("a.o", elfHeader(62, 1))));
  assert.ok(!nativeElf.detect(itemCtx("core", elfHeader(62, 4))));
});

test("go buildinfo: a magic literal before the real header is skipped; the real header decodes", () => {
  const MAGIC = Buffer.from("\xff Go buildinf:", "latin1");
  const str = (s: Buffer | string) => { const v = Buffer.isBuffer(s) ? s : Buffer.from(s); return Buffer.concat([Buffer.from([v.length]), v]); };
  const sentinel = Buffer.alloc(16, 0x30);
  const mod = Buffer.concat([sentinel, Buffer.from("path\texample.com/acme\nmod\texample.com/acme\t(devel)\t\n"), sentinel]);
  const hdr = Buffer.concat([MAGIC, Buffer.from([8, 0x2]), Buffer.alloc(16)]);
  const bin = Buffer.concat([Buffer.from("x"), MAGIC, Buffer.from("not a header..................."), hdr, str("go1.22.3"), str(mod)]);
  const info = readGoBuildInfo(bin);
  assert.equal(info?.version, "go1.22.3");
  assert.ok(info?.modInfo.includes("example.com/acme"));
  assert.equal(readGoBuildInfo(Buffer.from("no buildinfo here")), null);
});

test("axml codec: truncated and hostile chunk headers never throw", () => {
  const cases = [Buffer.alloc(0), Buffer.from([3, 0, 8, 0]), Buffer.concat([u16(3), u16(8), u32(0xffffffff)]), Buffer.concat([u16(3), u16(8), u32(64), u16(0x102), u16(16), u32(12)])];
  for (const c of cases) assert.doesNotThrow(() => readAndroidManifest(c));
});

test("report markdown: hostile artifact names cannot inject table cells, HTML or links", () => {
  const dir = tmp("anti-rea-review-");
  const evil = "x|y<img src=a>](http://e).js.map";
  put(dir, evil, JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: ["x"], mappings: "A" }));
  const r = inventoryOfPath(dir);
  const lane = recoveryLane(r.inventory, "2026-11-07T00:00:00Z", { app: { name: "demo", version: "1" } });
  const md = renderExposureMarkdown(buildExposureReport(lane, lane.profile));
  assert.ok(!md.includes("<img"), "raw HTML escaped");
  assert.ok(!md.includes("](http://e)"), "link syntax escaped");
});

test("redaction: a credential in a Go -X flag and in a KEY=VALUE pair is masked; a commit hash is kept", () => {
  const s = redact("-ldflags=-X main.apiKey=sk-live-0123456789abcdef API_TOKEN=ghp_ABCDEFabcdef0123456789 vcs.revision=4d9bb03a1b2c3d4e5f60718293a4b5c6d7e8f901");
  assert.ok(!s.includes("sk-live-0123456789abcdef"));
  assert.ok(!s.includes("ghp_ABCDEFabcdef0123456789"));
  assert.ok(s.includes("4d9bb03a1b2c3d4e5f60718293a4b5c6d7e8f901"));
});

// ---------------------------------------------------------------- structure-preserving fuzz
// The seed fuzzer (v08-fuzz.test.ts) keeps only a magic prefix, so deep parser paths (a PE's debug
// directory, an APK signing block, a PyInstaller TOC) rarely run. Here complete, valid fixtures are
// mutated in place (same length, a few bytes changed), which reaches those paths with hostile values.

import { readFileSync, existsSync } from "node:fs";
import { looksLikeMachO, machoHardening } from "../src/codecs/macho.js";
import { nativeMachO } from "../src/analyzers/native-macho.js";
import { nativePe } from "../src/analyzers/native-pe.js";

function rng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return (s >>> 0) / 0xffffffff; };
}

function mutate(src: Buffer, rand: () => number): Buffer {
  const b = Buffer.from(src);
  const n = 1 + Math.floor(rand() * 8);
  for (let i = 0; i < n; i++) {
    const at = Math.floor(rand() * b.length);
    const r = rand();
    if (r < 0.4) b[at] = Math.floor(rand() * 256);
    else if (r < 0.7 && at + 4 <= b.length) b.writeUInt32LE([0, 0xffffffff, 0x7fffffff, 0x80000000, b.length, b.length + 1][Math.floor(rand() * 6)]! >>> 0, at);
    else b[at] = (b[at] ?? 0) ^ (1 << Math.floor(rand() * 8));
  }
  return rand() < 0.15 ? b.subarray(0, Math.floor(rand() * b.length)) : b;
}

test("structure-preserving fuzz: mutated valid fixtures never throw and stay fast", () => {
  const zip = writeZip([{ path: "AndroidManifest.xml", data: MANIFEST_STUB }, { path: "classes.dex", data: Buffer.alloc(0x70) }]);
  const fixtures: [string, Buffer, (b: Buffer) => void][] = [
    ["pe", pe(0x4140), (b) => { try { readPe(b); } catch (e) { if (!(e instanceof RangeError)) throw e; } const c = itemCtx("a.exe", b); if (nativePe.detect(c)) nativePe.analyze(c); }],
    ["apk-sig", withSigningBlock(zip, 0xf05368c0), (b) => { apkSigningSchemes(b); }],
    ["go", Buffer.concat([Buffer.from("\xff Go buildinf:", "latin1"), Buffer.from([8, 2]), Buffer.alloc(16), Buffer.from([8]), Buffer.from("go1.22.3"), Buffer.from([40]), Buffer.alloc(40, 0x30)]), (b) => { readGoBuildInfo(b); }],
    ["elf", elfHeader(62), (b) => { const c = itemCtx("a", b); if (nativeElf.detect(c)) nativeElf.analyze(c); }],
  ];
  for (const sys of ["/bin/ls", "/usr/bin/true"]) {
    if (!existsSync(sys)) continue;
    const bin = readFileSync(sys);
    fixtures.push([sys, bin, (b) => { if (looksLikeMachO(b)) try { machoHardening(b); } catch (e) { if (!/not a Mach-O/.test((e as Error).message)) throw e; } const c = itemCtx("ls", b); if (nativeMachO.detect(c)) nativeMachO.analyze(c); }]);
  }
  const started = Date.now();
  let runs = 0;
  for (const [name, seed, run] of fixtures) {
    const rand = rng(0xa11ce ^ name.length * 7919);
    const iterations = seed.length > 64 * 1024 ? 60 : 400;
    for (let i = 0; i < iterations; i++) {
      const b = mutate(seed, rand);
      try {
        run(b);
      } catch (e) {
        assert.fail(`${name} iteration ${i} threw: ${(e as Error).stack}`);
      }
      runs++;
    }
  }
  assert.ok(runs > 1000);
  assert.ok(Date.now() - started < 60_000, `fuzz took ${Date.now() - started}ms`);
});
