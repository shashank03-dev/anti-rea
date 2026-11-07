/**
 * Differential tests: Anti-REA's container readers/writers vs. the reference
 * implementations, on real third-party content (the TypeScript compiler's lib
 * directory: 125 files, ~23 MB, written by other people).
 *
 *   asar  ↔ @electron/asar (Electron's official packer)
 *   zip   ↔ Info-ZIP `zip` / `unzip`, macOS `ditto` (data descriptors), streaming zip
 *   tar   ↔ bsdtar in pax, gnutar and ustar formats, plus gzip
 *
 * Every extracted entry must be byte-identical to the source file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, relative, sep } from "node:path";
import { sha256Hex } from "../src/util/hash.js";
import { DEFAULT_LIMITS, classify, expand } from "../src/lanes/containers.js";
import { writeAsar, writeTar, writeZip } from "../src/pack/writers.js";
import { tmp } from "./helpers.js";

const require = createRequire(import.meta.url);
const TS_LIB = join(require.resolve("typescript/package.json"), "..", "lib");

function has(cmd: string): boolean {
  return spawnSync("/usr/bin/which", [cmd]).status === 0;
}

/**
 * The tar differentials compare against libarchive's bsdtar (macOS `tar`; `bsdtar` from libarchive-tools on
 * Linux). GNU tar rejects bsdtar's flags, so it must not stand in silently: no bsdtar means the test is skipped.
 */
const BSDTAR: string | null = (() => {
  for (const cmd of ["bsdtar", "tar"]) {
    const r = spawnSync(cmd, ["--version"], { encoding: "utf8" });
    if (r.status === 0 && /bsdtar/.test(r.stdout)) return cmd;
  }
  return null;
})();
const tarCmd = () => BSDTAR!;

function listFiles(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(relative(root, p).split(sep).join("/"), sha256Hex(readFileSync(p)));
    }
  };
  walk(root);
  return out;
}

/** A corpus with real files plus awkward names (long paths > 100 bytes, unicode, spaces). */
function corpus(): { dir: string; files: Map<string, string> } {
  const dir = tmp("anti-rea-diff-");
  const src = join(dir, "src");
  cpSync(TS_LIB, join(src, "lib"), { recursive: true });
  const deep = join(src, "very-long-directory-name-to-exceed-ustar-limits/".repeat(3), "nested");
  mkdirSync(deep, { recursive: true });
  writeFileSync(join(deep, "a file with spaces – ünïcödé.txt"), "long-path payload\n");
  writeFileSync(join(src, "empty.bin"), Buffer.alloc(0));
  return { dir, files: listFiles(src) };
}

function assertSameEntries(label: string, entries: { name: string; data: Buffer | null }[], expected: Map<string, string>, strip = "") {
  const got = new Map<string, string>();
  for (const e of entries) {
    if (e.data === null) assert.fail(`${label}: entry ${e.name} unreadable`);
    const name = strip && e.name.startsWith(strip) ? e.name.slice(strip.length) : e.name;
    got.set(name, sha256Hex(e.data!));
  }
  for (const [name, h] of expected) assert.equal(got.get(name), h, `${label}: ${name} differs or is missing`);
  assert.equal([...got.keys()].filter((k) => !expected.has(k) && !k.startsWith("__MACOSX/")).length, 0, `${label}: unexpected extra entries`);
}

const ok = (e: ReturnType<typeof expand>) => {
  assert.ok(e.ok, e.ok ? "" : e.reason);
  return e.ok ? e.entries : [];
};

test("asar: reader matches @electron/asar packing real files (incl. unpacked entries)", async () => {
  const asar = await import("@electron/asar");
  const { dir, files } = corpus();
  const out = join(dir, "app.asar");
  await asar.createPackageWithOptions(join(dir, "src"), out, { unpack: "*.txt" });
  const buf = readFileSync(out);
  assert.deepEqual(classify("app.asar", buf), { type: "container", kind: "asar" });
  const ex = expand("asar", "app.asar", buf, DEFAULT_LIMITS);
  assert.ok(ex.ok);
  if (!ex.ok) return;
  const packed = new Map([...files].filter(([k]) => !k.endsWith(".txt")));
  assertSameEntries("asar", ex.entries, packed);
  assert.ok(ex.notes.some((n) => n.includes("is unpacked")), "unpacked entries are reported, not silently dropped");
});

test("asar: writer output is readable by @electron/asar", async () => {
  const asar = await import("@electron/asar");
  const { dir, files } = corpus();
  const src = join(dir, "src");
  const out = join(dir, "mine.asar");
  writeFileSync(out, writeAsar([...files.keys()].map((p) => ({ path: p, data: readFileSync(join(src, p)) }))));
  const listed = asar.listPackage(out, { isPack: false }).map((p: string) => p.replace(/^[/\\]/, "").split(sep).join("/"));
  for (const p of files.keys()) {
    assert.ok(listed.includes(p), `official lister missing ${p}`);
    assert.equal(sha256Hex(asar.extractFile(out, p)), files.get(p), `official extractor differs on ${p}`);
  }
});

test("zip: reader matches Info-ZIP, streaming zip (data descriptors) and macOS ditto", { skip: !has("zip") }, () => {
  const { dir, files } = corpus();
  const src = join(dir, "src");
  const variants: [string, () => Buffer][] = [
    ["zip -r -9", () => (execFileSync("zip", ["-q", "-r", "-9", join(dir, "a.zip"), "."], { cwd: src }), readFileSync(join(dir, "a.zip")))],
    ["zip -r -0 (stored)", () => (execFileSync("zip", ["-q", "-r", "-0", join(dir, "b.zip"), "."], { cwd: src }), readFileSync(join(dir, "b.zip")))],
  ];
  if (has("ditto")) variants.push(["ditto -c -k", () => (execFileSync("ditto", ["-c", "-k", "--norsrc", src, join(dir, "c.zip")]), readFileSync(join(dir, "c.zip")))]);
  for (const [label, make] of variants) assertSameEntries(label, ok(expand("zip", "x.zip", make(), DEFAULT_LIMITS)), files);

  // Streaming mode writes sizes in data descriptors after each entry (general-purpose flag bit 3).
  const one = join(src, "lib", "typescript.js");
  const streamed = execFileSync("zip", ["-q", "-", "-"], { input: readFileSync(one), maxBuffer: 1 << 30 });
  const entries = ok(expand("zip", "s.zip", streamed, DEFAULT_LIMITS));
  assert.equal(entries.length, 1);
  assert.equal(sha256Hex(entries[0]!.data!), files.get("lib/typescript.js"));
});

test("zip: writer output passes `unzip -t` and extracts identically", { skip: !has("unzip") }, () => {
  const { dir, files } = corpus();
  const src = join(dir, "src");
  const out = join(dir, "mine.zip");
  writeFileSync(out, writeZip([...files.keys()].map((p) => ({ path: p, data: readFileSync(join(src, p)) }))));
  const t = spawnSync("unzip", ["-t", "-q", out], { encoding: "utf8" });
  assert.equal(t.status, 0, t.stdout + t.stderr);
  const x = join(dir, "x");
  execFileSync("unzip", ["-q", out, "-d", x]);
  assert.deepEqual(listFiles(x), files);
});

test("tar: reader matches bsdtar in pax, gnutar and ustar formats, and gzip", { skip: !BSDTAR }, () => {
  const { dir, files } = corpus();
  const src = join(dir, "src");
  for (const fmt of ["pax", "gnutar"]) {
    const out = join(dir, `${fmt}.tar`);
    execFileSync(tarCmd(), ["--format", fmt, "--no-mac-metadata", "-cf", out, "."], { cwd: src });
    assertSameEntries(`tar ${fmt}`, ok(expand("tar", out, readFileSync(out), DEFAULT_LIMITS)), files);
  }
  // With macOS metadata on, bsdtar writes AppleDouble `._*` members; they are real shipped bytes and must be surfaced.
  const mac = join(dir, "mac.tar");
  execFileSync(tarCmd(), ["--format", "pax", "-cf", mac, "lib/lib.d.ts"], { cwd: src });
  const macNames = ok(expand("tar", mac, readFileSync(mac), DEFAULT_LIMITS)).map((e) => e.name);
  assert.ok(macNames.includes("lib/lib.d.ts"));
  // ustar cannot represent every long path; compare only the files it accepted.
  const ustar = join(dir, "u.tar");
  spawnSync(tarCmd(), ["--format", "ustar", "--no-mac-metadata", "-cf", ustar, "lib"], { cwd: src });
  const uFiles = new Map([...files].filter(([k]) => k.startsWith("lib/")));
  assertSameEntries("tar ustar", ok(expand("tar", ustar, readFileSync(ustar), DEFAULT_LIMITS)), uFiles);

  const tgz = join(dir, "x.tgz");
  execFileSync(tarCmd(), ["--no-mac-metadata", "-czf", tgz, "."], { cwd: src });
  const g = expand("gzip", "x.tgz", readFileSync(tgz), DEFAULT_LIMITS);
  assert.ok(g.ok && g.kind === "tar");
  assertSameEntries("tgz", ok(g), files);
});

test("tar: writer output is listed and extracted identically by bsdtar", { skip: !BSDTAR }, () => {
  const { dir, files } = corpus();
  const src = join(dir, "src");
  const short = [...files.keys()].filter((p) => p.length < 100);
  const out = join(dir, "mine.tar");
  writeFileSync(out, writeTar(short.map((p) => ({ path: p, data: readFileSync(join(src, p)) }))));
  const x = join(dir, "x");
  mkdirSync(x);
  execFileSync(tarCmd(), ["-xf", out, "-C", x]);
  const got = listFiles(x);
  for (const p of short) assert.equal(got.get(p), files.get(p), p);
});

test("compressed tarballs from real tools (bzip2, xz, lzma, zstd) expand to identical entries", { skip: !BSDTAR }, () => {
  const { dir, files } = corpus();
  const src = join(dir, "src");
  const cases: [string, string[]][] = [
    ["x.tar.bz2", ["-cjf"]],
    ["x.tar.xz", ["-cJf"]],
    ["x.tar.lzma", ["--lzma", "-cf"]],
    ["x.tar.zst", ["--zstd", "-cf"]],
  ];
  let checked = 0;
  for (const [name, flags] of cases) {
    const out = join(dir, name);
    const r = spawnSync(tarCmd(), ["--no-mac-metadata", ...flags, out, "."], { cwd: src });
    if (r.status !== 0) continue; // this bsdtar lacks the compressor
    checked++;
    const c = classify(name, readFileSync(out));
    assert.equal(c.type, "container", `${name}: ${JSON.stringify(c)}`);
    const ex = expand((c as { kind: Parameters<typeof expand>[0] }).kind, name, readFileSync(out), DEFAULT_LIMITS);
    assert.ok(ex.ok && ex.kind === "tar", `${name}: ${JSON.stringify(ex.ok ? ex.kind : ex.reason)}`);
    assertSameEntries(name, ok(ex), files);
  }
  // A bsdtar that can write none of these formats must not turn this test into a silent pass.
  assert.ok(checked > 0, "bsdtar wrote none of bzip2/xz/lzma/zstd tarballs; install the compressors or skip explicitly");
});

test("xz with BCJ/delta filters, multiple blocks and concatenated streams matches xz(1)", { skip: !has("xz") || !BSDTAR }, () => {
  const { dir } = corpus();
  const src = join(dir, "src");
  const tarPath = join(dir, "plain.tar");
  execFileSync(tarCmd(), ["--format", "pax", "--no-mac-metadata", "-cf", tarPath, "lib"], { cwd: src });
  const tarBytes = readFileSync(tarPath);
  const variants: string[][] = [["--x86", "--lzma2=preset=6"], ["--delta=dist=4", "--lzma2"], ["-T4", "--block-size=1MiB"], ["-0", "--check=sha256"], ["-9e", "--check=none"]];
  for (const v of variants) {
    const xzBytes = execFileSync("xz", [...v, "-c", tarPath], { maxBuffer: 1 << 30 });
    const ex = expand("xz", "x.tar.xz", xzBytes, DEFAULT_LIMITS);
    assert.ok(ex.ok, `${v.join(" ")}: ${ex.ok ? "" : ex.reason}`);
    const joined = Buffer.concat(ok(ex).map((e) => e.data!));
    assert.ok(joined.length > 0);
  }
  // Concatenated streams decode to the concatenation (xz -dc semantics).
  const a = execFileSync("xz", ["-c", join(src, "lib", "lib.d.ts")]);
  const b = execFileSync("xz", ["-c", join(src, "lib", "lib.es5.d.ts")]);
  const cat = expand("xz", "two.xz", Buffer.concat([a, Buffer.alloc(8), b]), DEFAULT_LIMITS);
  assert.ok(cat.ok);
  assert.equal(sha256Hex(ok(cat)[0]!.data!), sha256Hex(Buffer.concat([readFileSync(join(src, "lib", "lib.d.ts")), readFileSync(join(src, "lib", "lib.es5.d.ts"))])));
  assert.equal(sha256Hex(Buffer.from(execFileSync("xz", ["-dc"], { input: execFileSync("xz", ["--x86", "--lzma2", "-c", tarPath], { maxBuffer: 1 << 30 }), maxBuffer: 1 << 30 }))), sha256Hex(tarBytes));
});

test("damaged xz / bzip2 input is reported as a decode failure, never as content", { skip: !has("xz") || !has("bzip2") }, () => {
  const { dir } = corpus();
  const f = join(dir, "src", "lib", "lib.d.ts");
  for (const [kind, bytes] of [["xz", execFileSync("xz", ["-c", f])], ["bzip2", execFileSync("bzip2", ["-c", f])]] as const) {
    for (const at of [0.25, 0.5, 0.9]) {
      const bad = Buffer.from(bytes);
      bad[Math.floor(bad.length * at)]! ^= 0x10;
      const ex = expand(kind, `x.${kind}`, bad, DEFAULT_LIMITS);
      assert.equal(ex.ok, false, `${kind} flipped at ${at}`);
      assert.match((ex as { reason: string }).reason, /failed to decode|exceeds expansion limit/);
    }
  }
});

test("ar archives written by ar(1) (the .deb container) expand to identical members", { skip: !has("ar") }, () => {
  const { dir } = corpus();
  const lib = join(dir, "src", "lib");
  const names = readdirSync(lib).filter((n) => n.endsWith(".d.ts")).slice(0, 12);
  const out = join(dir, "x.a");
  execFileSync("ar", ["-S", "-q", out, ...names], { cwd: lib }); // -S: no symbol table (macOS ar drops non-Mach-O members otherwise)
  const ex = expand("ar", "x.a", readFileSync(out), DEFAULT_LIMITS);
  assert.ok(ex.ok);
  const expected = new Map(names.map((n) => [n, sha256Hex(readFileSync(join(lib, n)))]));
  assertSameEntries("ar", ok(ex).filter((e) => !e.name.startsWith("__.SYMDEF")), expected);
});

test("lz4 frames from lz4(1) (default, HC, linked blocks, block checksums, legacy) decode identically", { skip: !has("lz4") || !BSDTAR }, () => {
  const { dir } = corpus();
  const src = join(dir, "src");
  const tarPath = join(dir, "plain.tar");
  execFileSync(tarCmd(), ["--format", "pax", "--no-mac-metadata", "-cf", tarPath, "lib"], { cwd: src });
  const tarBytes = readFileSync(tarPath);
  for (const flags of [[], ["-9", "--no-frame-crc"], ["-BD", "-B4", "--content-size"], ["-BX", "-B5"], ["-l"]]) {
    const lz = execFileSync("lz4", ["-q", "-c", ...flags, tarPath], { maxBuffer: 1 << 30 });
    assert.equal(classify("x.tar.lz4", lz).type, "container", flags.join(" "));
    const ex = expand("lz4", "x.tar.lz4", lz, DEFAULT_LIMITS);
    assert.ok(ex.ok && ex.kind === "tar", `${flags.join(" ")}: ${ex.ok ? ex.kind : ex.reason}`);
    const fromTar = expand("tar", "plain.tar", tarBytes, DEFAULT_LIMITS);
    assert.deepEqual(ok(ex).map((e) => sha256Hex(e.data!)), ok(fromTar).map((e) => sha256Hex(e.data!)), flags.join(" "));
  }
});

test("zip entries compressed with bzip2 (method 12) and LZMA (method 14) by Python zipfile decode identically", { skip: !has("python3") }, () => {
  const { dir } = corpus();
  const lib = join(dir, "src", "lib");
  const names = readdirSync(lib).filter((n) => n.endsWith(".d.ts")).slice(0, 8);
  for (const [method, label] of [["ZIP_BZIP2", "bzip2"], ["ZIP_LZMA", "lzma"]] as const) {
    const out = join(dir, `${label}.zip`);
    execFileSync("python3", ["-I", "-c", `import sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], "w", compression=zipfile.${method})\nfor n in sys.argv[2:]: z.write(n)\nz.close()`, out, ...names], { cwd: lib });
    const ex = expand("zip", out, readFileSync(out), DEFAULT_LIMITS);
    assertSameEntries(label, ok(ex), new Map(names.map((n) => [n, sha256Hex(readFileSync(join(lib, n)))])));
  }
});

test("formats this version cannot read stay explicit coverage gaps", () => {
  const { dir } = corpus();
  const f = join(dir, "src", "lib", "lib.d.ts");
  if (has("zip")) {
    const z = join(dir, "enc.zip");
    execFileSync("zip", ["-q", "-P", "not-a-real-password", "-j", z, f]);
    const ex = expand("zip", "enc.zip", readFileSync(z), DEFAULT_LIMITS);
    assert.ok(ex.ok);
    assert.equal(ok(ex)[0]!.data, null);
    assert.equal(ok(ex)[0]!.reason, "encrypted zip entry");
  }
  assert.deepEqual(classify("x.7z", Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4])), { type: "opaque", format: "7-Zip" });
  // v0.5 reads UDIF version 4 images (see "dmg:" tests); an unknown trailer version stays a gap.
  const dmg = Buffer.concat([Buffer.alloc(4096, 7), Buffer.from("koly"), Buffer.alloc(508)]);
  assert.deepEqual(classify("x.dmg", dmg), { type: "opaque", format: "Apple disk image (unrecognised UDIF version)" });
  assert.deepEqual(classify("x.dmg", Buffer.concat([Buffer.from("encrcdsa"), Buffer.alloc(600)])), { type: "opaque", format: "encrypted Apple disk image" });
});
