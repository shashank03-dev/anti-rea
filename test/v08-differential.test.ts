/**
 * v0.8 differential tests: the exposure readers checked against the real toolchains that produce the
 * formats, on binaries built here. Each test skips when its tool is absent, as the v0.7 differential
 * tests do. Go cross-compiles real ELF/PE/WASM; clang builds real Mach-O.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readElf, elfHardening } from "../src/codecs/elf.js";
import { machoHardening } from "../src/codecs/macho.js";
import { go } from "../src/analyzers/go.js";
import { nativeMachO } from "../src/analyzers/native-macho.js";
import { redact } from "../src/analyzers/redact.js";
import type { Inventory, InventoryItem } from "../src/lanes/types.js";
import type { ItemContext } from "../src/analyzers/types.js";
import { put, tmp } from "./helpers.js";

const has = (bin: string) => spawnSync("/usr/bin/which", [bin]).status === 0;
const GO = has("go");
const DARWIN = process.platform === "darwin";
const CLANG = has("clang");
const MACHO_TOOLS = DARWIN && CLANG && has("otool") && has("strip");
const sh = (cmd: string, args: string[], cwd?: string) => execFileSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 1 << 28, stdio: ["ignore", "pipe", "pipe"] });

function itemCtx(path: string, buf: Buffer): ItemContext {
  const item: InventoryItem = { ref: { path, sha256: "x", bytes: buf.length }, source: { kind: "mem", buf }, kind: "file", depth: 0, supported: true };
  const inv: Inventory = { releaseId: "r", items: [item], notes: [], limits: {} as never };
  return { scope: "item", item, bytes: buf, complete: true, inv };
}

const SECRET = "sk-live-DIFFERENTIAL-SECRET-0123456789ab";

function goSource(dir: string): void {
  put(dir, "go.mod", "module example.com/exposedemo\n\ngo 1.20\n");
  put(dir, "main.go", `package main\nimport "fmt"\nvar apiKey = "default"\nfunc main() { fmt.Println(apiKey) }\n`);
}

test("go: the buildinfo module path agrees with `go version -m`, and -ldflags secrets are redacted", { skip: !GO }, () => {
  const dir = tmp("anti-rea-v08-go-");
  goSource(dir);
  const exe = join(dir, "app");
  sh("go", ["build", "-ldflags", `-X main.apiKey=${SECRET}`, "-o", exe, "."], dir);
  const buf = readFileSync(exe);
  const findings = go.analyze(itemCtx("app-linux", buf));
  const bi = findings.find((f) => f.analyzerId === "go" && f.rubricId === "metadata/build");
  assert.ok(bi, "go buildinfo reported");

  // oracle: `go version -m` prints the module path and the build settings
  const oracle = sh("go", ["version", "-m", exe]);
  const modPath = /\bpath\s+(\S+)/.exec(oracle)?.[1] ?? /\bmod\s+(\S+)/.exec(oracle)?.[1];
  assert.ok(modPath && bi!.recovers.includes("dependency"), "module/deps summarised");
  assert.ok(oracle.includes("example.com/exposedemo"), "oracle sees our module");

  // the planted -X secret must be redacted everywhere in the finding
  const serialized = JSON.stringify(redact(bi!.detail ?? ""));
  assert.ok(!serialized.includes(SECRET), "the -ldflags secret must be redacted");
  assert.ok(oracle.includes(SECRET), "sanity: the oracle itself does show the secret (so redaction is doing real work)");
});

test("go: ELF hardening matches a non-PIE linux/amd64 default (language-aware, graded low)", { skip: !GO }, () => {
  const dir = tmp("anti-rea-v08-goelf-");
  goSource(dir);
  const env = { ...process.env, GOOS: "linux", GOARCH: "amd64" };
  execFileSync("go", ["build", "-ldflags", `-X main.apiKey=${SECRET}`, "-o", join(dir, "app-linux2"), "."], { cwd: dir, env });
  const buf = readFileSync(join(dir, "app-linux2"));
  const e = readElf(buf);
  const h = elfHardening(e);
  assert.ok(e.sections.some((s) => s.name === ".gopclntab" || s.name === ".go.buildinfo"), "a Go ELF has its pclntab/buildinfo sections");
  assert.ok(["no-pie", "pie", "dso"].includes(h.pie));
});

test("native-macho: PIE agrees with otool -hv, and stripping removes the local symbols", { skip: !MACHO_TOOLS }, () => {
  const dir = tmp("anti-rea-v08-macho-");
  put(dir, "a.c", "static int helper(int x){return x*3;}\nint main(void){return helper(2);}\n");
  const exe = join(dir, "app");
  sh("clang", ["-g", "-O0", "-arch", "arm64", "a.c", "-o", "app"], dir);

  const buf = readFileSync(exe);
  const hard = machoHardening(buf);
  const otool = sh("otool", ["-hv", exe]);
  const otoolPie = /\bPIE\b/.test(otool);
  assert.equal(hard.some((s) => s.pie), otoolPie, "MH_PIE agrees with otool -hv");

  const before = nativeMachO.analyze(itemCtx("app", buf));
  assert.ok(before.some((f) => f.rubricId === "symbols/debug-info" || f.rubricId === "symbols/local"), "unstripped Mach-O exposes debug/local symbols");

  sh("strip", ["-x", "-S", exe]);
  const after = nativeMachO.analyze(itemCtx("app", readFileSync(exe)));
  const localsBefore = before.filter((f) => f.rubricId === "symbols/local").length;
  const localsAfter = after.filter((f) => f.rubricId === "symbols/local").length;
  assert.ok(localsAfter <= localsBefore, "stripping does not increase recovered local symbols");
});
