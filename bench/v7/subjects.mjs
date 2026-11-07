#!/usr/bin/env node
// v7 subject discovery. Finds REAL code on this machine that no earlier calibration or benchmark used,
// keeps only what builds OFFLINE (so the corpus is reproducible from the recorded pool), and assigns each
// subject to dev or eval by a fixed hash rule (PREREGISTRATION.md §4): sha256(id)[0] < 64 → dev, else eval.
//
//   go  — `package main` directories in the Go module cache (~/go/pkg/mod) that build with GOPROXY=off
//   c   — C libraries vendored in Rust crates (~/.cargo/registry/src): zstd, QuickJS, SQLite, FreeType, …
//   js  — packages under the Homebrew npm install that esbuild bundles for node
//
// Output: bench/v7/subjects.json. It is part of the frozen tree: discovery runs once, before registration.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const sha = (s) => createHash("sha256").update(s).digest("hex");
export const split = (id) => (parseInt(sha(id).slice(0, 2), 16) < 64 ? "dev" : "eval");

function walk(dir, visit, depth = 0) {
  let names;
  try {
    names = readdirSync(dir).sort();
  } catch {
    return;
  }
  for (const n of names) {
    const p = join(dir, n);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (depth < 12) walk(p, visit, depth + 1);
    } else visit(p);
  }
}

/** spawn with a real timeout (macOS has no timeout(1)). */
function run(cmd, args, opts = {}, ms = 180_000) {
  return new Promise((resolve) => {
    const c = spawn(cmd, args, { ...opts, stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    c.stderr.on("data", (d) => (err += d));
    const t = setTimeout(() => c.kill("SIGKILL"), ms);
    c.on("close", (code) => {
      clearTimeout(t);
      resolve({ ok: code === 0, err: err.slice(-400) });
    });
  });
}

async function pool(items, n, fn) {
  const out = [];
  let i = 0;
  await Promise.all(
    Array.from({ length: n }, async () => {
      while (i < items.length) {
        const k = i++;
        out[k] = await fn(items[k], k);
      }
    }),
  );
  return out;
}

export const GO_ENV = { GOPROXY: "off", GOFLAGS: "-mod=readonly", GOTOOLCHAIN: "local", CGO_ENABLED: "0", GOWORK: "off" };

async function discoverGo(tmp) {
  const MOD = join(homedir(), "go", "pkg", "mod");
  const mains = new Set();
  walk(MOD, (p) => {
    if (!p.endsWith(".go") || p.endsWith("_test.go") || /\/(testdata|internal|vendor|cache)\//.test(p)) return;
    if (/^package main\s*$/m.test(readFileSync(p, "utf8").slice(0, 4096))) mains.add(dirname(p));
  });
  const cands = [...mains].sort().map((dir) => {
    let m = dir;
    while (m !== MOD && !existsSync(join(m, "go.mod"))) m = dirname(m);
    return { dir, module: m };
  }).filter((c) => c.module !== MOD);
  console.error(`go: ${cands.length} main packages; building offline (linux/amd64)…`);
  const res = await pool(cands, 4, async (c, k) => {
    const out = join(tmp, `go-${k}`);
    const r = await run("go", ["build", "-o", out, `./${relative(c.module, c.dir)}`], { cwd: c.module, env: { ...process.env, ...GO_ENV, GOOS: "linux", GOARCH: "amd64" } });
    return r.ok ? { kind: "go", id: `go:${relative(MOD, c.dir)}`, module: relative(MOD, c.module), pkg: `./${relative(c.module, c.dir)}` } : null;
  });
  return res.filter(Boolean);
}

/** C libraries vendored in crates: [id, crate-dir glob prefix, library root inside the crate]. */
const C_LIBS = [
  ["c:zstd", "zstd-sys-", "zstd/lib"],
  ["c:quickjs", "rquickjs-sys-", "quickjs"],
  ["c:sqlite", "libsqlite3-sys-", "sqlite3"],
  ["c:freetype", "freetype-sys-", "freetype2/src"],
  ["c:ring", "ring-", "crypto"],
  ["c:libdbus", "libdbus-sys-", "vendor/dbus/dbus"],
  ["c:aws-lc", "aws-lc-sys-", "aws-lc/crypto"],
];
const C_SKIP_DIR = /\/(tests?|examples?|fuzz|programs|contrib|docs?|bench(mark)?s?|tools?|unix|win32|windows)\//i;

export function cSources(root) {
  const files = [];
  walk(root, (p) => {
    if (!p.endsWith(".c") || C_SKIP_DIR.test(`${p}`.slice(root.length))) return;
    const t = readFileSync(p, "latin1");
    if (/\bint\s+main\s*\(/.test(t)) return; // a program, not library code
    files.push(p);
  });
  return files;
}

export function cIncludes(crate) {
  const dirs = new Set();
  walk(crate, (p) => {
    if (p.endsWith(".h")) dirs.add(dirname(p));
  });
  return [...dirs].sort();
}

async function discoverC(tmp) {
  const REG = join(homedir(), ".cargo", "registry", "src");
  const idx = readdirSync(REG).map((d) => join(REG, d));
  const out = [];
  for (const [id, prefix, sub] of C_LIBS) {
    const crate = idx.flatMap((d) => readdirSync(d).filter((n) => n.startsWith(prefix) && /\d/.test(n.slice(prefix.length, prefix.length + 1))).map((n) => join(d, n))).sort().pop();
    if (!crate || !existsSync(join(crate, sub))) {
      console.error(`c: ${id} not found`);
      continue;
    }
    const root = join(crate, sub);
    const srcs = cSources(root);
    const inc = cIncludes(crate).flatMap((d) => ["-I", d]);
    const res = await pool(srcs, 6, (f, k) => run("clang", ["-c", "-O1", "-w", "-fPIC", ...inc, "-o", join(tmp, `${id.slice(2)}-${k}.o`), f], {}, 120_000));
    const ok = srcs.filter((_, k) => res[k].ok);
    console.error(`c: ${id}: ${ok.length}/${srcs.length} translation units compile`);
    if (ok.length >= 1) out.push({ kind: "c", id, crate: basename(crate), root: relative(crate, root), units: ok.map((f) => relative(crate, f)) });
  }
  return out;
}

async function discoverJs(tmp) {
  const NM = "/opt/homebrew/lib/node_modules/npm/node_modules";
  if (!existsSync(NM)) return [];
  const pkgs = readdirSync(NM).filter((n) => !n.startsWith(".")).flatMap((n) => (n.startsWith("@") ? readdirSync(join(NM, n)).map((s) => `${n}/${s}`) : [n])).sort();
  const esbuild = join(ROOT, "node_modules", ".bin", "esbuild");
  const res = await pool(pkgs, 6, async (name, k) => {
    const dir = join(NM, name);
    let main = "index.js";
    try {
      const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      main = typeof pj.main === "string" ? pj.main : main;
    } catch {
      return null;
    }
    const entry = [join(dir, main), join(dir, `${main}.js`), join(dir, main, "index.js")].find((p) => existsSync(p) && statSync(p).isFile());
    if (!entry) return null;
    const out = join(tmp, `js-${k}.js`);
    const r = await run(esbuild, [entry, "--bundle", "--platform=node", "--external:electron", "--log-level=error", `--outfile=${out}`], {}, 60_000);
    return r.ok && existsSync(out) && statSync(out).size >= 4096 ? { kind: "js", id: `js:${name}`, entry: relative(NM, entry) } : null;
  });
  return res.filter(Boolean);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const tmp = mkdtempSync(join(tmpdir(), "anti-rea-v7-subjects-"));
  const go = await discoverGo(tmp);
  const c = await discoverC(tmp);
  const js = await discoverJs(tmp);
  const all = [...go, ...c, ...js].map((s) => ({ ...s, set: split(s.id) }));
  const env = {
    go: spawnSync("go", ["version"], { encoding: "utf8" }).stdout.trim(),
    clang: spawnSync("clang", ["--version"], { encoding: "utf8" }).stdout.split("\n")[0],
    esbuild: spawnSync(join(ROOT, "node_modules", ".bin", "esbuild"), ["--version"], { encoding: "utf8" }).stdout.trim(),
    node: process.version,
  };
  const count = (k, s) => all.filter((x) => x.kind === k && x.set === s).length;
  writeFileSync(join(HERE, "subjects.json"), JSON.stringify({ schema: "anti-rea/bench-v7-subjects/v1", discoveredAt: new Date().toISOString(), toolchain: env, subjects: all }, null, 2) + "\n");
  console.error(`subjects: go ${count("go", "dev")} dev / ${count("go", "eval")} eval; c ${count("c", "dev")} / ${count("c", "eval")}; js ${count("js", "dev")} / ${count("js", "eval")}`);
}
