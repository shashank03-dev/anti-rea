#!/usr/bin/env node
// v7 corpus generator (PREREGISTRATION.md §4–5). Every case is ONE real build of real third-party code with a
// known toolchain configuration, packaged as releases ship it. Truth:
//   native (Go, C): the refcheck reference (Go stdlib parsers) run on the built bytes — construction is
//                   recorded beside it, and any disagreement is reported, never silently resolved;
//   js:             construction (the planted values are known exactly), plus a scan of the plain bundle for
//                   natural mentions of the probe strings.
//
//   node bench/v7/corpus.mjs --set dev|eval --out bench/runs/v7/<set>
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { frozenHash } from "./freeze.mjs";
import { GO_ENV, cIncludes } from "./subjects.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
export const DEV_SEED = 0x00c0ffee;
export const SIZES = { dev: { go: 16, c: 8, js: 16 }, eval: { go: 96, c: 48, js: 96 } };

function mulberry32(a) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const sh = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 1 << 28, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")}: ${(r.stderr || r.stdout || "").slice(-600)}`);
  return r.stdout;
};

let REFCHECK = null;
function refcheck(files) {
  REFCHECK ??= (() => {
    const out = join(ROOT, "bench", "runs", "v7", ".bin", "refcheck");
    mkdirSync(dirname(out), { recursive: true });
    sh("go", ["build", "-o", out, "."], { cwd: join(HERE, "refcheck"), env: { ...process.env, GOTOOLCHAIN: "local", GOFLAGS: "-mod=mod", GOPROXY: "off" } });
    return out;
  })();
  return sh(REFCHECK, files).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// ------------------------------------------------------------------ packaging

const ASAR = join(ROOT, "node_modules", "@electron", "asar", "bin", "asar.mjs");

/** Move `dir`'s content into `<parent>/<archiveName>` (zip or tar.gz) — the archive replaces the directory. */
function archive(dir, kind, archivePath) {
  mkdirSync(dirname(archivePath), { recursive: true });
  if (kind === "zip") sh("zip", ["-q", "-r", "-X", archivePath, "."], { cwd: dir });
  else sh("tar", ["--no-mac-metadata", "-czf", archivePath, "."], { cwd: dir, env: { ...process.env, COPYFILE_DISABLE: "1" } });
  rmSync(dir, { recursive: true, force: true });
}

// ------------------------------------------------------------------ go

const GOOS = [
  ["linux", "amd64", "elf"],
  ["windows", "amd64", "pe"],
  ["darwin", "arm64", "macho"],
];
const LDFLAGS = ["", "-w", "-s -w", "-s"];

function buildGo(subject, goos, goarch, ldflags, trimpath, cache) {
  const key = `${subject.id}|${goos}|${ldflags}|${trimpath}`.replace(/[^\w.|-]/g, "_");
  const out = join(cache, "go", key);
  if (existsSync(out)) return out;
  mkdirSync(dirname(out), { recursive: true });
  const mod = join(homedir(), "go", "pkg", "mod", subject.module);
  sh("go", ["build", ...(trimpath ? ["-trimpath"] : []), ...(ldflags ? [`-ldflags=${ldflags}`] : []), "-o", `${out}.tmp`, subject.pkg], { cwd: mod, env: { ...process.env, ...GO_ENV, GOOS: goos, GOARCH: goarch }, timeout: 600_000 });
  renameSync(`${out}.tmp`, out);
  return out;
}

function goCase(rand, subject, dir, cache) {
  const [goos, goarch, format] = GOOS[Math.floor(rand() * GOOS.length)];
  const ldflags = LDFLAGS[Math.floor(rand() * LDFLAGS.length)];
  const trimpath = rand() < 0.5;
  const packaging = ["direct", "zip", "tgz"][Math.floor(rand() * 3)];
  const bin = buildGo(subject, goos, goarch, ldflags, trimpath, cache);
  const name = (basename(subject.pkg) === "." ? basename(subject.module).replace(/@.*/, "") : basename(subject.pkg)) + (goos === "windows" ? ".exe" : "");
  const app = join(dir, "release", "App");
  const stage = packaging === "direct" ? join(app, "bin") : join(dir, "stage");
  mkdirSync(stage, { recursive: true });
  cpSync(bin, join(stage, name));
  if (packaging !== "direct") archive(stage, packaging, join(app, "updates", `${name}-update.${packaging === "zip" ? "zip" : "tar.gz"}`));
  const ref = refcheck([bin])[0];
  const construction = { dwarf: !/-w|-s/.test(ldflags), locals: !/-s/.test(ldflags) };
  return {
    family: "go",
    format,
    subject: subject.id,
    config: { goos, goarch, ldflags, trimpath, packaging },
    classes: ["dwarf", "locals"],
    truth: { dwarf: ref.dwarf, locals: ref.locals },
    construction,
    reference: ref,
  };
}

// ------------------------------------------------------------------ c (Mach-O dylib)

const STRIP = [[], ["-S"], ["-x"], ["-S", "-x"]];

function buildCObjects(subject, g, cache) {
  const dir = join(cache, "c", `${subject.id.slice(2)}-${g ? "g" : "nog"}`);
  if (existsSync(join(dir, ".done"))) return readdirSync(dir).filter((f) => f.endsWith(".o")).sort().map((f) => join(dir, f));
  mkdirSync(dir, { recursive: true });
  const REG = join(homedir(), ".cargo", "registry", "src");
  const crate = readdirSync(REG).map((d) => join(REG, d, subject.crate)).find((p) => existsSync(p));
  const inc = cIncludes(crate).flatMap((d) => ["-I", d]);
  const objs = [];
  subject.units.forEach((u, i) => {
    const o = join(dir, `${String(i).padStart(4, "0")}.o`);
    const r = spawnSync("clang", ["-c", "-O1", "-w", "-fPIC", ...(g ? ["-g"] : []), ...inc, "-o", o, join(crate, u)], { encoding: "utf8", timeout: 180_000 });
    if (r.status === 0) objs.push(o);
  });
  writeFileSync(join(dir, ".done"), String(objs.length));
  return objs;
}

function cCase(rand, subject, dir, cache) {
  const g = rand() < 0.6;
  const strip = STRIP[Math.floor(rand() * STRIP.length)];
  const shipDsym = g && rand() < 0.5;
  const packaging = ["direct", "zip", "tgz"][Math.floor(rand() * 3)];
  const name = `lib${subject.id.slice(2).replace(/[^\w]/g, "")}.dylib`;
  const work = join(dir, "work");
  mkdirSync(work, { recursive: true });
  const objs = buildCObjects(subject, g, cache);
  const dylib = join(work, name);
  const link = (o) => spawnSync("clang", ["-dynamiclib", "-undefined", "dynamic_lookup", "-Wl,-install_name,@rpath/" + name, "-o", dylib, ...o], { encoding: "utf8" });
  let linked = objs;
  if (link(objs).status !== 0) {
    // Duplicate definitions across translation units: fall back to the largest unit that links alone.
    linked = [...objs].sort((a, b) => statSync(b).size - statSync(a).size).filter((o) => link([o]).status === 0).slice(0, 1);
    if (linked.length === 0) throw new Error(`${subject.id}: nothing links`);
    link(linked);
  }
  const dsym = join(work, `${name}.dSYM`);
  if (shipDsym) sh("dsymutil", [dylib, "-o", dsym]);
  if (strip.length > 0) sh("strip", [...strip, dylib]);
  const ref = refcheck([dylib])[0];
  const dsymFile = shipDsym ? join(dsym, "Contents", "Resources", "DWARF", name) : null;
  const dref = dsymFile && existsSync(dsymFile) ? refcheck([dsymFile])[0] : null;

  const app = join(dir, "release", "App");
  const stage = packaging === "direct" ? join(app, "lib") : join(dir, "stage");
  mkdirSync(stage, { recursive: true });
  cpSync(dylib, join(stage, name));
  if (shipDsym) cpSync(dsym, join(stage, `${name}.dSYM`), { recursive: true });
  if (packaging !== "direct") archive(stage, packaging, join(app, "plugins", `${name}.${packaging === "zip" ? "zip" : "tar.gz"}`));
  rmSync(work, { recursive: true, force: true });
  return {
    family: "c",
    format: "macho",
    subject: subject.id,
    config: { g, strip: strip.join(" ") || "none", shipDsym, packaging, units: linked.length },
    classes: ["debugmap", "locals", "dsym"],
    truth: { debugmap: ref.debugmap, locals: ref.locals, dsym: !!dref?.dsym },
    construction: { debugmap: g && !strip.includes("-S"), locals: !strip.includes("-x"), dsym: shipDsym },
    reference: { dylib: ref, dsym: dref },
  };
}

// ------------------------------------------------------------------ js (Electron)

const MAPS = ["none", "external-sources", "external-names", "inline-sources", "inline-names", "reference-only"];
const INSECURE = [
  ["nodeIntegration", "true"],
  ["contextIsolation", "false"],
  ["sandbox", "false"],
  ["webSecurity", "false"],
  ["allowRunningInsecureContent", "true"],
];
const SECURE = { contextIsolation: "true", nodeIntegration: "false", sandbox: "true", webSecurity: "true" };
/** Natural mentions of the probe strings: present in documentation-like text, never an actual setting or call. */
const HARD_NEGATIVE = `
// Security note: never ship webPreferences: { nodeIntegration: true } or call win.webContents.openDevTools() in production.
const SECURITY_HELP = "Do not set nodeIntegration: true, contextIsolation: false or webSecurity: false; do not call openDevTools() in release builds.";
`;
const NM = "/opt/homebrew/lib/node_modules/npm/node_modules";

function jsCase(rand, subject, dir) {
  const map = MAPS[Math.floor(rand() * MAPS.length)];
  const minify = rand() < 0.5;
  const insecure = rand() < 0.5 ? INSECURE[Math.floor(rand() * INSECURE.length)] : null;
  const style = rand() < 0.25 ? "indirect" : "literal";
  const devtools = rand() < 0.4;
  const hardNegative = rand() < 0.25;
  const packaging = ["dir", "asar", "asar-in-zip"][Math.floor(rand() * 3)];

  const prefs = { ...SECURE, ...(insecure ? { [insecure[0]]: insecure[1] } : {}) };
  const prefLines =
    style === "literal"
      ? Object.entries(prefs).map(([k, v]) => `${k}: ${v}`).join(", ")
      : Object.keys(prefs).map((k) => `${k}: SECURITY.${k}`).join(", ");
  const entryDir = join(dir, "src");
  mkdirSync(entryDir, { recursive: true });
  writeFileSync(
    join(entryDir, "main.js"),
    [
      `const path = require("path");`,
      `const { app, BrowserWindow } = require("electron");`,
      `const lib = require(${JSON.stringify(join(NM, subject.entry))});`,
      hardNegative ? HARD_NEGATIVE : "",
      style === "indirect" ? `const SECURITY = { ${Object.entries(prefs).map(([k, v]) => `${k}: ${v}`).join(", ")} };` : "",
      `function createWindow() {`,
      `  const win = new BrowserWindow({ width: 1200, height: 800, webPreferences: { preload: path.join(__dirname, "preload.js"), ${prefLines} } });`,
      `  win.loadFile("index.html");`,
      devtools ? `  win.webContents.openDevTools();` : "",
      `  return lib;`,
      `}`,
      `app.whenReady().then(createWindow);`,
      ``,
    ].join("\n"),
  );
  const esbuild = join(ROOT, "node_modules", ".bin", "esbuild");
  const app = packaging === "dir" ? join(dir, "release", "App", "resources", "app") : join(dir, "stage-app");
  mkdirSync(app, { recursive: true });
  const flags = ["--bundle", "--platform=node", "--external:electron", "--log-level=error", `--outfile=${join(app, "main.js")}`, ...(minify ? ["--minify"] : [])];
  if (map === "external-sources" || map === "reference-only") flags.push("--sourcemap");
  if (map === "external-names") flags.push("--sourcemap", "--sources-content=false");
  if (map === "inline-sources") flags.push("--sourcemap=inline");
  if (map === "inline-names") flags.push("--sourcemap=inline", "--sources-content=false");
  sh(esbuild, [join(entryDir, "main.js"), ...flags]);
  if (map === "reference-only") rmSync(join(app, "main.js.map"), { force: true });
  writeFileSync(join(app, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", main: "main.js" }));
  writeFileSync(join(app, "index.html"), "<!doctype html><title>App</title>\n");

  // Natural mentions in the subject's own code (recorded; truth stays construction-defined).
  const plain = readFileSync(join(app, "main.js"), "utf8").replace(/\/\/# sourceMappingURL=.*$/m, "");
  const natural = { inlineMapComment: /^[ \t]*\/\/[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*data:/m.test(plain), devtoolsText: /openDevTools\s*\(/.test(plain.replace(HARD_NEGATIVE, "")) && !devtools };

  if (packaging !== "dir") {
    const resources = join(dir, packaging === "asar" ? join("release", "App", "resources") : "stage-zip");
    mkdirSync(resources, { recursive: true });
    sh(process.execPath, [ASAR, "pack", app, join(resources, "app.asar")]);
    rmSync(app, { recursive: true, force: true });
    if (packaging === "asar-in-zip") archive(resources, "zip", join(dir, "release", "App", "updates", "app-update.zip"));
  }
  rmSync(entryDir, { recursive: true, force: true });
  const shipped = map !== "none" && map !== "reference-only";
  return {
    family: "js",
    format: "js",
    subject: subject.id,
    config: { map, minify, insecure: insecure ? `${insecure[0]}: ${insecure[1]}` : null, style, devtools, hardNegative, packaging },
    classes: ["map", "webprefs", "devtools"],
    truth: { map: shipped, webprefs: insecure !== null, devtools },
    construction: { map: shipped, mapWithSources: map.endsWith("-sources"), webprefs: insecure !== null, devtools },
    natural,
  };
}

// ------------------------------------------------------------------ main

export function seedFor(set) {
  return set === "eval" ? parseInt(frozenHash().slice(0, 8), 16) : DEV_SEED;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const set = args[args.indexOf("--set") + 1];
  if (set !== "dev" && set !== "eval") throw new Error("--set dev|eval");
  const out = args.includes("--out") ? args[args.indexOf("--out") + 1] : join(ROOT, "bench", "runs", "v7", set);
  const seed = seedFor(set);
  const rand = mulberry32(seed);
  const subjects = JSON.parse(readFileSync(join(HERE, "subjects.json"), "utf8")).subjects.filter((s) => s.set === set);
  const byKind = (k) => subjects.filter((s) => s.kind === k);
  const cache = join(ROOT, "bench", "runs", "v7", ".cache");
  rmSync(join(out, "cases"), { recursive: true, force: true });
  const plan = [...Array(SIZES[set].go).fill("go"), ...Array(SIZES[set].c).fill("c"), ...Array(SIZES[set].js).fill("js")];
  const index = { schema: "anti-rea/bench-v7-corpus/v1", set, seed, cases: [] };
  plan.forEach((kind, i) => {
    const pool = byKind(kind);
    const subject = pool[Math.floor(rand() * pool.length)];
    const id = String(i).padStart(3, "0");
    const dir = join(out, "cases", id);
    mkdirSync(dir, { recursive: true });
    const t0 = Date.now();
    let c;
    try {
      c = kind === "go" ? goCase(rand, subject, dir, cache) : kind === "c" ? cCase(rand, subject, dir, cache) : jsCase(rand, subject, dir);
    } catch (e) {
      // A build failure is recorded and the case excluded (rule §5.4): it never becomes a silent pass.
      c = { family: kind, subject: subject.id, excluded: `build failed: ${e.message.slice(0, 400)}` };
    }
    for (const d of ["stage", "stage-app", "stage-zip", "work"]) rmSync(join(dir, d), { recursive: true, force: true });
    writeFileSync(join(dir, "truth.json"), JSON.stringify({ id, ...c }, null, 2) + "\n");
    index.cases.push({ id, family: kind, subject: subject.id, excluded: c.excluded ?? null });
    console.error(`${set} ${id} ${kind} ${subject.id} ${c.excluded ? "EXCLUDED " + c.excluded.slice(0, 120) : JSON.stringify(c.config)} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  });
  writeFileSync(join(out, "index.json"), JSON.stringify(index, null, 2) + "\n");
  console.error(`${set}: ${index.cases.length} cases, ${index.cases.filter((c) => c.excluded).length} excluded, seed 0x${seed.toString(16)}`);
}
