#!/usr/bin/env node
// v7 runner: AR (anti-rea expose, as shipped) and BL (the checklist baseline) on every non-excluded case.
//   node bench/v7/run.mjs --set dev|eval
// Eval refuses to run unless the tree matches PREREGISTRATION.md's frozen hash and the corpus seed was
// derived from it.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { frozenHash } from "./freeze.mjs";
import { baseline } from "./baseline.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

/** Finding title → class (PREREGISTRATION.md §3.2). */
export function arClasses(findings) {
  const t = findings.map((f) => f.title);
  const any = (p) => t.some(p);
  return {
    dwarf: any((x) => x === "Embedded DWARF debug information"),
    locals: any((x) => x === "Unstripped local symbol names" || x === "Unstripped .symtab with local symbols" || x === "COFF symbol table shipped"),
    debugmap: any((x) => x.startsWith("Debug map (stabs)")),
    dsym: any((x) => x === "dSYM debug companion shipped"),
    map: any((x) => /^(Inline )?[Ss]ource map (ships the original source|restores original names and layout)$/.test(x)),
    mapWithSources: any((x) => /^(Inline )?[Ss]ource map ships the original source$/.test(x)),
    webprefs: any((x) => x.startsWith("Insecure Electron webPreferences")),
    devtools: any((x) => x === "Electron DevTools opened from shipped code"),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const set = args[args.indexOf("--set") + 1];
  if (set !== "dev" && set !== "eval") throw new Error("--set dev|eval");
  const dir = join(ROOT, "bench", "runs", "v7", set);
  const index = JSON.parse(readFileSync(join(dir, "index.json"), "utf8"));
  if (set === "eval") {
    const prereg = readFileSync(join(HERE, "PREREGISTRATION.md"), "utf8");
    const m = prereg.match(/frozen-sha256:\s*`?([0-9a-f]{64})`?/);
    const now = frozenHash();
    if (!m || m[1] !== now) throw new Error(`refusing to run eval: tree hash ${now} does not match the pre-registered ${m?.[1] ?? "(none)"}`);
    if (index.seed !== parseInt(now.slice(0, 8), 16)) throw new Error(`refusing to run eval: corpus seed ${index.seed} was not derived from the frozen hash`);
  }
  const b = spawnSync("npx", ["tsc", "-p", "tsconfig.json"], { cwd: ROOT, encoding: "utf8" });
  if (b.status !== 0) throw new Error(`build failed: ${b.stdout}${b.stderr}`);
  const cli = join(ROOT, "build", "src", "cli.js");
  const out = { schema: "anti-rea/bench-v7-decisions/v1", set, frozenSha256: frozenHash(), node: process.version, startedAt: new Date().toISOString(), cases: [] };
  for (const c of index.cases) {
    if (c.excluded) continue;
    const cdir = join(dir, "cases", c.id);
    const t0 = Date.now();
    const r = spawnSync(process.execPath, [cli, "expose", join(cdir, "release"), "--json", "--include-third-party"], { encoding: "utf8", maxBuffer: 1 << 28 });
    const arMs = Date.now() - t0;
    if (r.status !== 0) {
      out.cases.push({ id: c.id, error: `anti-rea exit ${r.status}: ${r.stderr.slice(-400)}` });
      continue;
    }
    const report = JSON.parse(r.stdout);
    const t1 = Date.now();
    const bl = baseline(join(cdir, "release"));
    out.cases.push({
      id: c.id,
      ar: arClasses(report.findings),
      bl,
      arMs,
      blMs: Date.now() - t1,
      arTitles: [...new Set(report.findings.map((f) => f.title))].sort(),
      opaque: report.coverage.opaque,
    });
    process.stderr.write(".");
  }
  out.finishedAt = new Date().toISOString();
  writeFileSync(join(dir, "decisions.json"), JSON.stringify(out, null, 2) + "\n");
  console.error(`\n${set}: ${out.cases.length} cases run (${out.cases.filter((c) => c.error).length} errors)`);
}
