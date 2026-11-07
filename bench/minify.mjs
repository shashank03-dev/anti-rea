#!/usr/bin/env node
/**
 * Minification classifier benchmark (v0.7). Labelled corpus:
 *   readable     — real hand-written / tsc-emitted JavaScript (npm's own installed tree)
 *   whitespace   — the same file through esbuild { minifyWhitespace, minifySyntax } (names kept)
 *   mangled      — the same file through esbuild { minify: true, format: "cjs" } (names mangled)
 * Files are split by sha256(path): first hex digit even → dev (thresholds chosen), odd → eval (reported once).
 * Usage: node bench/minify.mjs [dev|eval|both] [--dump]
 *
 * Held-out mode (round 2, pre-registered before its single run):
 *   MINIFY_CORPUS=<tree> node bench/minify.mjs heldout
 * A third-party tree mixes readable and pre-minified files, so originals are labelled by an independent
 * oracle: readable if esbuild's full minify shrinks them below 60% of their size; dropped above 85%
 * (already minified) and in between (ambiguous). Variants keep their construction labels. 600 files are
 * sampled deterministically (lowest sha256(relative path)).
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { transformSync } from "esbuild";
import { jsShape, minifyVerdict, MINIFY_THRESHOLDS } from "../build/src/lanes/aids.js";

const ROOT = process.env.MINIFY_CORPUS ?? "/opt/homebrew/lib/node_modules/npm";
const split = process.argv[2] ?? "both";
const files = [];
(function walk(d) {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.(c|m)?js$/.test(n) && !/\.min\.js$/.test(n) && st.size >= 2048 && st.size <= 2_000_000) files.push(p);
  }
})(ROOT);
files.sort();
const HELDOUT = split === "heldout";
if (HELDOUT) {
  const key = (p) => createHash("sha256").update(p.slice(ROOT.length)).digest("hex");
  files.sort((a, b) => (key(a) < key(b) ? -1 : 1));
  files.splice(600);
}
const half = (p) => HELDOUT ? "heldout" : (parseInt(createHash("sha256").update(p.slice(ROOT.length)).digest("hex")[0], 16) % 2 === 0 ? "dev" : "eval");
const rows = [];
for (const f of files) {
  const h = half(f);
  if (!HELDOUT && split !== "both" && h !== split) continue;
  const src = readFileSync(f, "utf8");
  let ws, mg;
  try {
    ws = transformSync(src, { minifyWhitespace: true, minifySyntax: true, format: "cjs", logLevel: "silent" }).code;
    mg = transformSync(src, { minify: true, format: "cjs", logLevel: "silent" }).code;
  } catch {
    continue; // not parseable by esbuild (e.g. syntax it rejects): excluded from both halves
  }
  const ratio = mg.length / Math.max(1, src.length);
  const variants = [["whitespace", ws], ["mangled", mg]];
  if (!HELDOUT || ratio < 0.6) variants.unshift(["readable", src]);
  for (const [label, text] of variants) rows.push({ file: f.slice(ROOT.length), half: h, label, ...jsShape(text) });
}
// Expected verdicts: level "whitespace" passes whitespace+mangled; level "identifiers" passes only mangled.
const want = { whitespace: { readable: false, whitespace: true, mangled: true }, identifiers: { readable: false, whitespace: false, mangled: true } };
const out = { thresholds: MINIFY_THRESHOLDS, corpus: ROOT, files: new Set(rows.map((r) => r.file)).size, halves: {} };
for (const h of HELDOUT ? ["heldout"] : ["dev", "eval"]) {
  const hr = rows.filter((r) => r.half === h);
  if (hr.length === 0) continue;
  const res = {};
  for (const level of ["whitespace", "identifiers"]) {
    let correct = 0, judged = 0, abstain = 0;
    const confusion = {};
    for (const r of hr) {
      const v = minifyVerdict(r, level).ok;
      if (v === null) { abstain++; continue; }
      judged++;
      const ok = v === want[level][r.label];
      if (ok) correct++;
      const k = `${r.label}->${v ? "pass" : "flag"}`;
      confusion[k] = (confusion[k] ?? 0) + 1;
    }
    res[level] = { judged, correct, accuracy: +(correct / judged).toFixed(4), abstained: abstain, confusion };
  }
  out.halves[h] = { samples: hr.length, ...res };
}
console.log(JSON.stringify(out, null, 2));
if (process.argv.includes("--dump")) writeFileSync("build/minify-rows.json", JSON.stringify(rows));
