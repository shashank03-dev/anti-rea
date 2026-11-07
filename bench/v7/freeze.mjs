#!/usr/bin/env node
// v7 frozen hash: everything that can influence the exposure benchmark's results — the tool's source, the
// package manifest, the subject pool and the whole v7 harness (generator, reference checker, baseline,
// runner, scorer). PREREGISTRATION.md records it; the eval seed is its first 32 bits, and bench/v7/run.mjs
// refuses to run eval on any other tree.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const INCLUDE = [
  "src",
  "package.json",
  "bench/v7/freeze.mjs",
  "bench/v7/subjects.mjs",
  "bench/v7/subjects.json",
  "bench/v7/corpus.mjs",
  "bench/v7/baseline.mjs",
  "bench/v7/run.mjs",
  "bench/v7/score.mjs",
  "bench/v7/refcheck/main.go",
  "bench/v7/refcheck/go.mod",
];

export function frozenFiles() {
  const out = [];
  const walk = (p) => {
    const st = statSync(p);
    if (st.isDirectory()) for (const n of readdirSync(p).sort()) walk(join(p, n));
    else out.push(p);
  };
  for (const i of INCLUDE) walk(join(ROOT, i));
  return out.sort();
}

export function frozenHash() {
  const h = createHash("sha256");
  for (const f of frozenFiles()) h.update(`${relative(ROOT, f).split("\\").join("/")}\0${createHash("sha256").update(readFileSync(f)).digest("hex")}\n`);
  return h.digest("hex");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(frozenHash());
