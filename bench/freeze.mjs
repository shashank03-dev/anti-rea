#!/usr/bin/env node
// Content hash of everything that can influence benchmark results: the tool's
// source, its policy, and the benchmark harness itself. The pre-registration
// records this value; bench/run.mjs refuses to run the evaluation set if the
// current tree does not match it.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const INCLUDE = ["src", "bench/freeze.mjs", "bench/corpus.mjs", "bench/run.mjs", "bench/score.mjs", "bench/policy.json", "bench/policy.open.json", "package.json", "bench/v4/anti-rea-0.4.0"];

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
  for (const f of frozenFiles()) h.update(`${relative(ROOT, f)}\0${createHash("sha256").update(readFileSync(f)).digest("hex")}\n`);
  return h.digest("hex");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(frozenHash());
