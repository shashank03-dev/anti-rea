#!/usr/bin/env node
// v7 POST-HOC analysis (not pre-registered; written after the eval run, and labelled as such everywhere).
//
// Defect found after the run: subject discovery accepted directories whose only `package main` file is a
// `//go:build ignore` code generator inside a LIBRARY package. `go build -o` on such a directory writes a Go
// package archive (`!<arch>`), not an executable. Those cases test nothing: both systems are trivially right.
// This analysis drops every Go case whose built artifact the reference did not recognise as ELF, PE or Mach-O,
// and recomputes the registered metrics with the registered code paths' definitions.
//   node bench/v7/posthoc.mjs   → bench/v7/RESULTS-eval.posthoc.json
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { clopperPearson, mcnemar } from "./score.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const dir = join(HERE, "..", "runs", "v7", "eval");
const index = JSON.parse(readFileSync(join(dir, "index.json"), "utf8"));
const dec = new Map(JSON.parse(readFileSync(join(dir, "decisions.json"), "utf8")).cases.map((c) => [c.id, c]));

const dropped = [];
const units = [];
for (const c of index.cases) {
  const t = JSON.parse(readFileSync(join(dir, "cases", c.id, "truth.json"), "utf8"));
  if (t.excluded) continue;
  if (t.family === "go" && t.reference.format === "other") {
    dropped.push({ id: t.id, subject: t.subject });
    continue;
  }
  const d = dec.get(c.id);
  for (const k of t.classes) units.push({ family: t.family, cls: k, truth: t.truth[k], ar: d.ar[k], bl: d.bl[k], config: t.config });
}

const acc = (us, who) => {
  const k = us.filter((u) => u[who] === u.truth).length;
  return { k, n: us.length, rate: k / us.length, ci: clopperPearson(k, us.length) };
};
const neg = units.filter((u) => !u.truth);
const fp = (who) => ({ fp: neg.filter((u) => u[who]).length, n: neg.length, ci: clopperPearson(neg.filter((u) => u[who]).length, neg.length) });
const b = units.filter((u) => u.ar === u.truth && u.bl !== u.truth).length;
const c = units.filter((u) => u.ar !== u.truth && u.bl === u.truth).length;
const fam = (f) => ({ ar: acc(units.filter((u) => u.family === f), "ar"), bl: acc(units.filter((u) => u.family === f), "bl") });
const direct = units.filter((u) => !(u.cls === "webprefs" && u.truth && u.config.style === "indirect"));

const out = {
  schema: "anti-rea/bench-v7-posthoc/v1",
  note: "POST-HOC, not pre-registered. Drops Go cases whose artifact is a Go package archive, not an executable (a subject-discovery defect found after the run).",
  droppedCases: dropped.length,
  droppedSubjects: [...new Set(dropped.map((d) => d.subject))].sort(),
  units: units.length,
  overall: { ar: acc(units, "ar"), bl: acc(units, "bl") },
  falsePositives: { ar: fp("ar"), bl: fp("bl") },
  mcnemar: { b, c, p: mcnemar(b, c) },
  families: { go: fam("go"), c: fam("c"), js: fam("js") },
  goExecutables: units.filter((u) => u.family === "go").length / 2,
  withinDocumentedScope: { note: "excludes the 19 indirect webPreferences units (P1: outside the documented literal-object scope)", ar: acc(direct, "ar"), bl: acc(direct, "bl") },
};
writeFileSync(join(HERE, "RESULTS-eval.posthoc.json"), JSON.stringify(out, null, 2) + "\n");
const p = (x) => `${(100 * x.rate).toFixed(1)}% (${x.k}/${x.n}) [${(100 * x.ci[0]).toFixed(1)}, ${(100 * x.ci[1]).toFixed(1)}]`;
console.log(`dropped ${dropped.length} non-executable Go cases; ${units.length} units remain`);
console.log(`AR ${p(out.overall.ar)}   BL ${p(out.overall.bl)}   McNemar b=${b} c=${c} p=${out.mcnemar.p.toPrecision(3)}`);
console.log(`false positives: AR ${out.falsePositives.ar.fp}/${out.falsePositives.ar.n} (95% CI upper ${(100 * out.falsePositives.ar.ci[1]).toFixed(2)}%), BL ${out.falsePositives.bl.fp}/${out.falsePositives.bl.n}`);
for (const f of ["go", "c", "js"]) console.log(`${f}: AR ${p(out.families[f].ar)}  BL ${p(out.families[f].bl)}`);
console.log(`go executables kept: ${out.goExecutables}`);
console.log(`within documented scope: AR ${p(out.withinDocumentedScope.ar)}  BL ${p(out.withinDocumentedScope.bl)}`);
