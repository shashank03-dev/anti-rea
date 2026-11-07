#!/usr/bin/env node
// v7 scorer (PREREGISTRATION.md §6–7). Unit of analysis: one (case, class) decision against the truth.
// Exact Clopper–Pearson 95% intervals, exact two-sided McNemar test, hypotheses evaluated mechanically.
//   node bench/v7/score.mjs --set dev|eval   → bench/runs/v7/<set>/RESULTS.md + summary.json
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

// ---------------------------------------------------------------- exact statistics

function logChoose(n, k) {
  let s = 0;
  for (let i = 1; i <= k; i++) s += Math.log(n - k + i) - Math.log(i);
  return s;
}
function binomCdf(k, n, p) {
  if (k < 0) return 0;
  if (k >= n) return 1;
  let s = 0;
  for (let i = 0; i <= k; i++) s += Math.exp(logChoose(n, i) + i * Math.log(p) + (n - i) * Math.log1p(-p));
  return Math.min(1, s);
}
/** Exact (Clopper–Pearson) two-sided 95% interval for k successes in n. */
export function clopperPearson(k, n, alpha = 0.05) {
  if (n === 0) return [0, 1];
  const solve = (f) => {
    let lo = 0;
    let hi = 1;
    for (let i = 0; i < 80; i++) {
      const mid = (lo + hi) / 2;
      if (f(mid)) hi = mid;
      else lo = mid;
    }
    return (lo + hi) / 2;
  };
  const lower = k === 0 ? 0 : solve((p) => 1 - binomCdf(k - 1, n, p) >= alpha / 2);
  const upper = k === n ? 1 : solve((p) => binomCdf(k, n, p) <= alpha / 2);
  return [lower, upper];
}
/** Exact two-sided McNemar: b = AR right & BL wrong, c = AR wrong & BL right. */
export function mcnemar(b, c) {
  const n = b + c;
  if (n === 0) return 1;
  const k = Math.min(b, c);
  return Math.min(1, 2 * binomCdf(k, n, 0.5));
}

const pct = (x) => `${(100 * x).toFixed(1)}%`;
const ci = ([a, b]) => `[${(100 * a).toFixed(1)}, ${(100 * b).toFixed(1)}]`;

// ---------------------------------------------------------------- scoring

export function score(set) {
  const dir = join(ROOT, "bench", "runs", "v7", set);
  const index = JSON.parse(readFileSync(join(dir, "index.json"), "utf8"));
  const decisions = JSON.parse(readFileSync(join(dir, "decisions.json"), "utf8"));
  const dec = new Map(decisions.cases.map((c) => [c.id, c]));
  const units = [];
  const cases = [];
  for (const c of index.cases) {
    const truth = JSON.parse(readFileSync(join(dir, "cases", c.id, "truth.json"), "utf8"));
    cases.push(truth);
    if (truth.excluded) continue;
    const d = dec.get(c.id);
    if (!d || d.error) {
      // A tool error on a case counts as WRONG for every class of that case (§6.3): never dropped.
      for (const k of truth.classes) units.push({ id: c.id, family: truth.family, format: truth.format, cls: k, truth: truth.truth[k], ar: !truth.truth[k], bl: d?.bl?.[k] ?? !truth.truth[k], config: truth.config, error: true });
      continue;
    }
    for (const k of truth.classes) units.push({ id: c.id, family: truth.family, format: truth.format, cls: k, truth: truth.truth[k], ar: d.ar[k], bl: d.bl[k], config: truth.config, arMapWithSources: d.ar.mapWithSources, mapWithSources: truth.construction.mapWithSources });
  }

  const acc = (us, who) => {
    const k = us.filter((u) => u[who] === u.truth).length;
    return { k, n: us.length, rate: us.length ? k / us.length : NaN, ci: clopperPearson(k, us.length) };
  };
  const conf = (us, who) => {
    const tp = us.filter((u) => u.truth && u[who]).length;
    const fn = us.filter((u) => u.truth && !u[who]).length;
    const tn = us.filter((u) => !u.truth && !u[who]).length;
    const fp = us.filter((u) => !u.truth && u[who]).length;
    return { tp, fn, tn, fp, recall: tp + fn ? tp / (tp + fn) : NaN, specificity: tn + fp ? tn / (tn + fp) : NaN, fpr: tn + fp ? fp / (tn + fp) : NaN, fprCi: clopperPearson(fp, tn + fp) };
  };
  const b = units.filter((u) => u.ar === u.truth && u.bl !== u.truth).length;
  const c = units.filter((u) => u.ar !== u.truth && u.bl === u.truth).length;

  const CLASSES = ["dwarf", "locals", "debugmap", "dsym", "map", "webprefs", "devtools"];
  const perClass = Object.fromEntries(CLASSES.map((k) => [k, { ar: conf(units.filter((u) => u.cls === k), "ar"), bl: conf(units.filter((u) => u.cls === k), "bl"), n: units.filter((u) => u.cls === k).length }]).filter(([, v]) => v.n > 0));
  const native = units.filter((u) => u.family !== "js");
  const strata = {};
  const add = (name, pred) => {
    const us = units.filter(pred);
    if (us.length) strata[name] = { n: us.length, ar: acc(us, "ar"), bl: acc(us, "bl") };
  };
  for (const f of ["go", "c", "js"]) add(`family=${f}`, (u) => u.family === f);
  for (const f of ["elf", "pe", "macho"]) add(`go format=${f}`, (u) => u.family === "go" && u.format === f);
  for (const p of ["direct", "zip", "tgz", "dir", "asar", "asar-in-zip"]) add(`packaging=${p}`, (u) => u.config?.packaging === p);
  add("webprefs insecure, literal, not minified", (u) => u.cls === "webprefs" && u.truth && u.config.style === "literal" && !u.config.minify);
  add("webprefs insecure, literal, minified (!0/!1)", (u) => u.cls === "webprefs" && u.truth && u.config.style === "literal" && u.config.minify);
  add("webprefs insecure, indirect (P1: out of scope)", (u) => u.cls === "webprefs" && u.truth && u.config.style === "indirect");
  add("hard-negative mentions (webprefs+devtools negatives)", (u) => (u.cls === "webprefs" || u.cls === "devtools") && !u.truth && u.config.hardNegative);
  add("map=reference-only (comment, map not shipped)", (u) => u.cls === "map" && u.config.map === "reference-only");
  for (const m of ["external-sources", "external-names", "inline-sources", "inline-names", "none"]) add(`map=${m}`, (u) => u.cls === "map" && u.config.map === m);

  // Secondary (§6.4): on shipped maps, does AR's grade match whether sourcesContent ships?
  const shipped = units.filter((u) => u.cls === "map" && u.truth && u.ar);
  const grade = { n: shipped.length, k: shipped.filter((u) => u.arMapWithSources === u.mapWithSources).length };

  const overall = { ar: acc(units, "ar"), bl: acc(units, "bl") };
  const negatives = units.filter((u) => !u.truth);
  const fpr = { ar: conf(negatives, "ar"), bl: conf(negatives, "bl") };
  const nativeAcc = { ar: acc(native, "ar"), bl: acc(native, "bl") };
  const disagreements = cases.filter((t) => !t.excluded && t.construction && t.classes.some((k) => k in t.construction && t.construction[k] !== t.truth[k])).map((t) => ({ id: t.id, subject: t.subject, config: t.config, construction: t.construction, truth: t.truth }));

  const recallOk = Object.entries(perClass).every(([k, v]) => {
    const us = units.filter((u) => u.cls === k && u.truth && !(k === "webprefs" && u.config.style === "indirect"));
    const r = us.length ? us.filter((u) => u.ar).length / us.length : 1;
    return r >= 0.9 && (Number.isNaN(v.ar.specificity) || v.ar.specificity >= 0.95);
  });
  const hypotheses = {
    H1: { claim: "AR overall accuracy ≥ 95% and exact 95% CI lower bound ≥ 93%", supported: overall.ar.rate >= 0.95 && overall.ar.ci[0] >= 0.93 },
    H2: { claim: "AR false-positive rate on truth-negative units ≤ 2%", supported: fpr.ar.fpr <= 0.02 },
    H3: { claim: "AR accuracy > BL accuracy, exact McNemar p < 0.01", supported: overall.ar.rate > overall.bl.rate && mcnemar(b, c) < 0.01 },
    H4: { claim: "On native units (Go + C), AR agrees with the reference on ≥ 99%", supported: nativeAcc.ar.rate >= 0.99 },
    H5: { claim: "Every class: AR recall ≥ 90% (indirect webPreferences excluded, P1) and specificity ≥ 95%", supported: recallOk },
  };
  return { set, frozenSha256: decisions.frozenSha256, cases: { total: index.cases.length, excluded: cases.filter((t) => t.excluded).length, errors: decisions.cases.filter((d) => d.error).length }, units: units.length, overall, fpr, nativeAcc, mcnemar: { b, c, p: mcnemar(b, c) }, perClass, strata, grade, hypotheses, disagreements, excludedCases: cases.filter((t) => t.excluded).map((t) => ({ id: t.id, subject: t.subject, reason: t.excluded })), errors: units.filter((u) => u.ar !== u.truth).map((u) => ({ id: u.id, cls: u.cls, truth: u.truth, ar: u.ar, family: u.family, format: u.format, config: u.config })) };
}

export function render(s) {
  const L = [];
  L.push(`# v7 exposure benchmark — ${s.set} results`, "");
  L.push(`Frozen tree: \`${s.frozenSha256}\`. Cases: ${s.cases.total} generated, ${s.cases.excluded} excluded (build failures, §5.4), ${s.cases.errors} tool errors (scored wrong). Units (case × class): **${s.units}**.`, "");
  L.push("| | Accuracy | 95% CI | False-positive rate |", "|---|---|---|---|");
  L.push(`| **AR** (anti-rea expose) | **${pct(s.overall.ar.rate)}** (${s.overall.ar.k}/${s.overall.ar.n}) | ${ci(s.overall.ar.ci)} | ${pct(s.fpr.ar.fpr)} (${s.fpr.ar.fp}/${s.fpr.ar.fp + s.fpr.ar.tn}) |`);
  L.push(`| BL (checklist baseline) | ${pct(s.overall.bl.rate)} (${s.overall.bl.k}/${s.overall.bl.n}) | ${ci(s.overall.bl.ci)} | ${pct(s.fpr.bl.fpr)} (${s.fpr.bl.fp}/${s.fpr.bl.fp + s.fpr.bl.tn}) |`, "");
  L.push(`McNemar (exact, two-sided): AR right/BL wrong = ${s.mcnemar.b}, AR wrong/BL right = ${s.mcnemar.c}, p = ${s.mcnemar.p.toPrecision(3)}.`, "");
  L.push("## Hypotheses (evaluated mechanically)", "", "| | Claim | Result |", "|---|---|---|");
  for (const [k, h] of Object.entries(s.hypotheses)) L.push(`| ${k} | ${h.claim} | ${h.supported ? "**supported**" : "**not supported**"} |`);
  L.push("", "## Per class", "", "| Class | Units | AR recall | AR specificity | BL recall | BL specificity |", "|---|---|---|---|---|---|");
  for (const [k, v] of Object.entries(s.perClass)) L.push(`| ${k} | ${v.n} | ${pct(v.ar.recall)} (${v.ar.tp}/${v.ar.tp + v.ar.fn}) | ${pct(v.ar.specificity)} (${v.ar.tn}/${v.ar.tn + v.ar.fp}) | ${pct(v.bl.recall)} | ${pct(v.bl.specificity)} |`);
  L.push("", "## Strata", "", "| Stratum | Units | AR | BL |", "|---|---|---|---|");
  for (const [k, v] of Object.entries(s.strata)) L.push(`| ${k} | ${v.n} | ${pct(v.ar.rate)} | ${pct(v.bl.rate)} |`);
  L.push("", `Secondary (§6.4): on shipped maps AR detected, its grade matched whether \`sourcesContent\` ships on ${s.grade.k}/${s.grade.n}.`, "");
  L.push(`## Construction vs reference`, "", s.disagreements.length ? `${s.disagreements.length} case(s) where the toolchain did not do what its flags suggest; truth follows the reference (§3.1):` : "None.", "");
  for (const d of s.disagreements.slice(0, 30)) L.push(`- ${d.id} ${d.subject} ${JSON.stringify(d.config)}: construction ${JSON.stringify(d.construction)} vs reference ${JSON.stringify(d.truth)}`);
  L.push("", "## Every AR error", "");
  if (s.errors.length === 0) L.push("None.");
  for (const e of s.errors) L.push(`- ${e.id} ${e.family}/${e.format} **${e.cls}** truth=${e.truth} AR=${e.ar} ${JSON.stringify(e.config)}`);
  if (s.excludedCases.length) {
    L.push("", "## Excluded cases (build failures)", "");
    for (const e of s.excludedCases) L.push(`- ${e.id} ${e.subject}: ${e.reason.slice(0, 200)}`);
  }
  return L.join("\n") + "\n";
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const set = args[args.indexOf("--set") + 1];
  const s = score(set);
  const dir = join(ROOT, "bench", "runs", "v7", set);
  writeFileSync(join(dir, "summary.json"), JSON.stringify(s, null, 2) + "\n");
  writeFileSync(join(dir, "RESULTS.md"), render(s));
  process.stdout.write(render(s));
}
