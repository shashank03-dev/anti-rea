#!/usr/bin/env node
// Scores bench/runs/<set>/results.jsonl against ground truth and evaluates the
// pre-registered hypotheses mechanically (no judgement calls after the fact).
//
//   node bench/score.mjs --set dev|eval
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALPHA = 0.05;
const BASELINES = ["GL-D", "GL-T", "TH-D", "TH-T", "DS-D"];

// ---------------------------------------------------------------- exact statistics
function logGamma(z) {
  const g = 7;
  const c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (z < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * z)) - logGamma(1 - z);
  z -= 1;
  let x = c[0];
  for (let i = 1; i < g + 2; i++) x += c[i] / (z + i);
  const t = z + g + 0.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}
const logChoose = (n, k) => logGamma(n + 1) - logGamma(k + 1) - logGamma(n - k + 1);
function binomCdf(k, n, p) {
  if (k < 0) return 0;
  if (k >= n) return 1;
  if (p <= 0) return 1;
  if (p >= 1) return 0;
  let s = 0;
  for (let i = 0; i <= k; i++) s += Math.exp(logChoose(n, i) + i * Math.log(p) + (n - i) * Math.log(1 - p));
  return Math.min(1, s);
}
function bisect(f, lo = 0, hi = 1) {
  for (let i = 0; i < 100; i++) {
    const m = (lo + hi) / 2;
    if (f(m)) hi = m;
    else lo = m;
  }
  return (lo + hi) / 2;
}
/** Exact Clopper–Pearson interval for x successes in n trials. */
export function clopperPearson(x, n, alpha = ALPHA) {
  if (n === 0) return [0, 1];
  const lower = x === 0 ? 0 : bisect((p) => 1 - binomCdf(x - 1, n, p) >= alpha / 2);
  const upper = x === n ? 1 : bisect((p) => binomCdf(x, n, p) <= alpha / 2);
  return [lower, upper];
}
/** Exact two-sided McNemar test on discordant pairs b (A right, B wrong) and c (A wrong, B right). */
export function mcnemarExact(b, c) {
  const n = b + c;
  if (n === 0) return 1;
  return Math.min(1, 2 * binomCdf(Math.min(b, c), n, 0.5));
}

const pct = (x) => (x === null || Number.isNaN(x) ? "—" : `${(100 * x).toFixed(1)}%`);
const ci = ([a, b]) => `[${(100 * a).toFixed(1)}, ${(100 * b).toFixed(1)}]`;
const median = (a) => {
  const s = a.filter((x) => typeof x === "number").sort((x, y) => x - y);
  return s.length === 0 ? null : s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};

function main() {
  const set = process.argv[process.argv.indexOf("--set") + 1];
  const dir = join(ROOT, "bench", "runs", set);
  const rows = readFileSync(join(dir, "results.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const env = JSON.parse(readFileSync(join(dir, "environment.json"), "utf8"));
  const truths = new Map();
  for (const r of rows) {
    if (!truths.has(r.scenario)) truths.set(r.scenario, JSON.parse(readFileSync(join(dir, "corpus", r.scenario, "truth.json"), "utf8")));
  }
  const configs = [...new Set(rows.map((r) => r.config))];
  const families = [...new Set(rows.map((r) => r.family))];
  const by = (cfg) => rows.filter((r) => r.config === cfg);
  const ran = (cfg) => by(cfg).every((r) => r.decision !== "not-run");
  const correct = (r) => r.decision === r.truth;

  const summary = {};
  for (const cfg of configs) {
    const rs = by(cfg);
    if (!ran(cfg)) {
      summary[cfg] = { ran: false, reason: rs[0]?.reason };
      continue;
    }
    const n = rs.length;
    const k = rs.filter(correct).length;
    const pass = rs.filter((r) => r.truth === "pass");
    const block = rs.filter((r) => r.truth === "block");
    summary[cfg] = {
      ran: true,
      n,
      correct: k,
      accuracy: k / n,
      ci: clopperPearson(k, n),
      falseBlock: pass.filter((r) => r.decision === "block").length / pass.length,
      falsePass: block.filter((r) => r.decision === "pass").length / block.length,
      toolErrors: rs.filter((r) => r.toolError).length,
      spuriousTotal: rs.reduce((s, r) => s + r.spurious, 0),
      medianMs: median(rs.map((r) => r.ms)),
      perFamily: Object.fromEntries(families.map((f) => {
        const fr = rs.filter((r) => r.family === f);
        return [f, fr.filter(correct).length / fr.length];
      })),
    };
  }

  // Paired tests: AR-1 (and AR-2) vs each baseline that ran.
  const paired = {};
  for (const a of ["AR-1", "AR-2"]) {
    if (!summary[a]?.ran) continue;
    for (const b of BASELINES) {
      if (!summary[b]?.ran) continue;
      const A = new Map(by(a).map((r) => [r.scenario, correct(r)]));
      let bb = 0, cc = 0;
      for (const r of by(b)) {
        const ar = A.get(r.scenario), br = correct(r);
        if (ar && !br) bb++;
        if (!ar && br) cc++;
      }
      paired[`${a} vs ${b}`] = { aRightBWrong: bb, aWrongBRight: cc, diff: (summary[a].accuracy - summary[b].accuracy), p: mcnemarExact(bb, cc) };
    }
  }

  // Needle-level recall by wrapper (families with planted credentials).
  const recall = {};
  for (const cfg of configs) {
    if (!summary[cfg]?.ran) continue;
    const acc = {};
    for (const r of by(cfg)) {
      const t = truths.get(r.scenario);
      t.needles.forEach((nd, i) => {
        if (nd.kind !== "secret") return;
        const key = `${t.family} / ${nd.wrapper}${nd.outsideAntiReaDetectors !== undefined ? (nd.outsideAntiReaDetectors ? " (outside AR detectors)" : " (inside AR detectors)") : ""}`;
        acc[key] ??= [0, 0];
        acc[key][1]++;
        if (r.needleHits[i]) acc[key][0]++;
      });
    }
    recall[cfg] = acc;
  }

  // ---------------------------------------------------------------- hypotheses (as pre-registered)
  const ranBaselines = BASELINES.filter((b) => summary[b]?.ran);
  const H = [];
  const ar1 = summary["AR-1"];
  if (ranBaselines.length < BASELINES.length) {
    H.push({ id: "H1", verdict: "NOT EVALUABLE", detail: `baselines not run: ${BASELINES.filter((b) => !summary[b]?.ran).join(", ")}. H1 requires all five.` });
  } else {
    const thr = 0.01 / ranBaselines.length;
    const each = ranBaselines.map((b) => ({ b, ...paired[`AR-1 vs ${b}`] }));
    const ok = each.every((e) => e.diff >= 0.15 && e.p < thr);
    H.push({ id: "H1", verdict: ok ? "SUPPORTED" : "NOT SUPPORTED", detail: each.map((e) => `${e.b}: Δ=${pct(e.diff)} p=${e.p.toExponential(2)} (need Δ≥15.0%, p<${thr})`).join("; ") });
  }
  if (summary["AR-2"]?.ran && ar1) {
    const undecl = (cfg) => by(cfg).filter((r) => r.family === "UNDECLARED-LEAK");
    const fp1 = undecl("AR-1").filter((r) => r.decision === "pass").length;
    const fp2 = undecl("AR-2").filter((r) => r.decision === "pass").length;
    const ok = summary["AR-2"].accuracy >= ar1.accuracy && fp2 < fp1;
    H.push({ id: "H2", verdict: ok ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-2 acc ${pct(summary["AR-2"].accuracy)} vs AR-1 ${pct(ar1.accuracy)}; UNDECLARED-LEAK false passes AR-2 ${fp2} vs AR-1 ${fp1}` });
  } else H.push({ id: "H2", verdict: "NOT EVALUABLE", detail: "AR-2 requires trufflehog" });
  if (ar1) {
    const silent = by("AR-1").filter((r) => r.family === "UNVERIFIABLE" && r.decision === "pass").length;
    H.push({ id: "H3", verdict: silent === 0 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 silent passes on secrets inside unsupported content: ${silent}` });
  }
  if (summary["TH-D"]?.ran && ar1) {
    const out = (cfg) => {
      let hit = 0, n = 0;
      for (const r of by(cfg).filter((x) => x.family === "UNDECLARED-LEAK")) {
        const t = truths.get(r.scenario);
        t.needles.forEach((nd, i) => { if (nd.outsideAntiReaDetectors) { n++; if (r.needleHits[i]) hit++; } });
      }
      return [hit, n];
    };
    const [a, n] = out("AR-1"), [b] = out("TH-D");
    H.push({ id: "H4 (expected loss)", verdict: a < b ? "CONFIRMED (Anti-REA loses)" : "NOT CONFIRMED", detail: `recall on undeclared formats outside AR detectors: AR-1 ${a}/${n}, TH-D ${b}/${n}` });
    const fb = (cfg) => by(cfg).filter((r) => r.family === "UNVERIFIABLE-CLEAN" && r.decision === "block").length;
    const nClean = by("AR-1").filter((r) => r.family === "UNVERIFIABLE-CLEAN").length;
    H.push({ id: "H5 (expected loss)", verdict: fb("AR-1") > fb("TH-D") ? "CONFIRMED (Anti-REA loses)" : "NOT CONFIRMED", detail: `false blocks on clean undecodable content: AR-1 ${fb("AR-1")}/${nClean}, TH-D ${fb("TH-D")}/${nClean}` });
  } else {
    H.push({ id: "H4 (expected loss)", verdict: "NOT EVALUABLE", detail: "requires trufflehog" });
    H.push({ id: "H5 (expected loss)", verdict: "NOT EVALUABLE", detail: "requires trufflehog" });
  }

  // ---------------------------------------------------------------- report
  const L = [];
  L.push(`# Benchmark results — ${set} set`);
  L.push("");
  L.push(`Generated from \`bench/runs/${set}/results.jsonl\` by \`bench/score.mjs\`. Frozen tool+harness sha256 \`${env.frozenSha256}\`. Node ${env.node}, ${env.platform}.`);
  L.push("");
  L.push(`Tools: ${Object.entries(env.tools).map(([k, v]) => `${k} \`${v}\``).join(", ") || "none besides Anti-REA"}.`);
  L.push("");
  L.push("## Release-decision accuracy");
  L.push("");
  L.push("| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |");
  L.push("|---|---|---|---|---|---|---|---|");
  for (const cfg of configs) {
    const s = summary[cfg];
    if (!s.ran) L.push(`| ${cfg} | NOT RUN | — | — | — | — | — | — |`);
    else L.push(`| ${cfg} | ${s.correct}/${s.n} = ${pct(s.accuracy)} | ${ci(s.ci)} | ${pct(s.falseBlock)} | ${pct(s.falsePass)} | ${s.toolErrors} | ${s.spuriousTotal} | ${s.medianMs?.toFixed(0)} |`);
  }
  L.push("");
  L.push("## Accuracy per family");
  L.push("");
  const ranCfgs = configs.filter((c) => summary[c].ran);
  L.push(`| Family (truth) | ${ranCfgs.join(" | ")} |`);
  L.push(`|---|${ranCfgs.map(() => "---").join("|")}|`);
  for (const f of families) {
    const t = rows.find((r) => r.family === f).truth;
    L.push(`| ${f} (${t}) | ${ranCfgs.map((c) => pct(summary[c].perFamily[f])).join(" | ")} |`);
  }
  L.push("");
  if (Object.keys(paired).length) {
    L.push("## Paired comparisons (exact McNemar, two-sided)");
    L.push("");
    L.push("| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |");
    L.push("|---|---|---|---|---|");
    for (const [k, v] of Object.entries(paired)) L.push(`| ${k} | ${v.aRightBWrong} | ${v.aWrongBRight} | ${pct(v.diff)} | ${v.p.toExponential(2)} |`);
    L.push("");
  }
  L.push("## Needle recall by wrapper");
  L.push("");
  const keys = [...new Set(Object.values(recall).flatMap((r) => Object.keys(r)))].sort();
  L.push(`| Family / wrapper | ${ranCfgs.join(" | ")} |`);
  L.push(`|---|${ranCfgs.map(() => "---").join("|")}|`);
  for (const k of keys) L.push(`| ${k} | ${ranCfgs.map((c) => (recall[c][k] ? `${recall[c][k][0]}/${recall[c][k][1]}` : "—")).join(" | ")} |`);
  L.push("");
  L.push("## Pre-registered hypotheses");
  L.push("");
  for (const h of H) L.push(`- **${h.id}: ${h.verdict}** — ${h.detail}`);
  L.push("");
  writeFileSync(join(dir, "RESULTS.md"), L.join("\n"));
  writeFileSync(join(dir, "results.summary.json"), JSON.stringify({ summary, paired, recall, hypotheses: H, environment: env }, null, 2));
  console.log(L.join("\n"));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
