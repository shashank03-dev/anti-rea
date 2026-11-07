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
  for (const a of ["AR-1", "AR-2", "AR-1o"]) {
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
        const key = `${t.family} / ${nd.wrapper}${nd.stratum ? ` (${nd.stratum}, ${nd.style})` : ""}`;
        acc[key] ??= [0, 0];
        acc[key][1]++;
        if (r.needleHits[i]) acc[key][0]++;
      });
    }
    recall[cfg] = acc;
  }

  // ---------------------------------------------------------------- hypotheses (as pre-registered, v4)
  let cellTable = null;
  const ranBaselines = BASELINES.filter((b) => summary[b]?.ran);
  const H = [];
  const ar1 = summary["AR-1"];
  const fam = (cfg, f) => by(cfg).filter((r) => r.family === f);
  const needleOf = (r) => truths.get(r.scenario).needles[0];
  if (ranBaselines.length < BASELINES.length) {
    const why = `baselines not run: ${BASELINES.filter((b) => !summary[b]?.ran).join(", ")}. Requires all five.`;
    H.push({ id: "H1", verdict: "NOT EVALUABLE", detail: why }, { id: "H1b", verdict: "NOT EVALUABLE", detail: why });
  } else {
    const thr = 0.01 / ranBaselines.length;
    const each = ranBaselines.map((b) => ({ b, ...paired[`AR-1 vs ${b}`] }));
    const ok = each.every((e) => e.diff >= 0.15 && e.p < thr);
    H.push({ id: "H1", verdict: ok ? "SUPPORTED" : "NOT SUPPORTED", detail: each.map((e) => `${e.b}: Δ=${pct(e.diff)} p=${e.p.toExponential(2)} (need Δ≥15.0%, p<${thr})`).join("; ") });
    const thr2 = 0.05 / ranBaselines.length;
    const ok2 = each.every((e) => e.diff > 0 && e.p < thr2);
    H.push({ id: "H1b", verdict: ok2 ? "SUPPORTED" : "NOT SUPPORTED", detail: each.map((e) => `${e.b}: Δ=${pct(e.diff)} p=${e.p.toExponential(2)} (need Δ>0, p<${thr2})`).join("; ") });
  }
  if (summary["AR-2"]?.ran && ar1) {
    const fp1 = fam("AR-1", "UNDECLARED-LEAK").filter((r) => r.decision === "pass").length;
    const fp2 = fam("AR-2", "UNDECLARED-LEAK").filter((r) => r.decision === "pass").length;
    const ok = summary["AR-2"].accuracy >= ar1.accuracy && fp2 < fp1;
    H.push({ id: "H2", verdict: ok ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-2 acc ${pct(summary["AR-2"].accuracy)} vs AR-1 ${pct(ar1.accuracy)}; UNDECLARED-LEAK false passes AR-2 ${fp2} vs AR-1 ${fp1}` });
  } else H.push({ id: "H2", verdict: "NOT EVALUABLE", detail: "AR-2 requires trufflehog" });
  if (ar1) {
    const silent = fam("AR-1", "UNVERIFIABLE").filter((r) => r.decision === "pass").length;
    H.push({ id: "H3", verdict: silent === 0 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 silent passes on secrets inside uninspectable content: ${silent}/${fam("AR-1", "UNVERIFIABLE").length}` });
  }
  const heldout = (cfg, stratum) => fam(cfg, "UNDECLARED-LEAK").filter((r) => needleOf(r).stratum === stratum);
  const accOf = (rs) => rs.filter(correct).length;
  if (summary["TH-D"]?.ran && ar1) {
    const fb = (cfg) => fam(cfg, "UNVERIFIABLE-CLEAN").filter((r) => r.decision === "block").length;
    const nClean = fam("AR-1", "UNVERIFIABLE-CLEAN").length;
    H.push({ id: "H5 (expected loss)", verdict: fb("AR-1") > fb("TH-D") ? "CONFIRMED (Anti-REA loses)" : "NOT CONFIRMED", detail: `false blocks on clean uninspectable content: AR-1 ${fb("AR-1")}/${nClean}, TH-D ${fb("TH-D")}/${nClean}` });
  } else H.push({ id: "H5 (expected loss)", verdict: "NOT EVALUABLE", detail: "requires trufflehog" });
  if (ar1) {
    const style = (r) => needleOf(r).style;
    const un = heldout("AR-1", "HELDOUT-UNPREFIXED");
    const hp = heldout("AR-1", "HELDOUT-PREFIXED");
    // H4 (v4): the keyed detector generalises to held-out unprefixed formats that appear under a key name.
    const keyedStyles = un.filter((r) => ["env", "config"].includes(style(r)));
    const ok4 = keyedStyles.length > 0 && accOf(keyedStyles) >= Math.ceil(0.8 * keyedStyles.length);
    H.push({ id: "H4 (keyed detector generalises)", verdict: keyedStyles.length === 0 ? "NOT EVALUABLE" : ok4 ? "SUPPORTED" : "NOT SUPPORTED", detail: `held-out unprefixed, env/config style: blocked ${accOf(keyedStyles)}/${keyedStyles.length} (need ≥80%)` });
    // H4c (v4): call-style detection on held-out formats (ctor and method styles, both held-out strata).
    const callStyles = [...un, ...hp].filter((r) => ["ctor", "method"].includes(style(r)));
    const ok4c = callStyles.length > 0 && accOf(callStyles) >= Math.ceil(0.5 * callStyles.length);
    const bare = [...un, ...hp].filter((r) => style(r) === "bare");
    H.push({ id: "H4c (call styles)", verdict: callStyles.length === 0 ? "NOT EVALUABLE" : ok4c ? "SUPPORTED" : "NOT SUPPORTED", detail: `held-out formats, ctor/method style: blocked ${accOf(callStyles)}/${callStyles.length} (need ≥50%); bare style (no credential signal, predicted loss, not scored): blocked ${accOf(bare)}/${bare.length}` });
    const cc = fam("AR-1", "COMPRESSED-CLEAN");
    const ccOk = accOf(cc);
    const NEW = ["W7-base64", "W8-xz", "W9-bz2", "W10-zst", "W11-deb", "W12-percent", "W14-lz4", "W15-zip-bzip2"];
    const nw = fam("AR-1", "LEAK-DECLARED").filter((r) => NEW.includes(needleOf(r).wrapper));
    const nwOk = nw.filter((r) => correct(r) && r.needleHits.every(Boolean)).length;
    const ok6 = ccOk >= Math.ceil(0.95 * cc.length) && nwOk === nw.length;
    H.push({ id: "H6 (decoders)", verdict: ok6 ? "SUPPORTED" : "NOT SUPPORTED", detail: `COMPRESSED-CLEAN correct ${ccOk}/${cc.length} (need ≥95%); LEAK-DECLARED via ${NEW.join("/")} blocked with needle found ${nwOk}/${nw.length} (need all)` });
    // H7 (v4): held-out prefixes that mark the token secret (sk-or-, lsv2_sk_, csk-), across ALL styles.
    const MARKED = ["openrouter", "langsmith", "cerebras"];
    const marked = hp.filter((r) => MARKED.includes(needleOf(r).format));
    const unmarked = hp.filter((r) => !MARKED.includes(needleOf(r).format));
    const ok7 = marked.length > 0 && accOf(marked) >= Math.ceil(0.8 * marked.length);
    H.push({ id: "H7 (held-out secret-marked prefixes)", verdict: marked.length === 0 ? "NOT EVALUABLE" : ok7 ? "SUPPORTED" : "NOT SUPPORTED", detail: `secret-marked prefixes blocked ${accOf(marked)}/${marked.length} across all styles (need ≥80%); unmarked prefixes blocked ${accOf(unmarked)}/${unmarked.length}` });
    const spurious = by("AR-1").reduce((s, r) => s + r.spurious, 0);
    H.push({ id: "H8 (noise)", verdict: spurious <= 20 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 spurious findings: ${spurious} (need ≤20)` });
    if (summary["TH-T"]?.ran) {
      const s = (cfg) => accOf(fam(cfg, "UNDECLARED-LEAK"));
      const nU = fam("AR-1", "UNDECLARED-LEAK").length;
      H.push({ id: "H9 (undeclared leaks)", verdict: s("AR-1") >= s("TH-T") ? "SUPPORTED" : "NOT SUPPORTED", detail: `UNDECLARED-LEAK correct: AR-1 ${s("AR-1")}, TH-T ${s("TH-T")}, GL-T ${summary["GL-T"]?.ran ? s("GL-T") : "—"} of ${nU} (need AR-1 ≥ TH-T)` });
      // H9b (v4): the undeclared-leak advantage is significant (exact McNemar within the family).
      const A = new Map(fam("AR-1", "UNDECLARED-LEAK").map((r) => [r.scenario, correct(r)]));
      let b9 = 0, c9 = 0;
      for (const r of fam("TH-T", "UNDECLARED-LEAK")) {
        if (A.get(r.scenario) && !correct(r)) b9++;
        if (!A.get(r.scenario) && correct(r)) c9++;
      }
      const p9 = mcnemarExact(b9, c9);
      H.push({ id: "H9b (undeclared leaks, significance)", verdict: b9 > c9 && p9 < 0.05 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 vs TH-T on UNDECLARED-LEAK: ${b9} : ${c9} discordant, exact McNemar p=${p9.toExponential(2)} (need AR-1 ahead and p<0.05)` });
      if (summary["AR-1o"]?.ran) {
        const e = paired["AR-1o vs TH-T"];
        H.push({ id: "H10 (secondary: AR-1o vs TH-T)", verdict: e.diff > 0 && e.p < 0.01 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1o (uninspectable content warns) vs TH-T: Δ=${pct(e.diff)}, ${e.aRightBWrong} : ${e.aWrongBRight}, p=${e.p.toExponential(2)} (need Δ>0, p<0.01)` });
      }
    }
    // Per-cell table for UNDECLARED-LEAK (report only).
    cellTable = {};
    for (const cfg of configs.filter((c) => summary[c]?.ran))
      for (const r of fam(cfg, "UNDECLARED-LEAK")) {
        const k = `${needleOf(r).stratum} / ${needleOf(r).style}`;
        ((cellTable[k] ??= {})[cfg] ??= [0, 0])[1]++;
        if (correct(r)) cellTable[k][cfg][0]++;
      }
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
  if (cellTable) {
    L.push("## UNDECLARED-LEAK by stratum × render style (correct / n)");
    L.push("");
    L.push(`| Stratum / style | ${ranCfgs.join(" | ")} |`);
    L.push(`|---|${ranCfgs.map(() => "---").join("|")}|`);
    for (const k of Object.keys(cellTable)) L.push(`| ${k} | ${ranCfgs.map((c) => (cellTable[k][c] ? `${cellTable[k][c][0]}/${cellTable[k][c][1]}` : "—")).join(" | ")} |`);
    L.push("");
  }
  L.push("## Pre-registered hypotheses");
  L.push("");
  for (const h of H) L.push(`- **${h.id}: ${h.verdict}** — ${h.detail}`);
  L.push("");
  writeFileSync(join(dir, "RESULTS.md"), L.join("\n"));
  writeFileSync(join(dir, "results.summary.json"), JSON.stringify({ summary, paired, recall, undeclaredCells: cellTable, hypotheses: H, environment: env }, null, 2));
  console.log(L.join("\n"));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
