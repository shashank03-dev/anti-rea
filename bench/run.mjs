#!/usr/bin/env node
// Runs every pre-registered configuration over a generated corpus.
//
//   node bench/run.mjs --set dev|eval [--only AR-1,GL-D]
//
// Writes bench/runs/<set>/results.jsonl (one line per scenario × configuration).
// A configuration whose tool is not installed is recorded as "not-run"; no
// result is ever inferred for a tool that did not execute.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fingerprintOf } from "../build/src/index.js";
import { frozenHash } from "./freeze.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLS = join(ROOT, "bench", ".tools");
const TIMEOUT_MS = 600_000;

// Baselines never get network access: synthetic credentials must not reach any provider API.
const OFFLINE_ENV = { ...process.env, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", http_proxy: "http://127.0.0.1:9", https_proxy: "http://127.0.0.1:9", NO_PROXY: "", no_proxy: "" };

function which(name, local) {
  if (local && existsSync(local)) return local;
  const r = spawnSync("/usr/bin/which", [name], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : null;
}
const BIN = {
  gitleaks: which("gitleaks", join(TOOLS, "bin", "gitleaks")),
  trufflehog: which("trufflehog", join(TOOLS, "bin", "trufflehog")),
  detectSecrets: which("detect-secrets", join(TOOLS, "venv", "bin", "detect-secrets")),
};

function exec(cmd, args, opts = {}) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 1 << 30, timeout: TIMEOUT_MS, env: OFFLINE_ENV, ...opts });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { status: r.status, signal: r.signal, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ms, error: r.error ? String(r.error) : undefined };
}

const sha1 = (s) => createHash("sha1").update(s).digest("hex");

// ---------------------------------------------------------------- configurations (pre-registered)
const AR = (manifestName, extra = [], policy = "bench/policy.json", cli = "build/src/cli.js") => (scn, out) => {
  const r = exec(process.execPath, [join(ROOT, cli), "assure", "--manifest", join(scn, manifestName), "--policy", join(ROOT, policy), "--out", out, ...extra(scn)]);
  let findings = [];
  try {
    const rep = JSON.parse(readFileSync(join(out, "report.json"), "utf8"));
    findings = rep.evidence.flatMap((e) => e.findings).filter((f) => f.gate).map((f) => ({ rule: f.gate, fp: f.witness?.sha256, path: f.artifact?.path ?? f.reportedPath }));
  } catch {}
  return { ...r, decision: r.status === 0 ? "pass" : "block", toolError: r.status !== 0 && r.status !== 2, findings };
};

function gitleaks(tuned) {
  return (scn, out) => {
    mkdirSync(out, { recursive: true });
    const report = join(out, "gitleaks.json");
    const args = ["dir", join(scn, "release"), "--report-format", "json", "--report-path", report, "--no-banner", "--log-level", "error"];
    if (tuned) args.push("--config", join(scn, "gitleaks.toml"), "--max-archive-depth", "8", "--max-decode-depth", "5");
    const r = exec(BIN.gitleaks, args);
    let findings = [];
    try {
      findings = JSON.parse(readFileSync(report, "utf8") || "[]").map((f) => ({ rule: f.RuleID, fp: fingerprintOf(f.Secret ?? ""), path: f.File }));
    } catch {}
    return { ...r, decision: r.status === 0 && findings.length === 0 ? "pass" : "block", toolError: r.status !== 0 && r.status !== 1, findings };
  };
}

function trufflehog(tuned) {
  return (scn, out) => {
    mkdirSync(out, { recursive: true });
    const args = ["filesystem", join(scn, "release"), "--json", "--no-verification", "--no-update", "--fail"];
    if (tuned) args.push("--config", join(scn, "trufflehog.yaml"), "--fail-on-scan-errors");
    const r = exec(BIN.trufflehog, args);
    writeFileSync(join(out, "trufflehog.jsonl"), r.stdout);
    const findings = [];
    for (const line of r.stdout.split("\n")) {
      if (!line.trim()) continue;
      try {
        const j = JSON.parse(line);
        if (!j.DetectorName) continue;
        // Custom detectors are reported as DetectorName "CustomRegex"; their configured name is in ExtraData.name (amendment A1).
        const rule = j.DetectorName === "CustomRegex" && j.ExtraData?.name ? j.ExtraData.name : j.DetectorName;
        findings.push({ rule, fp: fingerprintOf(j.Raw || j.RawV2 || ""), path: j.SourceMetadata?.Data?.Filesystem?.file });
      } catch {}
    }
    return { ...r, decision: r.status === 0 && findings.length === 0 ? "pass" : "block", toolError: r.status !== 0 && r.status !== 183, findings };
  };
}

function detectSecrets() {
  return (scn, out) => {
    mkdirSync(out, { recursive: true });
    const r = exec(BIN.detectSecrets, ["scan", "--all-files", "--no-verify", "release"], { cwd: scn });
    writeFileSync(join(out, "detect-secrets.json"), r.stdout);
    const findings = [];
    try {
      for (const [file, list] of Object.entries(JSON.parse(r.stdout).results ?? {}))
        for (const f of list) findings.push({ rule: f.type, sha1: f.hashed_secret, path: file });
    } catch {}
    return { ...r, decision: r.status === 0 && findings.length === 0 ? "pass" : "block", toolError: r.status !== 0, findings };
  };
}

export const CONFIGS = [
  { id: "AR-0", label: "Anti-REA, no owner knowledge", needs: [], run: AR("manifest.noknowledge.json", () => []) },
  { id: "AR-1", label: "Anti-REA, owner asset model", needs: [], run: AR("manifest.json", () => []) },
  // Secondary (pre-registered, report only): same, but content that cannot be inspected warns instead of blocking.
  { id: "AR-1o", label: "Anti-REA, owner asset model, inconclusive lanes warn", needs: [], run: AR("manifest.json", () => [], "bench/policy.open.json") },
  // v5: the v0.4 tool exactly as evaluated in v4 (bench/v4/anti-rea-0.4.0), for a same-corpus regression comparison.
  { id: "AR-1@0.4", label: "Anti-REA v0.4 (frozen v4 build), owner asset model", needs: [], run: AR("manifest.json", () => [], "bench/policy.json", "bench/v4/anti-rea-0.4.0/src/cli.js") },
  { id: "GL-D", label: "gitleaks dir, defaults", needs: ["gitleaks"], run: gitleaks(false) },
  { id: "GL-T", label: "gitleaks dir, tuned (archives, decoding, owner rules + allowlist)", needs: ["gitleaks"], run: gitleaks(true) },
  { id: "TH-D", label: "trufflehog filesystem, defaults (no verification)", needs: ["trufflehog"], run: trufflehog(false) },
  { id: "TH-T", label: "trufflehog filesystem, tuned (owner detectors, fail on scan errors)", needs: ["trufflehog"], run: trufflehog(true) },
  { id: "DS-D", label: "detect-secrets scan --all-files", needs: ["detectSecrets"], run: detectSecrets() },
  {
    id: "AR-2",
    label: "Anti-REA owner asset model + imported trufflehog findings",
    needs: ["trufflehog"],
    run: (scn, out, runsDir) => {
      const th = join(runsDir, "out", "TH-D", scn.split("/").pop(), "trufflehog.jsonl");
      if (!existsSync(th)) return { status: null, ms: 0, decision: "not-run", toolError: true, findings: [], error: "TH-D output missing" };
      const thMs = JSON.parse(readFileSync(join(runsDir, "out", "TH-D", scn.split("/").pop(), "meta.json"), "utf8")).ms;
      const r = AR("manifest.json", () => ["--import", `trufflehog:${th}`])(scn, out);
      return { ...r, ms: r.ms + thMs };
    },
  },
];

// ---------------------------------------------------------------- needle matching
export function needleHits(truth, findings) {
  return truth.needles.map((n) => {
    if (n.kind === "secret" || n.kind === "public")
      return findings.some((f) => (f.fp && n.fingerprints.includes(f.fp)) || (f.sha1 && (n.sha1 ?? []).includes(f.sha1)));
    if (n.kind === "marker") return findings.some((f) => /serverOnlyFoundInDistribution|declared-server-only-implementation|DeclaredServerOnlyImplementation/.test(f.rule));
    if (n.kind === "private-artifact") return findings.some((f) => /declaredPrivateArtifactShipped|declared-private-artifact|inline-source-map|InlineSourceMap|SourceMapFile/.test(f.rule));
    if (n.kind === "clean-archive") return false; // nothing to find; present so the truth file names the archive
    return findings.length > 0; // doc-example: any finding is a hit (and a false alarm, since truth is pass)
  });
}

function main() {
  const args = process.argv.slice(2);
  const set = args[args.indexOf("--set") + 1];
  if (!["dev", "eval"].includes(set)) throw new Error("usage: run.mjs --set dev|eval [--only A,B]");
  const only = args.includes("--only") ? args[args.indexOf("--only") + 1].split(",") : null;
  const runsDir = join(ROOT, "bench", "runs", set);
  const corpus = join(runsDir, "corpus");
  if (set === "eval") {
    const prereg = readFileSync(join(ROOT, "bench", "PREREGISTRATION.md"), "utf8");
    const m = prereg.match(/frozen-sha256:\s*`?([0-9a-f]{64})`?/);
    const now = frozenHash();
    if (!m || m[1] !== now) throw new Error(`refusing to run eval: tool/harness hash ${now} does not match PREREGISTRATION.md (${m?.[1] ?? "missing"})`);
  }
  const index = JSON.parse(readFileSync(join(corpus, "index.json"), "utf8"));
  if (set === "eval" && index.seed !== parseInt(frozenHash().slice(0, 8), 16))
    throw new Error(`refusing to run eval: corpus seed ${index.seed} was not derived from the frozen hash`);
  const resultsPath = join(runsDir, "results.jsonl");
  if (!only) rmSync(resultsPath, { force: true });
  else if (existsSync(resultsPath)) {
    // Re-running a configuration replaces its rows instead of duplicating them (amendment A2).
    const keep = readFileSync(resultsPath, "utf8").split("\n").filter((l) => l.trim() && !only.includes(JSON.parse(l).config));
    writeFileSync(resultsPath, keep.map((l) => l + "\n").join(""));
  }
  const env = { node: process.version, platform: `${process.platform}-${process.arch}`, tools: {} };
  if (BIN.gitleaks) env.tools.gitleaks = exec(BIN.gitleaks, ["version"]).stdout.trim();
  if (BIN.trufflehog) env.tools.trufflehog = (exec(BIN.trufflehog, ["--version"]).stderr + exec(BIN.trufflehog, ["--version"]).stdout).trim().split("\n").pop();
  if (BIN.detectSecrets) env.tools["detect-secrets"] = exec(BIN.detectSecrets, ["--version"]).stdout.trim();
  env.frozenSha256 = frozenHash();
  writeFileSync(join(runsDir, "environment.json"), JSON.stringify(env, null, 2));

  for (const cfg of CONFIGS) {
    if (only && !only.includes(cfg.id)) continue;
    const missing = cfg.needs.filter((n) => !BIN[n]);
    let done = 0;
    for (const s of index.scenarios) {
      const scn = join(corpus, s.id);
      const truth = JSON.parse(readFileSync(join(scn, "truth.json"), "utf8"));
      const out = join(runsDir, "out", cfg.id, s.id);
      rmSync(out, { recursive: true, force: true });
      mkdirSync(out, { recursive: true });
      let rec;
      if (missing.length > 0) {
        rec = { decision: "not-run", reason: `tool not installed: ${missing.join(", ")}`, findings: [], ms: null };
      } else {
        const r = cfg.run(scn, out, runsDir);
        rec = { decision: r.decision, exit: r.status, signal: r.signal ?? null, toolError: r.toolError, ms: Math.round(r.ms), findings: r.findings, stderrTail: (r.stderr ?? "").slice(-400) };
      }
      writeFileSync(join(out, "meta.json"), JSON.stringify({ ms: rec.ms ?? 0 }));
      const hits = needleHits(truth, rec.findings);
      appendFileSync(
        resultsPath,
        JSON.stringify({ scenario: s.id, family: s.family, truth: s.truth, config: cfg.id, decision: rec.decision, exit: rec.exit ?? null, toolError: rec.toolError ?? false, ms: rec.ms, findings: rec.findings.length, needleHits: hits, spurious: rec.findings.filter((f) => !truth.needles.some((n, i) => hits[i] && matchesNeedle(n, f))).length, reason: rec.reason, stderrTail: rec.stderrTail }) + "\n",
      );
      done++;
    }
    console.log(`${cfg.id.padEnd(5)} ${missing.length ? `NOT RUN (${missing.join(", ")} not installed)` : `${done} scenarios`}`);
  }
}

function matchesNeedle(n, f) {
  return needleHits({ needles: [n] }, [f])[0];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
