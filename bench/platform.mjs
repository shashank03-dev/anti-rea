#!/usr/bin/env node
// v6 platform sub-study (pre-registered in bench/PREREGISTRATION.md §3b). macOS only: bundles are
// built and ad-hoc signed with codesign(1), then tampered or not.
//
//   node bench/platform.mjs --set dev|eval --gen      generate bench/runs/<set>/platform/corpus
//   node bench/platform.mjs --set dev|eval --run      run AR-1, CS-D, CS-T → results.jsonl
//   node bench/platform.mjs --set dev|eval --score    → bench/runs/<set>/platform/RESULTS.md (+ summary.json)
//
// The eval seed is bits 32..63 of the frozen hash (the main corpus uses bits 0..31). Eval generation
// and runs refuse to proceed unless the tree matches the pre-registered hash.
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeAsar } from "../build/src/index.js";
import { frozenHash } from "./freeze.mjs";
import { mcnemarExact } from "./score.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SEEDS = { dev: 0x91a7f006, eval: null };
const seedFor = (set) => (set === "eval" ? parseInt(frozenHash().slice(8, 16), 16) : SEEDS[set]);
/** Scenarios per kind. */
const PER_KIND = { dev: 1, eval: 4 };
const CLEAN_N = { dev: 5, eval: 20 };

export const KINDS = {
  "P-CLEAN": ["intact"],
  // Tampering after signing: codesign(1) is the reference and should reject every one.
  "P-TAMPER": ["modified-resource", "added-file", "deleted-resource", "modified-code-page", "modified-info-plist", "modified-asar"],
  // Validly signed but violating the declared hardening policy: codesign --verify accepts these.
  "P-HARDENING": ["get-task-allow", "no-hardened-runtime", "runasnode-fuse-enabled", "asar-integrity-mismatch"],
};
const TRUTH = { "P-CLEAN": "pass", "P-TAMPER": "block", "P-HARDENING": "block" };

function mulberry32(a) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Same real background as the main v6 corpus (git share/ and abseil headers).
const GIT_SHARE = "/opt/homebrew/Cellar/git/2.56.0_1/share";
const ABSEIL_INCLUDE = "/opt/homebrew/Cellar/abseil/20260817.0/include";
function pool() {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && st.size > 2048 && st.size < 1_500_000) out.push(p);
    }
  };
  walk(GIT_SHARE);
  walk(ABSEIL_INCLUDE);
  return out;
}

const SENTINEL = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const fuseWire = (runAsNode) => Buffer.concat([Buffer.alloc(256, 0x90), Buffer.from(SENTINEL, "latin1"), Buffer.from([1, 9]), Buffer.from((runAsNode ? "1" : "0") + "11001100", "latin1"), Buffer.alloc(256, 0x90)]);
const asarHeaderHash = (asar) => createHash("sha256").update(asar.subarray(16, 16 + asar.readUInt32LE(12))).digest("hex");

function build(dir, id, kind, rnd, bg) {
  const app = join(dir, "release", "Example.app");
  const C = join(app, "Contents");
  const pick = () => bg[Math.floor(rnd() * bg.length)];
  const asar = writeAsar([
    { path: "package.json", data: Buffer.from(JSON.stringify({ name: `example-${id}`, main: "main.js" })) },
    { path: "main.js", data: Buffer.from('require("electron").app.whenReady().then(() => {});\n') },
    { path: `vendor/${pick().split("/").pop()}`, data: readFileSync(pick()) },
  ]);
  const integrity = kind === "asar-integrity-mismatch" ? createHash("sha256").update(`wrong-${id}`).digest("hex") : asarHeaderHash(asar);
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Example</string>
<key>CFBundleIdentifier</key><string>dev.anti-rea.bench.${id.toLowerCase()}</string>
<key>CFBundleName</key><string>Example</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>ElectronAsarIntegrity</key><dict><key>Resources/app.asar</key><dict><key>algorithm</key><string>SHA256</string><key>hash</key><string>${integrity}</string></dict></dict>
</dict></plist>
`;
  mkdirSync(join(C, "MacOS"), { recursive: true });
  mkdirSync(join(C, "Resources", "docs"), { recursive: true });
  writeFileSync(join(C, "Info.plist"), plist);
  cpSync("/usr/bin/true", join(C, "MacOS", "Example"));
  writeFileSync(join(C, "Resources", "app.asar"), asar);
  writeFileSync(join(C, "Resources", "fuses.bin"), fuseWire(kind === "runasnode-fuse-enabled"));
  for (let i = 0; i < 3; i++) {
    const p = pick();
    writeFileSync(join(C, "Resources", "docs", `${i}-${p.split("/").pop()}`), readFileSync(p));
  }
  const args = ["-s", "-", "--force", "--timestamp=none"];
  if (kind !== "no-hardened-runtime") args.push("-o", "runtime");
  if (kind === "get-task-allow") {
    const ent = join(dir, "entitlements.plist");
    writeFileSync(ent, '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>');
    args.push("--entitlements", ent);
  }
  execFileSync("codesign", [...args, app], { stdio: "ignore" });

  // Tampering after signing.
  const docs = readdirSync(join(C, "Resources", "docs")).sort();
  if (kind === "modified-resource") {
    const f = join(C, "Resources", "docs", docs[0]);
    const b = readFileSync(f);
    b[Math.floor(rnd() * b.length)] ^= 0x20;
    writeFileSync(f, b);
  }
  if (kind === "added-file") writeFileSync(join(C, "Resources", "docs", "added-after-signing.txt"), readFileSync(pick()));
  if (kind === "deleted-resource") rmSync(join(C, "Resources", "docs", docs[1]));
  if (kind === "modified-code-page") {
    const f = join(C, "MacOS", "Example");
    const b = readFileSync(f);
    // every slice (codesign checks the host slice): a byte in the second code page
    const n = b.readUInt32BE(4);
    for (let i = 0; i < n; i++) {
      const off = b.readUInt32BE(8 + i * 20 + 8);
      b[off + 0x1100] ^= 0xff;
    }
    writeFileSync(f, b);
  }
  if (kind === "modified-info-plist") writeFileSync(join(C, "Info.plist"), plist.replace("<string>Example</string>\n<key>CFBundlePackageType", "<string>Example Pro</string>\n<key>CFBundlePackageType"));
  if (kind === "modified-asar") {
    const f = join(C, "Resources", "app.asar");
    const b = readFileSync(f);
    const at = 16 + b.toString("latin1", 16, 16 + b.readUInt32LE(12)).indexOf("main.js");
    b.write("mail.js", at, "latin1");
    writeFileSync(f, b);
  }

  const manifest = {
    schema: "anti-rea/manifest/v1",
    application: { name: "example", version: "1.0.0" },
    releaseClosure: { roots: ["release"] },
    assets: [{ id: "ui", placement: "public-by-design", rationale: "shipped UI" }],
    platform: { macos: { requireHardenedRuntime: true }, electron: { fuses: { RunAsNode: false }, requireAsarIntegrity: true } },
  };
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  return { id, kind };
}

function gen(set) {
  if (process.platform !== "darwin") throw new Error("the platform sub-study needs macOS (codesign)");
  const out = join(ROOT, "bench", "runs", set, "platform", "corpus");
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const seed = seedFor(set);
  const rnd = mulberry32(seed);
  const bg = pool();
  const plan = [];
  for (let i = 0; i < CLEAN_N[set]; i++) plan.push(["P-CLEAN", "intact"]);
  for (const fam of ["P-TAMPER", "P-HARDENING"]) for (const k of KINDS[fam]) for (let i = 0; i < PER_KIND[set]; i++) plan.push([fam, k]);
  // seeded order, so families are interleaved
  for (let i = plan.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [plan[i], plan[j]] = [plan[j], plan[i]];
  }
  const index = plan.map(([family, kind], i) => {
    const id = `P${String(i + 1).padStart(3, "0")}`;
    build(join(out, id), id, kind, rnd, bg);
    writeFileSync(join(out, id, "truth.json"), JSON.stringify({ id, family, kind, truth: TRUTH[family] }, null, 2));
    return { id, family, kind, truth: TRUTH[family] };
  });
  writeFileSync(join(out, "index.json"), JSON.stringify({ set, seed, scenarios: index, backgroundPoolSize: bg.length }, null, 2));
  console.log(`generated ${index.length} platform scenarios (${set}, seed 0x${seed.toString(16)}) -> ${out}`);
}

const sh = (cmd, args) => {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 1 << 28 });
  return { ...r, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
};
const FORBIDDEN = ["com.apple.security.get-task-allow", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.disable-executable-page-protection"];

export const PLATFORM_CONFIGS = [
  {
    id: "AR-1",
    label: "Anti-REA, platform expectations declared in the manifest",
    run: (scn, out) => {
      const r = sh(process.execPath, [join(ROOT, "build/src/cli.js"), "assure", "--manifest", join(scn, "manifest.json"), "--policy", join(ROOT, "bench/policy.platform.json"), "--out", out]);
      return { decision: r.status === 0 ? "pass" : r.status === 2 ? "block" : "error", ms: r.ms, detail: r.status === 2 ? (r.stdout.match(/✗ .*/g) ?? []).slice(0, 3).join(" | ") : "" };
    },
  },
  {
    id: "CS-D",
    label: "codesign --verify --deep --strict",
    run: (scn) => {
      const r = sh("codesign", ["--verify", "--deep", "--strict", join(scn, "release", "Example.app")]);
      return { decision: r.status === 0 ? "pass" : "block", ms: r.ms, detail: r.stderr.trim().split("\n").pop() };
    },
  },
  {
    id: "CS-T",
    label: "codesign --verify --deep --strict + hardened-runtime flag + forbidden-entitlement check",
    run: (scn) => {
      const app = join(scn, "release", "Example.app");
      const v = sh("codesign", ["--verify", "--deep", "--strict", app]);
      const d = sh("codesign", ["-dvvv", app]);
      const e = sh("codesign", ["-d", "--entitlements", "-", "--xml", app]);
      const runtime = /flags=0x[0-9a-f]*\(([^)]*)\)/.exec(d.stderr)?.[1]?.split(",").includes("runtime") ?? false;
      const ents = FORBIDDEN.filter((k) => e.stdout.includes(k));
      const block = v.status !== 0 || !runtime || ents.length > 0;
      return { decision: block ? "block" : "pass", ms: v.ms + d.ms + e.ms, detail: [v.status !== 0 ? "verify failed" : "", runtime ? "" : "no runtime", ...ents].filter(Boolean).join(", ") };
    },
  },
];

function assertFrozen(set) {
  if (set !== "eval") return;
  const prereg = readFileSync(join(ROOT, "bench", "PREREGISTRATION.md"), "utf8");
  const m = prereg.match(/frozen-sha256:\s*`?([0-9a-f]{64})`?/);
  if (!m || m[1] !== frozenHash()) throw new Error(`refusing: tool/harness hash ${frozenHash()} does not match PREREGISTRATION.md (${m?.[1] ?? "missing"})`);
}

function run(set) {
  const dir = join(ROOT, "bench", "runs", set, "platform");
  const index = JSON.parse(readFileSync(join(dir, "corpus", "index.json"), "utf8"));
  if (set === "eval" && index.seed !== seedFor("eval")) throw new Error("refusing: platform corpus seed was not derived from the frozen hash");
  const res = join(dir, "results.jsonl");
  rmSync(res, { force: true });
  for (const cfg of PLATFORM_CONFIGS) {
    for (const s of index.scenarios) {
      const out = join(dir, "out", cfg.id, s.id);
      rmSync(out, { recursive: true, force: true });
      mkdirSync(out, { recursive: true });
      const r = cfg.run(join(dir, "corpus", s.id), out);
      appendFileSync(res, JSON.stringify({ scenario: s.id, family: s.family, kind: s.kind, truth: s.truth, config: cfg.id, decision: r.decision, ms: Math.round(r.ms), detail: r.detail }) + "\n");
    }
    console.log(`${cfg.id.padEnd(5)} ${index.scenarios.length} scenarios`);
  }
}

const pct = (x) => `${(100 * x).toFixed(1)}%`;

function score(set) {
  const dir = join(ROOT, "bench", "runs", set, "platform");
  const rows = readFileSync(join(dir, "results.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const by = (c) => rows.filter((r) => r.config === c);
  const ok = (r) => r.decision === r.truth;
  const cfgs = PLATFORM_CONFIGS.map((c) => c.id);
  const N = by("AR-1").length;
  const acc = Object.fromEntries(cfgs.map((c) => [c, by(c).filter(ok).length]));
  const pair = (a, b) => {
    const B = new Map(by(b).map((r) => [r.scenario, ok(r)]));
    let x = 0, y = 0;
    for (const r of by(a)) {
      if (ok(r) && !B.get(r.scenario)) x++;
      if (!ok(r) && B.get(r.scenario)) y++;
    }
    return { x, y, p: mcnemarExact(x, y) };
  };
  const H = [];
  H.push({ id: "H12 (platform accuracy)", verdict: acc["AR-1"] >= Math.ceil(0.95 * N) ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 correct ${acc["AR-1"]}/${N} (need ≥95%)` });
  const agree = by("AR-1").filter((r) => r.family !== "P-HARDENING");
  const cs = new Map(by("CS-D").map((r) => [r.scenario, r.decision]));
  const nAgree = agree.filter((r) => r.decision === cs.get(r.scenario)).length;
  H.push({ id: "H12b (agreement with codesign on clean + tampered)", verdict: nAgree === agree.length ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 and CS-D decisions agree on ${nAgree}/${agree.length} P-CLEAN + P-TAMPER scenarios (need all)` });
  const e = pair("AR-1", "CS-T");
  H.push({ id: "H12c (AR-1 vs scripted codesign policy CS-T)", verdict: acc["AR-1"] > acc["CS-T"] && e.p < 0.01 ? "SUPPORTED" : "NOT SUPPORTED", detail: `AR-1 ${acc["AR-1"]}/${N} vs CS-T ${acc["CS-T"]}/${N}: ${e.x} : ${e.y}, exact McNemar p=${e.p.toExponential(2)} (need AR-1 ahead, p<0.01)` });
  const kinds = [...new Set(rows.map((r) => r.kind))];
  const L = [`# Platform sub-study results — ${set} set`, "", `N = ${N} scenarios; frozen ${frozenHash().slice(0, 8)}…`, "", "| Config | Correct | Accuracy |", "|---|---|---|"];
  for (const c of cfgs) L.push(`| ${c} | ${acc[c]}/${N} | ${pct(acc[c] / N)} |`);
  L.push("", "| Kind | Truth | n | " + cfgs.join(" | ") + " |", "|---|---|---|" + cfgs.map(() => "---").join("|") + "|");
  for (const k of kinds) {
    const rs = (c) => by(c).filter((r) => r.kind === k);
    L.push(`| ${k} | ${rs("AR-1")[0].truth} | ${rs("AR-1").length} | ${cfgs.map((c) => rs(c).filter(ok).length).join(" | ")} |`);
  }
  L.push("", "## Hypotheses", "");
  for (const h of H) L.push(`- **${h.id}: ${h.verdict}.** ${h.detail}`);
  const wrong = rows.filter((r) => !ok(r));
  if (wrong.length) {
    L.push("", "## Errors", "");
    for (const r of wrong) L.push(`- ${r.config} ${r.scenario} (${r.kind}, truth ${r.truth}): ${r.decision}${r.detail ? ` — ${r.detail}` : ""}`);
  }
  writeFileSync(join(dir, "RESULTS.md"), L.join("\n") + "\n");
  writeFileSync(join(dir, "summary.json"), JSON.stringify({ set, N, accuracy: acc, hypotheses: H }, null, 2));
  console.log(L.join("\n"));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const a = process.argv.slice(2);
  const set = a[a.indexOf("--set") + 1];
  if (!["dev", "eval"].includes(set)) throw new Error("usage: platform.mjs --set dev|eval --gen|--run|--score");
  if (a.includes("--gen")) {
    assertFrozen(set);
    gen(set);
  }
  if (a.includes("--run")) {
    assertFrozen(set);
    run(set);
  }
  if (a.includes("--score")) score(set);
}
