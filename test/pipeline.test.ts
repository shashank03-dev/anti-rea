import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assure } from "../src/engine/evaluate.js";
import { renderMarkdown } from "../src/engine/report.js";
import { setClock } from "../src/util/clock.js";
import { writeAsar, writeZip } from "../src/pack/writers.js";
import { canonicalSecret } from "../src/lanes/detectors.js";
import type { AuthzResults } from "../src/lanes/authorization.js";
import { fp, manifestFor, policyOf, put, syntheticPem, tmp } from "./helpers.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.js");

/** A small Electron-like release. `leak` plants the server-only key inside app.asar. */
function release(opts: { leak?: boolean; map?: boolean; serverImpl?: boolean; extra?: (dir: string) => void } = {}) {
  const dir = tmp();
  const pem = syntheticPem();
  const files = [
    { path: "main.js", data: Buffer.from("require('./lib.js');\n") },
    { path: "lib.js", data: Buffer.from(opts.leak ? `const KEY = "${pem.trimEnd().replace(/\n/g, "\\n")}";\n` : "fetch('/sign');\n") },
  ];
  if (opts.map) files.push({ path: "lib.js.map", data: Buffer.from('{"version":3}') });
  put(dir, "rel/resources/app.asar", writeAsar(files));
  put(dir, "rel/updates/plugin.zip", writeZip([{ path: "p.js", data: Buffer.from(opts.serverImpl ? "exports.secretScoreV9 = 1" : "exports.ok = 1") }]));
  opts.extra?.(dir);
  return { dir, pem };
}

function standardManifest(dir: string, pem: string) {
  return manifestFor(dir, {
    releaseClosure: { roots: ["rel"], private: ["**/*.map"] },
    assets: [
      { id: "signing-key", placement: "server-only", fingerprints: [fp(pem)] },
      { id: "scoring", placement: "server-only", markers: ["secretScoreV9"] },
      { id: "ui", placement: "public-by-design" },
    ],
  });
}

test("clean release passes; every required lane concludes", () => {
  const { dir, pem } = release();
  const rep = assure({ manifest: standardManifest(dir, pem), policy: policyOf() });
  assert.equal(rep.decision, "pass", rep.blockingReasons.join("\n"));
  assert.deepEqual(rep.coverage.lanes, { inventory: "concluded", exposure: "concluded", placement: "concluded", authorization: "not-run", external: "not-run" });
  assert.deepEqual(rep.coverage.assetsUnaddressed, []);
  const sk = rep.evidence.find((r) => r.id === "exposure/signing-key")!;
  assert.equal(sk.outcome, "not-recovered-within-budget", "negative is a scoped observation, not a proof");
});

test("a confirmed server-only secret inside a nested asar blocks — and nothing else can offset it", () => {
  const { dir, pem } = release({ leak: true });
  const rep = assure({ manifest: standardManifest(dir, pem), policy: policyOf() });
  assert.equal(rep.decision, "block");
  const g = rep.gates.find((x) => x.gate === "confirmedCriticalSecret")!;
  assert.equal(g.blocking.length, 1);
  assert.match(g.blocking[0]!.artifact!.path, /app\.asar!\/lib\.js$/);
  // Every other lane is perfect — the doc's §10.1 counterexample: no score can coexist with this passing.
  assert.ok(rep.gates.filter((x) => x.gate !== "confirmedCriticalSecret").every((x) => x.blocking.length === 0));
  assert.equal("score" in rep, false, "no aggregate score is produced");
});

test("serialized report never contains the plaintext secret", () => {
  const { dir, pem } = release({ leak: true });
  const rep = assure({ manifest: standardManifest(dir, pem), policy: policyOf() });
  const json = JSON.stringify(rep);
  const md = renderMarkdown(rep);
  const body = canonicalSecret(pem);
  for (const chunk of [body.slice(0, 32), body.slice(100, 132), body.slice(-32)]) {
    assert.ok(!json.includes(chunk), "json leaks secret material");
    assert.ok(!md.includes(chunk), "markdown leaks secret material");
  }
});

test("server-only markers inside a nested zip and a shipped private map each block", () => {
  const { dir, pem } = release({ serverImpl: true, map: true });
  const rep = assure({ manifest: standardManifest(dir, pem), policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(rep.gates.find((g) => g.gate === "serverOnlyFoundInDistribution")!.blocking.length, 1);
  assert.equal(rep.gates.find((g) => g.gate === "declaredPrivateArtifactShipped")!.blocking.length, 1);
});

test("unsupported content makes required lanes inconclusive, which blocks instead of silently passing", () => {
  const { dir, pem } = release({ extra: (d) => put(d, "rel/Installer.dmg", "koly-opaque") });
  const rep = assure({ manifest: standardManifest(dir, pem), policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(rep.coverage.lanes.exposure, "inconclusive");
  const g = rep.gates.find((x) => x.gate === "requiredLaneInconclusive")!;
  assert.ok(g.blocking.some((f) => f.id.startsWith("exposure/")));
});

test("server-only asset with no evidence requirement is an unresolved gap", () => {
  const { dir } = release();
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "mystery", placement: "server-only" }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.deepEqual(rep.coverage.assetsUnaddressed, ["mystery"]);
});

test("exceptions: active exception yields pass-with-exceptions; expired exception does not apply", () => {
  const { dir, pem } = release({ leak: true });
  const ex = { gate: "confirmedCriticalSecret" as const, assetId: "signing-key", owner: "sec-lead", scope: "4.2.0 hotfix only", rationale: "key already rotated; old key revoked" };
  setClock(new Date("2026-11-06T00:00:00Z"));
  try {
    const ok = assure({ manifest: standardManifest(dir, pem), policy: policyOf({ exceptions: [{ ...ex, expiry: "2026-11-06" }] }) });
    assert.equal(ok.decision, "pass-with-exceptions");
    assert.equal(ok.gates.find((g) => g.gate === "confirmedCriticalSecret")!.excepted.length, 1, "excepted findings stay visible");
    const expired = assure({ manifest: standardManifest(dir, pem), policy: policyOf({ exceptions: [{ ...ex, expiry: "2026-11-05" }] }) });
    assert.equal(expired.decision, "block");
    assert.equal(expired.gates.find((g) => g.gate === "confirmedCriticalSecret")!.expiredExceptions.length, 1);
    const otherAsset = assure({ manifest: standardManifest(dir, pem), policy: policyOf({ exceptions: [{ ...ex, assetId: "scoring", expiry: "2027-01-01" }] }) });
    assert.equal(otherAsset.decision, "block", "exception scoped to another asset must not apply");
  } finally {
    setClock(null);
  }
});

test("per-asset warn override reports without blocking", () => {
  const { dir, pem } = release({ leak: true });
  const m = manifestFor(dir, {
    releaseClosure: { roots: ["rel"] },
    assets: [{ id: "signing-key", placement: "server-only", fingerprints: [fp(pem)], onConfirmedDistribution: "warn" }],
  });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "pass");
  assert.equal(rep.gates.find((g) => g.gate === "confirmedCriticalSecret")!.warnings.length, 1);
});

test("fingerprint sweep confirms a declared secret no generic detector recognises", () => {
  const secret = "zq-internal-7Hk29sLpQ0vXbN4m";
  const dir = tmp();
  put(dir, "rel/config.ini", `[svc]\nhandle=${secret}\n`);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "svc-cred", placement: "server-only", fingerprints: [fp(secret)] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  const f = rep.gates.find((g) => g.gate === "confirmedCriticalSecret")!.blocking[0];
  assert.equal(f?.detector, "fingerprint-sweep");
  assert.equal(f?.location?.line, 2);
});

test("authorization: missing results inconclusive; prohibited effect blocks; false denial is reported", () => {
  const { dir, pem } = release();
  const base = standardManifest(dir, pem).value;
  const m = manifestFor(dir, {
    ...base,
    authorization: {
      principals: ["u1@A", "u2@B"],
      tenants: ["A"],
      objects: ["doc:1"],
      operations: ["read"],
      cases: [{ principal: "u1@A", tenant: "A", object: "doc:1", operation: "read", expected: "allow" }],
    },
  });
  const pol = policyOf({ requiredLanes: ["inventory", "exposure", "placement", "authorization"] });
  const none = assure({ manifest: m, policy: pol });
  assert.equal(none.coverage.lanes.authorization, "inconclusive");
  assert.equal(none.decision, "block");

  const results = (u1: "allowed" | "denied", u2: "allowed" | "denied"): AuthzResults => ({
    schema: "anti-rea/authz-results/v1",
    executor: "test",
    executedAt: "2026-11-06T00:00:00Z",
    results: [
      { id: "u1@A|A|doc:1|read", observed: u1 },
      { id: "u2@B|A|doc:1|read", observed: u2 },
    ],
  });
  const bola = assure({ manifest: m, policy: pol, authzResults: results("allowed", "allowed") });
  assert.equal(bola.decision, "block");
  assert.equal(bola.gates.find((g) => g.gate === "reproducedPrivilegedEffect")!.blocking.length, 1);

  const fd = assure({ manifest: m, policy: pol, authzResults: results("denied", "denied") });
  assert.equal(fd.decision, "pass");
  assert.ok(fd.evidence.find((r) => r.lane === "authorization")!.findings.some((f) => f.id.includes("false-denial")));
});

test("release id is deterministic and changes when shipped bytes change", () => {
  const a = release();
  const r1 = assure({ manifest: standardManifest(a.dir, a.pem), policy: policyOf() });
  const r2 = assure({ manifest: standardManifest(a.dir, a.pem), policy: policyOf() });
  assert.equal(r1.releaseId, r2.releaseId);
  put(a.dir, "rel/extra.txt", "1");
  const r3 = assure({ manifest: standardManifest(a.dir, a.pem), policy: policyOf() });
  assert.notEqual(r1.releaseId, r3.releaseId);
});

test("CLI: exit 0 on pass, 2 on block, 1 on config error; fingerprint never echoes the secret", () => {
  const { dir, pem } = release({ leak: true });
  const manifest = standardManifest(dir, pem).value;
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
  writeFileSync(join(dir, "policy.json"), JSON.stringify(policyOf().value));
  const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });

  const blocked = run("assure", "--manifest", join(dir, "manifest.json"), "--policy", join(dir, "policy.json"), "--out", join(dir, "out"));
  assert.equal(blocked.status, 2, blocked.stderr);
  assert.match(blocked.stdout, /decision: BLOCK/);
  const rep = JSON.parse(readFileSync(join(dir, "out", "report.json"), "utf8"));
  assert.equal(rep.decision, "block");

  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ...manifest, assets: [] }));
  const empty = run("assure", "--manifest", join(dir, "manifest.json"), "--policy", join(dir, "policy.json"), "--out", join(dir, "out-empty"));
  assert.equal(empty.status, 2, "an empty asset model cannot produce a green release when placement is required");
  assert.match(empty.stdout, /Required lane "placement" is inconclusive/);

  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ...manifest, assets: [{ id: "ui", placement: "public-by-design" }] }));
  const leakFree = run("assure", "--manifest", join(dir, "manifest.json"), "--policy", join(dir, "policy.json"), "--out", join(dir, "out2"));
  // The key is still there but undeclared: a high-confidence unconfirmed lead, which blocks until triaged.
  assert.equal(leakFree.status, 2, leakFree.stdout + leakFree.stderr);
  assert.match(leakFree.stdout, /\[unconfirmedCredentialLead\] Unconfirmed lead: PEM private key block/);

  writeFileSync(join(dir, "bad.json"), "{ nope");
  assert.equal(run("assure", "--manifest", join(dir, "bad.json"), "--policy", join(dir, "policy.json")).status, 1);
  assert.equal(run("frobnicate").status, 1);

  writeFileSync(join(dir, "k.pem"), pem);
  const f = run("fingerprint", "--file", join(dir, "k.pem"));
  assert.equal(f.status, 0);
  assert.ok(!f.stdout.includes(canonicalSecret(pem).slice(0, 20)));
  assert.match(f.stdout, /"value":"[0-9a-f]{64}"/);

  assert.match(run("stats", "min-trials", "--target", "0.001").stdout.trim(), /^2995$/);
});
