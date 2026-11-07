/**
 * One test per defect found in the self-review (see docs/research/REVIEW.md).
 * Each test fails on the pre-review implementation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { assure } from "../src/engine/evaluate.js";
import { classify, DEFAULT_LIMITS } from "../src/lanes/containers.js";
import { writeTar, writeZip } from "../src/pack/writers.js";
import { validateManifest } from "../src/util/io.js";
import { canonicalSecret } from "../src/lanes/detectors.js";
import { fp, manifestFor, policyOf, put, syntheticPem, tmp } from "./helpers.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.js");
const SLACK = "xoxb-" + "4815162342-" + "TESTONLYabcdefghijklmnop";

function gate(rep: ReturnType<typeof assure>, id: string) {
  return rep.gates.find((g) => g.gate === id)!;
}

test("R1: native executables are scanned, not treated as opaque; installers are opaque", () => {
  const pem = syntheticPem();
  const pe = Buffer.concat([Buffer.from("MZ\x90\x00", "latin1"), Buffer.alloc(200), Buffer.from(pem), Buffer.alloc(64)]);
  assert.equal(classify("MyApp.exe", pe).type, "plain");
  assert.equal(classify("Setup.exe", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100), Buffer.from("NullsoftInst")])).type, "opaque");
  const dir = tmp();
  put(dir, "rel/MyApp.exe", pe);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "k", placement: "server-only", fingerprints: [fp(pem)] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.coverage.lanes.exposure, "concluded");
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking.length, 1);
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking[0]!.location?.line, undefined, "binaries report offsets, not lines");
});

test("R2: chunked scanning finds a secret straddling a chunk boundary exactly once", () => {
  const pem = syntheticPem();
  const dir = tmp();
  const filler = "x".repeat(3000) + "\n";
  put(dir, "rel/big.js", filler + `k="${pem.trimEnd().replace(/\n/g, "\\n")}";\n` + filler.repeat(3));
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "k", placement: "server-only", fingerprints: [fp(pem)], markers: ["k=\"-----BEGIN"] }] });
  const limits = { ...DEFAULT_LIMITS, scanChunkBytes: 3500, scanOverlapBytes: 2048 };
  const rep = assure({ manifest: m, policy: policyOf(), limits });
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking.length, 1);
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking[0]!.location?.line, 2);
});

test("R3: empty or trivially short markers are rejected (previously an infinite loop)", () => {
  const base = { schema: "anti-rea/manifest/v1", application: { name: "a", version: "1" }, releaseClosure: { roots: ["r"] } };
  assert.throws(() => validateManifest({ ...base, assets: [{ id: "x", placement: "server-only", markers: [""] }] }), /at least 4 characters/);
});

test("R4: an inconclusive exposure record is not masked by a not-applicable placement record", () => {
  const pem = syntheticPem();
  const dir = tmp();
  put(dir, "rel/a.js", "ok");
  put(dir, "rel/Installer.dmg", "opaque");
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "k", placement: "server-only", fingerprints: [fp(pem)] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.deepEqual(rep.coverage.assetsUnaddressed, ["k"]);
});

test("R5: bundler code that builds source-map comments is not treated as a shipped map", () => {
  const dir = tmp();
  put(
    dir,
    "rel/bundler.js",
    [
      'const c = "//# sourceMappingURL=" + url;',
      "const t = `",
      "//# sourceMappingURL=data:application/json;base64,${b64}",
      "`;",
      'emit("/*# sourceMappingURL=" + name + " */");',
    ].join("\n"),
  );
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"], private: ["**/*.map"] }, assets: [{ id: "ui", placement: "public-by-design" }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.evidence.find((r) => r.id === "inventory")!.findings.length, 0);
  assert.equal(rep.decision, "pass");
});

test("R6: PEM templates without a base64 body are not private keys", () => {
  const dir = tmp();
  put(dir, "rel/tpl.js", "const pem = `-----BEGIN PRIVATE KEY-----\\n${base64EncodedPrivateKeyBody}\\n-----END PRIVATE KEY-----`;");
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "ui", placement: "public-by-design" }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "pass", rep.blockingReasons.join("\n"));
  assert.equal(rep.evidence.find((r) => r.id === "exposure/detectors")!.findings.length, 0);
});

test("R7: UTF-16LE secrets and markers inside binaries are found", () => {
  const secret = "corp-svc-Q2hlY2tVdGYxNkxF0123";
  const bin = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(300), Buffer.from(secret, "utf16le"), Buffer.alloc(40), Buffer.from("computeRiskInternal", "utf16le"), Buffer.alloc(300)]);
  const dir = tmp();
  put(dir, "rel/lib.so", bin);
  const m = manifestFor(dir, {
    releaseClosure: { roots: ["rel"] },
    assets: [
      { id: "svc", placement: "server-only", fingerprints: [fp(secret)] },
      { id: "risk", placement: "server-only", markers: ["computeRiskInternal"] },
    ],
  });
  const rep = assure({ manifest: m, policy: policyOf() });
  const c = gate(rep, "confirmedCriticalSecret").blocking[0];
  assert.equal(c?.location?.encoding, "utf16le");
  assert.equal(gate(rep, "serverOnlyFoundInDistribution").blocking[0]?.location?.encoding, "utf16le");
});

test("R8: declared passwords containing symbols are confirmed by the fingerprint sweep", () => {
  const pw = "Tr0ub4dor&3!xQ#9";
  const dir = tmp();
  put(dir, "rel/db.conf", `host=db.internal\npassword=${pw}\n`);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "db", placement: "server-only", fingerprints: [fp(pw)] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking[0]?.location?.line, 2);
});

test("R9: an undeclared high-confidence credential blocks by default; low-confidence leads warn; documented examples are suppressed", () => {
  const dir = tmp();
  put(dir, "rel/cfg.js", `const slack = "${SLACK}";\nconst t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXRlc3Q";\nconst docs = "AKIAIOSFODNN7EXAMPLE";\n`);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "ui", placement: "public-by-design" }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(gate(rep, "unconfirmedCredentialLead").blocking.length, 1);
  assert.equal(gate(rep, "lowConfidenceCredentialLead").warnings.length, 1);
  assert.equal(rep.evidence.find((r) => r.id === "exposure/detectors")!.invocation.suppressedKnownExamples, 1);
});

test("R10: conflicting authorization results for one case are inconclusive, not last-wins", () => {
  const dir = tmp();
  put(dir, "rel/a.js", "ok");
  const m = manifestFor(dir, {
    releaseClosure: { roots: ["rel"] },
    assets: [{ id: "ui", placement: "public-by-design" }],
    authorization: { cases: [{ principal: "u@B", tenant: "A", object: "o", operation: "read", expected: "deny" }] },
  });
  const rep = assure({
    manifest: m,
    policy: policyOf({ requiredLanes: ["inventory", "exposure", "placement", "authorization"] }),
    authzResults: {
      schema: "anti-rea/authz-results/v1",
      executor: "t",
      executedAt: "2026-11-06T00:00:00Z",
      results: [
        { id: "u@B|A|o|read", observed: "allowed" },
        { id: "u@B|A|o|read", observed: "denied" },
      ],
    },
  });
  assert.equal(rep.coverage.lanes.authorization, "inconclusive");
});

test("R11: the CLI refuses to write a report inside a release root", () => {
  const dir = tmp();
  put(dir, "rel/a.js", "ok");
  writeFileSync(join(dir, "m.json"), JSON.stringify(manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "ui", placement: "public-by-design" }] }).value));
  writeFileSync(join(dir, "p.json"), JSON.stringify(policyOf().value));
  const r = spawnSync(process.execPath, [CLI, "assure", "--manifest", join(dir, "m.json"), "--policy", join(dir, "p.json"), "--out", join(dir, "rel", "report")], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /inside release root/);
});

// Windows has no POSIX mode bits: chmod 0o000 only sets the read-only attribute and the file stays readable.
test("R12: unreadable files become coverage gaps instead of crashes", { skip: process.getuid?.() === 0 || process.platform === "win32" }, () => {
  const dir = tmp();
  put(dir, "rel/ok.js", "ok");
  put(dir, "rel/locked.bin", "secret?");
  chmodSync(join(dir, "rel/locked.bin"), 0o000);
  try {
    const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "ui", placement: "public-by-design" }] });
    const rep = assure({ manifest: m, policy: policyOf() });
    assert.equal(rep.coverage.lanes.exposure, "inconclusive");
    assert.equal(rep.decision, "block");
  } finally {
    chmodSync(join(dir, "rel/locked.bin"), 0o644);
  }
});

test("R13: zip with prepended bytes (self-extractor stub) is read with corrected offsets", () => {
  const pem = syntheticPem();
  const zip = writeZip([{ path: "inner/key.pem", data: Buffer.from(pem) }]);
  const dir = tmp();
  put(dir, "rel/sfx.zip", Buffer.concat([Buffer.alloc(1000, 0x41), zip]));
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "k", placement: "server-only", fingerprints: [fp(pem)] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.match(gate(rep, "confirmedCriticalSecret").blocking[0]?.artifact?.path ?? "", /sfx\.zip!\/inner\/key\.pem$/);
});

test("R14: overlapping roots and one secret declared under two placements are rejected", () => {
  const base = { schema: "anti-rea/manifest/v1", application: { name: "a", version: "1" } };
  assert.throws(() => validateManifest({ ...base, releaseClosure: { roots: ["dist", "dist/app"] }, assets: [] }), /overlap/);
  const f = fp("same-secret-value-123");
  assert.throws(
    () => validateManifest({ ...base, releaseClosure: { roots: ["r"] }, assets: [{ id: "a", placement: "server-only", fingerprints: [f] }, { id: "b", placement: "public-by-design", fingerprints: [f] }] }),
    /also declared/,
  );
});

test("External lane: imported scanner findings are mapped through the asset model and never stored in plaintext", () => {
  const pem = syntheticPem();
  const publicKey = "AIzaSyD-public-by-design-browser-key0";
  const dir = tmp();
  put(dir, "rel/a.js", "ok");
  writeFileSync(
    join(dir, "gl.json"),
    JSON.stringify([
      { RuleID: "private-key", Secret: pem, File: "rel/x.pem", StartLine: 1 },
      { RuleID: "gcp-api-key", Secret: publicKey, File: "rel/a.js", StartLine: 3 },
      { RuleID: "generic-api-key", Secret: "Zx81kLmQ0pRt5uVw", File: "rel/a.js", StartLine: 9 },
    ]),
  );
  writeFileSync(
    join(dir, "th.jsonl"),
    JSON.stringify({ DetectorName: "Gitlab", DecoderName: "BASE64", Raw: "glpat-ABCDEFGHIJKLMNOPQRST", SourceMetadata: { Data: { Filesystem: { file: "rel/cfg.b64", line: 1 } } } }) + "\n",
  );
  const m = manifestFor(dir, {
    releaseClosure: { roots: ["rel"] },
    assets: [
      { id: "signing", placement: "server-only", fingerprints: [fp(pem)] },
      { id: "maps", placement: "public-by-design", fingerprints: [fp(publicKey)] },
    ],
  });
  const rep = assure({
    manifest: m,
    policy: policyOf(),
    imports: [
      { tool: "gitleaks", path: join(dir, "gl.json") },
      { tool: "trufflehog", path: join(dir, "th.jsonl") },
    ],
  });
  assert.equal(gate(rep, "confirmedCriticalSecret").blocking.length, 1);
  assert.equal(gate(rep, "unconfirmedCredentialLead").blocking.length, 1, "trufflehog GitLab token (decoded from base64) is a high-confidence lead");
  assert.equal(gate(rep, "lowConfidenceCredentialLead").warnings.length, 1, "gitleaks generic rule is low confidence");
  const json = JSON.stringify(rep);
  assert.ok(!json.includes(canonicalSecret(pem).slice(40, 80)));
  assert.ok(!json.includes("glpat-ABCDEFGHIJKLMNOPQRST"));
  assert.ok(!json.includes(publicKey));
});
