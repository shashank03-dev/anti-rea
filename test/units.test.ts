import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { globToRegExp, matchesAny } from "../src/util/glob.js";
import { DEFAULT_LIMITS, classify, expand } from "../src/lanes/containers.js";
import { writeAsar, writeTar, writeZip } from "../src/pack/writers.js";
import { canonicalSecret, fingerprintOf, runDetectors, witnessOf } from "../src/lanes/detectors.js";
import { minTrialsForBound, zeroEventUpperBound } from "../src/engine/stats.js";
import { shannonEntropy } from "../src/util/entropy.js";
import { validateManifest, validatePolicy, ConfigError } from "../src/util/io.js";
import { syntheticPem } from "./helpers.js";

test("glob: ** / * / ? / {a,b}", () => {
  assert.ok(matchesAny("a/b/c.map", ["**/*.map"]));
  assert.ok(matchesAny("c.map", ["**/*.map"]));
  assert.ok(!matchesAny("c.mapx", ["**/*.map"]));
  assert.ok(globToRegExp("src/*.js").test("src/a.js"));
  assert.ok(!globToRegExp("src/*.js").test("src/x/a.js"));
  assert.ok(globToRegExp("a?.{pdb,map}").test("ab.pdb"));
  assert.ok(globToRegExp("**/*.dSYM/**").test("x/App.app.dSYM/Contents/Info.plist"));
  assert.ok(globToRegExp("a+b(c).txt").test("a+b(c).txt"), "regex metacharacters are literal");
});

test("containers: zip (deflate + stored), asar, tar, tgz round-trip", () => {
  const files = [
    { path: "a.txt", data: Buffer.from("hello") },
    { path: "dir/b.js", data: Buffer.from("x".repeat(5000)) },
  ];
  for (const [kind, buf] of [
    ["zip", writeZip(files)],
    ["zip", writeZip(files, { store: true })],
    ["asar", writeAsar(files)],
    ["tar", writeTar(files)],
  ] as const) {
    const name = kind === "asar" ? "app.asar" : `x.${kind}`;
    assert.deepEqual(classify(name, buf), { type: "container", kind });
    const ex = expand(kind, name, buf, DEFAULT_LIMITS);
    assert.ok(ex.ok, `${kind} should expand`);
    if (!ex.ok) return;
    const got = Object.fromEntries(ex.entries.map((e) => [e.name, e.data?.toString()]));
    assert.equal(got["a.txt"], "hello");
    assert.equal(got["dir/b.js"], "x".repeat(5000));
  }
  const tgz = gzipSync(writeTar(files));
  assert.deepEqual(classify("x.tgz", tgz), { type: "container", kind: "gzip" });
  const ex = expand("gzip", "x.tgz", tgz, DEFAULT_LIMITS);
  assert.ok(ex.ok && ex.kind === "tar" && ex.entries.length === 2);
});

test("containers: decompression bomb and corrupt archives become explicit unsupported reasons", () => {
  const bomb = writeZip([{ path: "zeros.bin", data: Buffer.alloc(2 * 1024 * 1024) }]);
  const ex = expand("zip", "bomb.zip", bomb, { ...DEFAULT_LIMITS, maxEntryBytes: 1024 * 1024 });
  assert.ok(ex.ok);
  if (ex.ok) {
    assert.equal(ex.entries[0]!.data, null);
    assert.match(ex.entries[0]!.reason!, /exceeds limit/);
  }
  const corrupt = expand("zip", "bad.zip", Buffer.from("PK\x03\x04garbage"), DEFAULT_LIMITS);
  assert.equal(corrupt.ok, false);
  assert.equal(classify("Setup.dmg", Buffer.from("koly")).type, "opaque");
  assert.deepEqual(classify("plain.js", Buffer.from("console.log(1)")), { type: "plain" });
});

test("detectors: PEM key canonicalises identically as a file and as an escaped JS string", () => {
  const pem = syntheticPem();
  const inJs = `const K = "${pem.trimEnd().replace(/\n/g, "\\n")}";`;
  const hits = runDetectors(inJs).filter((c) => c.detector === "pem-private-key");
  assert.equal(hits.length, 1);
  assert.equal(fingerprintOf(hits[0]!.value), fingerprintOf(pem));
  assert.equal(canonicalSecret(pem).includes("-----"), false);
});

test("detectors: witness never contains the secret body", () => {
  const pem = syntheticPem();
  const w = witnessOf(pem);
  const body = canonicalSecret(pem);
  assert.ok(!w.preview.includes(body.slice(0, 24)));
  assert.match(w.preview, /redacted \d+ chars/);
  const tok = "sk_live_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7";
  assert.ok(!witnessOf(tok).preview.includes(tok.slice(4)));
});

test("detectors: credential-shaped assignments require entropy; plain words do not trip", () => {
  assert.equal(runDetectors(`password = "aaaaaaaaaaaaaaaaaaaa"`).length, 0);
  assert.equal(runDetectors(`api_key: "correcthorsebatterystaple"`).length, 0);
  assert.equal(runDetectors(`client_secret: "q8Zt3LmX0vR7pK2wN9sB4cF6"`)[0]?.detector, "keyed-credential");
  assert.equal(runDetectors(`k = "AKIAIOSFODNN7EXAMPLE"`)[0]?.detector, "aws-access-key-id");
});

test("stats: reproduces the research doc's zero-event table and 2,995 minimum", () => {
  const pct = (n: number) => zeroEventUpperBound(n) * 100;
  assert.equal(pct(30).toFixed(2), "9.50");
  assert.equal(pct(100).toFixed(2), "2.95");
  assert.equal(pct(300).toFixed(3), "0.994");
  assert.equal(pct(3000).toFixed(4), "0.0998");
  assert.equal(pct(30000).toFixed(5), "0.00999");
  assert.equal(minTrialsForBound(0.001), 2995);
  assert.ok(zeroEventUpperBound(2995) < 0.001 && zeroEventUpperBound(2994) >= 0.001);
  assert.throws(() => zeroEventUpperBound(0), RangeError);
});

test("entropy: sanity", () => {
  assert.equal(shannonEntropy("aaaa"), 0);
  assert.equal(shannonEntropy("ab"), 1);
});

test("config validation rejects unsafe or ambiguous declarations", () => {
  const base = { schema: "anti-rea/manifest/v1", application: { name: "a", version: "1" }, releaseClosure: { roots: ["r"] } };
  assert.throws(() => validateManifest({ ...base, assets: [{ id: "x", placement: "secret" }] }), ConfigError);
  assert.throws(() => validateManifest({ ...base, assets: [{ id: "x", placement: "server-only" }, { id: "x", placement: "server-only" }] }), /duplicated/);
  assert.throws(
    () => validateManifest({ ...base, assets: [{ id: "x", placement: "server-only", fingerprints: [{ type: "sha256", value: "PLAINTEXT-SECRET" }] }] }),
    /64 lowercase hex/,
    "fingerprints must be hashes, never plaintext",
  );
  assert.throws(() => validateManifest({ ...base, releaseClosure: { roots: ["r"], exclude: ["**/*.map"] }, assets: [] }), /not supported/);
  const pol = { schema: "anti-rea/policy/v1", releaseScope: "s", requiredLanes: ["inventory"] };
  assert.throws(() => validatePolicy({ ...pol, requiredLanes: ["fuzzing"] }), /unknown lane/);
  assert.throws(() => validatePolicy({ ...pol, exceptions: [{ gate: "confirmedCriticalSecret", owner: "o", scope: "s", rationale: "" , expiry: "2027-01-01" }] }), /rationale is required/);
  assert.throws(() => validatePolicy({ ...pol, gates: { bogus: "block" } }), /unknown gate/);
  assert.equal(validatePolicy(pol).gates.confirmedCriticalSecret, "block", "defaults merged");
});
