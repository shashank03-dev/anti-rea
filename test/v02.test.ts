/**
 * v0.2 changes, one test per behaviour (see docs/research/V02-CHANGES.md):
 * decodable compressed formats, text-encoding decoding, broader detectors,
 * the structural prefixed-token gate, and their false-positive guards.
 * None of these needs external tools; differential.test.ts covers parity with xz(1)/bzip2/bsdtar/ar.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { assure } from "../src/engine/evaluate.js";
import { classify } from "../src/lanes/containers.js";
import { runDetectors } from "../src/lanes/detectors.js";
import { decodeLayers } from "../src/lanes/decode.js";
import { crc32, crc32be, crc64 } from "../src/codecs/crc.js";
import { writeTar, writeZip } from "../src/pack/writers.js";
import { fp, manifestFor, policyOf, put, tmp } from "./helpers.js";

const GHP = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5";

function gate(rep: ReturnType<typeof assure>, id: string) {
  return rep.gates.find((g) => g.gate === id)!;
}

test("CRC implementations match published check values for '123456789'", () => {
  const b = Buffer.from("123456789");
  assert.equal(crc32(b), 0xcbf43926);
  assert.equal(crc32be(b), 0xfc891918); // CRC-32/BZIP2
  assert.equal(crc64(b).readBigUInt64LE(0), 0x995dc9bbdf1939fan); // CRC-64/XZ
});

test("base64-, hex- and percent-encoded declared secrets are confirmed, with the decoding recorded", () => {
  const secret = "corp-svc-" + "Q7wE9rT1yU3iO5pA7sD9fG1hJ3kL5zX7";
  for (const [name, wrap] of [
    ["b64", (s: string) => JSON.stringify({ bootstrap: Buffer.from(`const K = "${s}";`).toString("base64") })],
    ["b64url-of-pct", (s: string) => `x=${Buffer.from(encodeURIComponent(`k=${s}&a=1`)).toString("base64url")}`],
    ["hex", (s: string) => `blob = "${Buffer.from(`token: ${s}`).toString("hex")}"`],
  ] as const) {
    const dir = tmp();
    put(dir, "rel/config.json", wrap(secret));
    const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "svc", placement: "server-only", fingerprints: [fp(secret)] }] });
    const rep = assure({ manifest: m, policy: policyOf() });
    const hit = gate(rep, "confirmedCriticalSecret").blocking;
    assert.equal(hit.length, 1, name);
    assert.ok(hit[0]!.location?.decoded?.length, `${name}: decoding chain recorded`);
    assert.equal(hit[0]!.location?.line, 1);
  }
});

test("decoding drops binary noise: images, hashes and random base64 produce no spans", () => {
  const png = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAPklEQVR4nGNgGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFowAAi4QLAVF2pT8AAAAASUVORK5CYII=";
  const sha = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";
  const commit = "9fceb02d0ae598e95dc970b74767f19372d61af8a6b1c4e3f7d2a9e8b5c6d7e8";
  assert.deepEqual(decodeLayers(`a="${png}" b="${sha}" c="${commit}" d="${Buffer.alloc(48, 7).toString("base64")}"`), []);
});

test("decoding is linear on long runs (a regex for percent runs was quadratic)", () => {
  const t = performance.now();
  decodeLayers("A".repeat(2_000_000) + "%41%42");
  decodeLayers(("x".repeat(500) + "%").repeat(4000));
  assert.ok(performance.now() - t < 2000, `took ${performance.now() - t} ms`);
});

test("xz, bzip2, ar (v0.2) and lz4 (v0.3) are containers; 7z and RAR stay explicit gaps", () => {
  assert.deepEqual(classify("a.tar.xz", Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 4])), { type: "container", kind: "xz" });
  assert.deepEqual(classify("a.bz2", Buffer.from("BZh91AY&SY\0\0\0\0")), { type: "container", kind: "bzip2" });
  assert.deepEqual(classify("a.deb", Buffer.from("!<arch>\ndebian-binary   ")), { type: "container", kind: "ar" });
  assert.equal(classify("a.lz4", Buffer.from([0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7])).type, "container");
  assert.equal(classify("a.rar", Buffer.from("Rar!\x1a\x07\x01\x00", "latin1")).type, "opaque");
});

test("a corrupt xz stream is a coverage gap (inconclusive → blocks), not a pass", () => {
  const dir = tmp();
  put(dir, "rel/legacy.tar.xz", Buffer.concat([Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04]), Buffer.alloc(64, 0x41)]));
  const rep = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [] }), policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(gate(rep, "requiredLaneInconclusive").blocking.length > 0, true);
});

test("documented provider formats are format leads (block); test-mode keys only warn", () => {
  const A = "Zq8Xw2Ve4Rt6Yu8Io0Pa2Sd4Fg6Hj8Kl0Zx2Cv4Bn6Mq8Wn0Eb2Rv4Tc6Yx8Uz0Ia2Os4Pd6Fa8Gs0Hd2Jf4Kg6Lh8Zj0Xk2Cl4Vm6Bn8Nq0Mw2Qe4Wr6Et8Ry0Tu2Yi4Uo6Ip8Oa0Ps2Ad4Sf";
  const formats: Record<string, string> = {
    "gitlab-token": "glpat-" + A.slice(0, 20),
    "npm-token": "npm_" + A.slice(0, 36),
    "sendgrid-api-key": `SG.${A.slice(0, 22)}.${A.slice(22, 65)}`,
    "huggingface-token": "hf_" + A.replace(/[0-9]/g, "").slice(0, 34),
    "shopify-token": "shpat_" + "0123456789abcdef".repeat(2),
    "digitalocean-token": "dop_v1_" + "0123456789abcdef".repeat(4),
    "anthropic-api-key": "sk-ant-api03-" + A.slice(0, 93) + "AA",
    "openai-api-key": `sk-proj-${A.slice(0, 40)}T3BlbkFJ${A.slice(40, 80)}`,
  };
  for (const [id, v] of Object.entries(formats)) {
    const hits = runDetectors(`const k = "${v}";`);
    assert.equal(hits.length, 1, `${id}: ${hits.map((h) => h.detector)}`);
    assert.equal(hits[0]!.detector, id);
    assert.equal(hits[0]!.kind, "format");
  }
  const t = runDetectors(`stripe("sk_test_${A.slice(0, 24)}")`);
  assert.equal(t[0]?.kind, "heuristic");
});

test("structural rule: unknown <prefix>_<random> tokens are caught once; identifiers, hashes and public keys are not", () => {
  const R = "Zq8Xw2Ve4Rt6Yu8Io0Pa2Sd4Fg6Hj8Kl0Zx2Cv4Bn6Mq8Wn0Eb2Rv4Tc";
  // Secret-marked prefixes block (structural). Since v0.3 an unmarked prefix yields no lead by itself.
  for (const [v, ids] of [
    [`gsk_${R.slice(0, 52)}`, ["prefixed-secret-token"]],
    [`pscale_tkn_${R.slice(0, 43)}`, ["prefixed-secret-token"]],
    [`secret_${R.slice(0, 43)}`, ["prefixed-secret-token"]],
    [`r8_${R.slice(0, 37)}`, []],
    [`fo1_${R.slice(0, 43)}`, []],
    [`client-${R.slice(0, 32)}`, []],
  ] as const) {
    const hits = runDetectors(`v = "${v}"`);
    assert.deepEqual(hits.map((h) => h.detector), ids, v);
  }
  for (const v of [
    "ts_createSourceFileFromScratch12AB",
    "sha512-" + R.slice(0, 40),
    "commit_9fceb02d0ae598e95dc970b74767f19372d61af8",
    "id-0f8fad5b-d9cb-469f-a165-70867728950e",
    "pk_live_" + R.slice(0, 24),
    "pk_test_" + R.slice(0, 24),
    "__webpack_require__moduleCache2024",
    "sbp_a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", // hex bodies are indistinguishable from hashes
    "err33_10F9C724BFCF9E2B84B647F2AE0C4251LLySS_SStcSgvpfi", // Swift symbol hash (calibration)
    "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict", // nanoid alphabet (calibration)
    "cr_nj2ZF92AXhQBS44aspXa6kTt63jVmGUt903N2FGE", // base64url SHA-256 (calibration)
  ])
    assert.deepEqual(runDetectors(`x = "${v}"`), [], v);
  // A Swift mangled symbol from calibration: its prefix carries no secret marker, so no lead.
  assert.deepEqual(runDetectors(`x = "ss11_StringGutsV8copyUTF84intoSiSgSrys5UInt8VG_tF"`), []);
  // A recognised format is reported by its own detector only, not also by the structural rule.
  assert.deepEqual(runDetectors(`x = "${GHP}"`).map((h) => h.detector), ["github-token"]);
});

test("unrecognizedTokenLead blocks by default and can be set to warn by policy", () => {
  const dir = tmp();
  put(dir, "rel/a.js", `const T = "gsk_Zq8Xw2Ve4Rt6Yu8Io0Pa2Sd4Fg6Hj8Kl0Zx2Cv4Bn6Mq8Wn0Eb2Rv4T";`);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "rules", placement: "server-only", markers: ["computeRiskScoreV9"] }] });
  assert.equal(assure({ manifest: m, policy: policyOf() }).decision, "block");
  assert.equal(assure({ manifest: m, policy: policyOf({ gates: { unrecognizedTokenLead: "warn" } }) }).decision, "pass");
});

test("secrets inside xz/bzip2-free nested paths still resolve: gzip tar inside zip inside the release", () => {
  const dir = tmp();
  const tgz = gzipSync(writeTar([{ path: "cfg/k.js", data: Buffer.from(`k="${GHP}"`) }]));
  put(dir, "rel/plugin.zip", writeZip([{ path: "assets.tgz", data: tgz }]));
  const rep = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [] }), policy: policyOf() });
  const lead = gate(rep, "unconfirmedCredentialLead").blocking[0]!;
  assert.equal(lead.artifact?.path, "rel/plugin.zip!/assets.tgz!/cfg/k.js");
});
