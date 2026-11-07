/**
 * v0.5 changes (see docs/research/V05-CHANGES.md):
 * - DMG (UDIF + HFS+) reading, checked against hdiutil(1) on real third-party files;
 * - the generated-value test accepts single-case and prefixed/compound keys (v4's main miss);
 * - calls: any constructor, configuration methods, assigned factory calls;
 * - CONSTANT_CASE credential names with qualifiers after the noun;
 * - false-lead guards from calibration on sets A, C and D.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, linkSync, mkdirSync, readFileSync, readdirSync, lstatSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, relative, sep } from "node:path";
import { DEFAULT_LIMITS, classify, expand } from "../src/lanes/containers.js";
import { adcDecompress } from "../src/codecs/udif.js";
import { assure } from "../src/engine/evaluate.js";
import { generatedValue, runDetectors } from "../src/lanes/detectors.js";
import { manifestFor, policyOf, put, tmp } from "./helpers.js";

const require = createRequire(import.meta.url);
const TS_LIB = join(require.resolve("typescript/package.json"), "..", "lib");
const HDIUTIL = process.platform === "darwin" && spawnSync("/usr/bin/which", ["hdiutil"]).status === 0;

function files(root: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p);
      else out.set(relative(root, p).split(sep).join("/").normalize("NFC"), readFileSync(p));
    }
  };
  walk(root);
  return out;
}

/** A folder of real third-party files (TypeScript's lib) plus the HFS+ edge cases a release can contain. */
function dmgSource(): string {
  const dir = tmp("anti-rea-dmg-");
  const src = join(dir, "src");
  cpSync(TS_LIB, join(src, "lib"), { recursive: true });
  for (let i = 0; i < 1500; i++) put(src, `many/f${i}.txt`, `n${i}\n`); // multi-node catalog B-tree
  put(src, "Ünïcødé naïve.txt", "résumé\n"); // HFS+ stores NFD; paths are reported NFC
  put(src, "orig.txt", "linked\n");
  linkSync(join(src, "orig.txt"), join(src, "hard.txt")); // HFS+ hard link -> iNode file
  symlinkSync("orig.txt", join(src, "sym.txt"));
  return dir;
}

test("dmg: UDZO, UDBZ, UDRO, UDCO (ADC) and ULMO images from hdiutil expand to byte-identical files", { skip: !HDIUTIL }, () => {
  const dir = dmgSource();
  const want = files(join(dir, "src"));
  for (const format of ["UDZO", "UDBZ", "UDRO", "UDCO", "ULMO"]) {
    const img = join(dir, `${format}.dmg`);
    execFileSync("hdiutil", ["create", "-quiet", "-format", format, "-fs", "HFS+", "-srcfolder", join(dir, "src"), "-volname", "T", "-ov", img]);
    const buf = readFileSync(img);
    assert.deepEqual(classify(img, buf), { type: "container", kind: "dmg" }, format); // not misread as a bzip2/xz stream
    const ex = expand("dmg", img, buf, DEFAULT_LIMITS);
    assert.ok(ex.ok, `${format}: ${ex.ok ? "" : ex.reason}`);
    const got = new Map(ex.entries.map((e) => [e.name, e.data]));
    for (const [p, data] of want) assert.ok(got.get(p)?.equals(data), `${format}: ${p}`);
    assert.ok(ex.notes.some((n) => /symbolic link/.test(n)), format);
  }
});

test("dmg: LZFSE (ULFO), APFS and encrypted images are explicit coverage gaps, never content", { skip: !HDIUTIL }, () => {
  const dir = tmp("anti-rea-dmg-");
  put(dir, "src/a.txt", "hello\n");
  const mk = (name: string, args: string[], input?: string) => {
    const img = join(dir, name);
    execFileSync("hdiutil", ["create", "-quiet", ...args, "-srcfolder", join(dir, "src"), "-volname", "T", "-ov", img], input ? { input } : {});
    return readFileSync(img);
  };
  const ulfo = mk("ulfo.dmg", ["-format", "ULFO", "-fs", "HFS+"]);
  const r1 = expand("dmg", "ulfo.dmg", ulfo, DEFAULT_LIMITS);
  assert.ok(!r1.ok && /LZFSE/.test(r1.reason));
  const apfs = mk("apfs.dmg", ["-format", "UDZO", "-fs", "APFS"]);
  const r2 = expand("dmg", "apfs.dmg", apfs, DEFAULT_LIMITS);
  assert.ok(!r2.ok && /APFS/.test(r2.reason));
  const enc = mk("enc.dmg", ["-format", "UDZO", "-fs", "HFS+", "-encryption", "AES-256", "-stdinpass"], "not-a-real-passphrase");
  assert.deepEqual(classify("enc.dmg", enc), { type: "opaque", format: "encrypted Apple disk image" });
});

test("dmg: corrupted images fail to decode or still yield identical bytes (never wrong content)", { skip: !HDIUTIL }, () => {
  const dir = tmp("anti-rea-dmg-");
  for (let i = 0; i < 20; i++) put(dir, `src/d${i}/f.txt`, `file ${i} `.repeat(200));
  const img = join(dir, "x.dmg");
  execFileSync("hdiutil", ["create", "-quiet", "-format", "UDZO", "-fs", "HFS+", "-srcfolder", join(dir, "src"), "-volname", "T", "-ov", img]);
  const orig = readFileSync(img);
  const want = files(join(dir, "src"));
  let seed = 7;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
  for (let t = 0; t < 300; t++) {
    const b = Buffer.from(orig);
    for (let j = 0; j < 3; j++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
    const ex = expand("dmg", "x.dmg", b, DEFAULT_LIMITS);
    if (!ex.ok) continue;
    const got = new Map(ex.entries.map((e) => [e.name, e]));
    for (const [p, data] of want) {
      const e = got.get(p);
      assert.ok(e && (e.data === null || e.data.equals(data)), `trial ${t}: ${p} decoded to wrong bytes`);
    }
  }
});

test("dmg: a secret inside an app.asar inside a DMG is found under its nested path", { skip: !HDIUTIL }, () => {
  const dir = tmp("anti-rea-dmg-");
  const secret = "ghp_" + "Zq8Xw2Ve4Rt6Yu8Io0Pa2Sd4Fg6Hj8Kl0Zx2Cv";
  put(dir, "stage/App.app/Contents/Resources/config.json", JSON.stringify({ token: secret }));
  mkdirSync(join(dir, "rel"), { recursive: true });
  execFileSync("hdiutil", ["create", "-quiet", "-format", "UDZO", "-fs", "HFS+", "-srcfolder", join(dir, "stage"), "-volname", "App", "-ov", join(dir, "rel", "App.dmg")]);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }] });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "block");
  const lead = rep.gates.find((g) => g.gate === "unconfirmedCredentialLead")!.blocking[0]!;
  assert.match(JSON.stringify(lead), /App\.dmg!\/App\.app\/Contents\/Resources\/config\.json/);
});

test("adc: literal runs and both match forms decode", () => {
  // literal "abc", then a 2-byte match (len 3, dist 3) and a 3-byte match (len 4, dist 6)
  const src = Buffer.from([0x82, 0x61, 0x62, 0x63, 0x00, 0x02, 0x40, 0x00, 0x05]);
  assert.equal(adcDecompress(src, 10).toString("latin1"), "abcabcabca");
  assert.throws(() => adcDecompress(Buffer.from([0x00, 0x05]), 3)); // distance beyond output
});

const R = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY";
const leads = (s: string) => runDetectors(s).map((h) => `${h.detector}:${h.value}`);

test("single-case and compound credentials pass the generated-value test (v4's main miss)", () => {
  for (const v of [
    "csk-4f8k2m9x7q3w5e1r6t0y8u2i4o9p3a7s5d1f6g8h2j4k0l3z", // lowercase-only body
    "fc-3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e", // short prefix + hex
    "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", // marker in the second segment
    "sk-lf-0f8fad5b-d9cb-469f-a165-70867728950e", // prefix + UUID
    "xVLyHw.DQrNxQ:" + R + "Zq8Xw2Ve4Rt", // app.key:secret
    "4f2a9c7e1b3d5f8a0c6e", // 20-digit hex secret
    "JBSWY3DPEHPK3PXP4F2Q7R5T", // uppercase base32 seed
    "tvly-" + R, // v4 dev miss S034: the prefix no longer counts against the body
  ])
    assert.equal(generatedValue(v), true, v);
  for (const v of [
    "x86_64-apple-darwin23.4.0-clang",
    "EC_KEY_get0_private_key",
    "markup.bold.markdown",
    "localhost:8080:proxy:upstream",
    "https://api.example.com/v1/token",
    "version2024release01build7",
    "sk_test_" + R, // test mode: reported by the heuristic instead
  ])
    assert.equal(generatedValue(v), false, v);
});

test("calls: any constructor, configuration methods and assigned factory calls carry credentials", () => {
  const cases: [string, string][] = [
    [`const c = new Resend("${R}");`, "client-constructor-argument"],
    [`const c = new Ably.Realtime("${R}");`, "client-constructor-argument"],
    [`sdk.init("${R}");`, "config-call-argument"],
    [`client.authenticate("${R}");`, "config-call-argument"],
    [`const client = resend("${R}");`, "bare-call-argument"],
    [`const s = Stripe("${R}");`, "bare-call-argument"],
    [`x = await createClient("${R}")`, "bare-call-argument"],
  ];
  for (const [src, id] of cases) assert.deepEqual(runDetectors(src).map((h) => h.detector), [id], src);
});

test("calls that carry data, not credentials, are not leads (calibration on sets A, C, D)", () => {
  for (const src of [
    `[Guid("0f8fad5b-d9cb-469f-a165-70867728950e")]`, // C# attribute
    `VALUES ('0f8fad5b-d9cb-469f-a165-70867728950e', 'x')`, // SQL
    `B: bigFromHex("3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e3f9a1c7e5b2d8f4a")`,
    `return fail("EC_KEY_get0_private_key")`,
    `x = parseToken("${R}")`,
    `e("${R}")`, // minified helper
    `t.exec("${R}")`, // non-configuration method
    `new Error("${R}")`,
    `y = atob("${R}")`,
    `expect(x).toBe("${R}")`,
  ])
    assert.deepEqual(leads(src), [], src);
});

test("CONSTANT_CASE credential names with qualifiers after the noun; ids, URLs and public names are not", () => {
  for (const src of [`MJ_APIKEY_PRIVATE = "${R}"`, `const API_KEY_PROD = "${R}";`, `STRIPE_SECRET_LIVE=${R}\n`])
    assert.equal(runDetectors(src).filter((h) => h.kind === "keyed").length, 1, src);
  for (const src of [`SIGNING_KEY_ID = "${R}"`, `TOKEN_URL = "${R}"`, `RECAPTCHA_SITE_KEY = "${R}"`, `SUPABASE_PUBLIC_KEY = "${R}"`, `API_KEY_HEADER = "${R}"`])
    assert.deepEqual(leads(src), [], src);
});

test("keyed values: `.` and `:` only inside quotes (unquoted they are member expressions)", () => {
  assert.deepEqual(leads("const sharedSecret = nacl25519.boxKeyPair2;"), []);
  assert.deepEqual(leads("var privateKey = pki.privateKeyToAsn1;"), []);
  assert.equal(runDetectors(`{"apiKey": "xVLyHw.DQrNxQ:${R}"}`).length, 1);
});

test("hex and single-case bodies behind strong markers, including a second-segment marker", () => {
  const hex = "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e";
  assert.deepEqual(leads(`x = "lsv2_sk_${hex}_9b1d7f3a5c";`), [`prefixed-secret-token:lsv2_sk_${hex}_9b1d7f3a5c`]);
  assert.deepEqual(leads(`x = "csk-4f8k2m9x7q3w5e1r6t0y8u2i4o9p3a7s5d1f6g8h";`), ["prefixed-secret-token:csk-4f8k2m9x7q3w5e1r6t0y8u2i4o9p3a7s5d1f6g8h"]);
  assert.deepEqual(leads(`diff-${hex}${hex}`), []); // unmarked: a digest
});

test("a DMG-wrapped release is no longer an uninspectable gap: a clean DMG passes", { skip: !HDIUTIL }, () => {
  const dir = tmp("anti-rea-dmg-");
  put(dir, "stage/App.app/Contents/Info.plist", "<plist/>");
  mkdirSync(join(dir, "rel"), { recursive: true });
  execFileSync("hdiutil", ["create", "-quiet", "-format", "UDZO", "-fs", "HFS+", "-srcfolder", join(dir, "stage"), "-volname", "App", "-ov", join(dir, "rel", "App.dmg")]);
  writeFileSync(join(dir, "rel", "README.txt"), "release\n");
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }] });
  assert.equal(assure({ manifest: m, policy: policyOf() }).decision, "pass");
});

test("validation set E: words ending in 'sk' are not secret markers; repeated symbol patterns are not tokens", () => {
  // GCC mangled symbols in mingw-w64's compilers (690 false leads before the fix)
  assert.deepEqual(leads("\x00hf3_mask_roundP7rtx_defS0_S0_S0_S0_S0_\x00"), []);
  assert.deepEqual(leads("\x00task_queueX9Lk2Mq8Wn4Pz7Rt5Yv3Bc1\x00"), []);
  // real markers still block
  assert.equal(runDetectors(`x = "csk_${R}Zq8Xw2Ve4Rt"`).filter((h) => h.kind === "structural").length, 1);
  assert.equal(runDetectors(`x = "gsk_${R}Zq8Xw2Ve4Rt"`).filter((h) => h.kind === "structural").length, 1);
});
