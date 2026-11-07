/**
 * v0.6 changes (see docs/research/V06-CHANGES.md):
 * - detector fixes for the v5 benchmark misses (Klaviyo `pk_`, fal `<uuid>:<hex>`, `*_PAT`);
 * - symlinks are inventory notes, not coverage gaps (real app bundles no longer block);
 * - property lists, Mach-O code signatures and bundle seals, checked against plutil(1) and codesign(1);
 * - the platform lane: signing, hardened runtime, team, entitlements, seals, Electron fuses, ASAR integrity;
 * - the provenance lane (DSSE / in-toto / SLSA) and signed release-decision attestations.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { assure } from "../src/engine/evaluate.js";
import { generatedValue, runDetectors } from "../src/lanes/detectors.js";
import { buildInventory } from "../src/lanes/inventory.js";
import { parsePlist } from "../src/codecs/plist.js";
import { readMachO } from "../src/codecs/macho.js";
import { collectPlatformFacts, readFuses, FUSE_NAMES } from "../src/lanes/platform.js";
import { pae, parseProvenance } from "../src/lanes/provenance.js";
import { decisionStatement, signStatement, verifyAttestation, PAYLOAD_TYPE } from "../src/engine/attest.js";
import { writeAsar } from "../src/pack/writers.js";
import { manifestFor, policyOf, put, tmp } from "./helpers.js";

const DARWIN = process.platform === "darwin";
const has = (bin: string) => DARWIN && spawnSync("/usr/bin/which", [bin]).status === 0;
const CODESIGN = has("codesign");
const PLUTIL = has("plutil");
const R = "Zq8Xw2Ve4Rt7Yu1Io3Pa5Sd6Fg9Hj0Kl";
const leads = (s: string) => runDetectors(s).map((h) => h.value);
const UI = [{ id: "ui", placement: "public-by-design" as const }];

// ---------------------------------------------------------------- detectors

test("v5 misses: Klaviyo pk_ private keys, fal <uuid>:<hex> pairs and *_PAT names are credentials", () => {
  const klaviyo = "pk_3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e19";
  const fal = "0f8fad5b-d9cb-469f-a165-70867728950e:9b1d7f3a5c2e8f4a6c0e3f9a1c7e5b2d";
  const pat = "patQ8xW2vE4rT7yU1i.3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e";
  assert.ok(leads(`KLAVIYO_PRIVATE_KEY="${klaviyo}"`).includes(klaviyo));
  assert.ok(leads(`const FAL_KEY = "${fal}";`).includes(fal));
  assert.ok(leads(`AIRTABLE_PAT="${pat}"`).includes(pat)); // unquoted, `.` reads as a member expression (by design)
  assert.ok(leads(`GITHUB_PAT: "ghx_${R}"`).length > 0);
  // Stripe publishable keys and explicit client/public values stay public
  for (const v of ["pk_live_" + R, "pk_test_" + R, "public_" + R, "client_" + R]) assert.equal(generatedValue(v), false, v);
});

// ---------------------------------------------------------------- inventory

test("symlinks are recorded as inventory notes, not coverage gaps (v0.5 blocked every app bundle)", () => {
  const dir = tmp("anti-rea-sym-");
  put(dir, "rel/F.framework/Versions/A/F", "binary");
  mkdirSync(join(dir, "rel/F.framework/Versions"), { recursive: true });
  symlinkSync("A", join(dir, "rel/F.framework/Versions/Current"));
  symlinkSync("Versions/Current/F", join(dir, "rel/F.framework/F"));
  symlinkSync("/etc/hosts", join(dir, "rel/outside"));
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI });
  const inv = buildInventory(m.value, dir);
  assert.equal(inv.items.filter((i) => !i.supported).length, 0);
  assert.ok(inv.notes.some((n) => /3 symbolic link/.test(n) && /outside the release closure/.test(n)));
  assert.equal(assure({ manifest: m, policy: policyOf() }).decision, "pass");
});

// ---------------------------------------------------------------- plist

test("plist: XML and binary forms parse to the same value; matches plutil", { skip: !PLUTIL }, () => {
  const dir = tmp("anti-rea-plist-");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>T &amp; U</string>
  <key>n</key><integer>-42</integer><key>big</key><integer>5000000000</integer><key>r</key><real>1.5</real>
  <key>t</key><true/><key>f</key><false/><key>d</key><data>AAEC/w==</data>
  <key>a</key><array><string>x</string><dict/><array/></array>
  <key>u</key><string>héllo ☃</string>
</dict></plist>`;
  writeFileSync(join(dir, "x.plist"), xml);
  execFileSync("plutil", ["-convert", "binary1", "-o", join(dir, "b.plist"), join(dir, "x.plist")]);
  const a = parsePlist(Buffer.from(xml));
  const b = parsePlist(readFileSync(join(dir, "b.plist")));
  assert.deepEqual(b, a);
  for (const k of ["CFBundleExecutable", "n", "big", "u"])
    assert.equal(String((a as Record<string, unknown>)[k]), execFileSync("plutil", ["-extract", k, "raw", "-o", "-", join(dir, "b.plist")], { encoding: "utf8" }).trim(), k);
  assert.deepEqual((a as Record<string, Buffer>).d, Buffer.from([0, 1, 2, 255]));
  assert.equal((a as Record<string, unknown>).big, 5000000000);
});

// ---------------------------------------------------------------- Mach-O and bundles (built and signed with codesign)

function cdhashFromCodesign(path: string): string {
  const r = spawnSync("codesign", ["-dvvv", path], { encoding: "utf8" });
  return /CDHash=([0-9a-f]+)/.exec(r.stderr)?.[1] ?? "";
}

function makeApp(dir: string, opts: { runtime?: boolean; entitlements?: Record<string, boolean>; asar?: Buffer; integrity?: string } = {}): string {
  const app = join(dir, "rel", "T.app");
  const integ = opts.asar
    ? `<key>ElectronAsarIntegrity</key><dict><key>Resources/app.asar</key><dict><key>algorithm</key><string>SHA256</string><key>hash</key><string>${opts.integrity}</string></dict></dict>`
    : "";
  put(app, "Contents/Info.plist", `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>T</string><key>CFBundleIdentifier</key><string>dev.anti-rea.t</string>${integ}</dict></plist>`);
  mkdirSync(join(app, "Contents/MacOS"), { recursive: true });
  cpSync("/usr/bin/true", join(app, "Contents/MacOS/T"));
  put(app, "Contents/Resources/a.txt", "resource\n");
  if (opts.asar) put(app, "Contents/Resources/app.asar", opts.asar);
  const args = ["-s", "-", "--force"];
  if (opts.runtime) args.push("-o", "runtime");
  if (opts.entitlements) {
    const ent = join(dir, "ent.plist");
    writeFileSync(ent, `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>${Object.entries(opts.entitlements).map(([k, v]) => `<key>${k}</key><${v}/>`).join("")}</dict></plist>`);
    args.push("--entitlements", ent);
  }
  execFileSync("codesign", [...args, app], { stdio: "ignore" });
  return app;
}

const csOk = (p: string) => spawnSync("codesign", ["--verify", "--deep", "--strict", p]).status === 0;

test("macho: code signatures parse; cdhash equals codesign's; a modified page is detected", { skip: !CODESIGN }, () => {
  const dir = tmp("anti-rea-macho-");
  const app = makeApp(dir, { runtime: true });
  const exe = join(app, "Contents/MacOS/T");
  const m = readMachO(readFileSync(exe));
  assert.ok(m.fat && m.slices.length >= 2);
  const cds = m.slices.flatMap((s) => s.codeDirectories);
  assert.ok(cds.every((c) => c.badPages === 0 && c.identifier === "dev.anti-rea.t"));
  assert.ok(cds.some((c) => c.cdhash === cdhashFromCodesign(exe)));
  const b = readFileSync(exe);
  for (const s of m.slices) b[s.offset + 0x4100] = b[s.offset + 0x4100]! ^ 0xff; // codesign checks the host slice
  writeFileSync(exe, b);
  assert.equal(csOk(app), false);
  assert.ok(readMachO(b).slices.some((s) => s.codeDirectories.some((c) => c.badPages > 0)));
});

test("platform lane: hardened runtime, ad hoc vs Developer ID, forbidden entitlements", { skip: !CODESIGN }, () => {
  const dir = tmp("anti-rea-plat-");
  makeApp(dir, { entitlements: { "com.apple.security.get-task-allow": true } });
  const run = (macos: object) => assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, platform: { macos } }), policy: policyOf() });
  const ids = (macos: object) => run(macos).gates.find((g) => g.gate === "platformHardeningViolation")!.blocking.map((f) => f.id.split("/")[1]);
  assert.deepEqual([...new Set(ids({}))], ["entitlement"]);
  assert.ok(ids({ requireHardenedRuntime: true }).includes("no-hardened-runtime"));
  assert.ok(ids({ requireDeveloperId: true }).includes("not-developer-signed"));
  assert.deepEqual(ids({ forbiddenEntitlements: [] }), []);
  assert.equal(run({ forbiddenEntitlements: [] }).decision, "pass");
});

test("bundle seal: agrees with codesign on intact, modified, added, deleted and Info.plist tampering", { skip: !CODESIGN }, () => {
  const cases: [string, (app: string) => void][] = [
    ["intact", () => {}],
    ["modified resource", (a) => writeFileSync(join(a, "Contents/Resources/a.txt"), "changed\n")],
    ["added resource", (a) => writeFileSync(join(a, "Contents/Resources/b.txt"), "new\n")],
    ["deleted resource", (a) => spawnSync("rm", [join(a, "Contents/Resources/a.txt")])],
    ["Info.plist", (a) => writeFileSync(join(a, "Contents/Info.plist"), readFileSync(join(a, "Contents/Info.plist"), "utf8").replace("dev.anti-rea.t", "dev.anti-rea.x"))],
    ["CodeResources", (a) => writeFileSync(join(a, "Contents/_CodeSignature/CodeResources"), readFileSync(join(a, "Contents/_CodeSignature/CodeResources"), "utf8").replace("<dict>", "<dict><key>x</key><string>y</string>"))],
  ];
  for (const [name, tamper] of cases) {
    const dir = tmp("anti-rea-seal-");
    const app = makeApp(dir);
    tamper(app);
    const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI });
    const facts = collectPlatformFacts(buildInventory(m.value, dir));
    const ours = facts.bundles.flatMap((b) => b.sealProblems);
    assert.equal(ours.length === 0, csOk(app), `${name}: anti-rea ${JSON.stringify(ours)} vs codesign ${csOk(app)}`);
  }
});

// ---------------------------------------------------------------- Electron

function fuseWire(states: string): Buffer {
  return Buffer.concat([Buffer.alloc(100, 7), Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1"), Buffer.from([1, states.length]), Buffer.from(states, "latin1"), Buffer.alloc(100)]);
}

test("electron fuses: the wire is read by name; required states are enforced", () => {
  const f = readFuses(fuseWire("01r10"))!;
  assert.equal(f.version, 1);
  assert.deepEqual(f.fuses, { [FUSE_NAMES[0]]: "disabled", [FUSE_NAMES[1]]: "enabled", [FUSE_NAMES[2]]: "removed", [FUSE_NAMES[3]]: "enabled", [FUSE_NAMES[4]]: "disabled" });
  const dir = tmp("anti-rea-fuse-");
  put(dir, "rel/Electron Framework", fuseWire("1100"));
  const run = (fuses: Record<string, boolean>) =>
    assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, platform: { electron: { fuses } } }), policy: policyOf() });
  assert.equal(run({ RunAsNode: false }).decision, "block");
  assert.equal(run({ EnableCookieEncryption: true, EnableNodeOptionsEnvironmentVariable: false, EnableNodeCliInspectArguments: false }).decision, "pass");
  // declared but no fuse wire in the release: inconclusive, never a silent pass
  const empty = tmp("anti-rea-nofuse-");
  put(empty, "rel/app.js", "x");
  const rep = assure({ manifest: manifestFor(empty, { releaseClosure: { roots: ["rel"] }, assets: UI, platform: { electron: { fuses: { RunAsNode: false } } } }), policy: policyOf({ requiredLanes: ["inventory", "exposure", "placement", "platform"] }) });
  assert.equal(rep.coverage.lanes.platform, "inconclusive");
  assert.equal(rep.decision, "block");
});

test("electron ASAR integrity: header hash matches; a modified header is a mismatch", { skip: !CODESIGN }, () => {
  const asar = writeAsar([{ path: "main.js", data: Buffer.from("console.log(1)") }]);
  const len = asar.readUInt32LE(12);
  const good = createHash("sha256").update(asar.subarray(16, 16 + len)).digest("hex");
  for (const [hash, expect] of [[good, "pass"], ["0".repeat(64), "block"]] as const) {
    const dir = tmp("anti-rea-asar-");
    makeApp(dir, { asar, integrity: hash });
    const rep = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, platform: { electron: { requireAsarIntegrity: true } } }), policy: policyOf() });
    assert.equal(rep.decision, expect, hash);
  }
});

// ---------------------------------------------------------------- provenance

function keypair(type: "ed25519" | "ec" | "rsa") {
  const k =
    type === "ed25519" ? generateKeyPairSync("ed25519") : type === "ec" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { priv: k.privateKey.export({ type: "pkcs8", format: "pem" }) as string, pub: k.publicKey.export({ type: "spki", format: "pem" }) as string, key: k.publicKey as KeyObject };
}

function slsa(subjects: [string, string][], builder: string) {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: subjects.map(([name, sha256]) => ({ name, digest: { sha256 } })),
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: { buildDefinition: { buildType: "x" }, runDetails: { builder: { id: builder } } },
  };
}

function provenanceRelease(type: "ed25519" | "ec" | "rsa" = "ed25519") {
  const dir = tmp("anti-rea-prov-");
  const bytes = Buffer.from("release artifact bytes\n");
  put(dir, "rel/app-1.0.bin", bytes);
  const kp = keypair(type);
  writeFileSync(join(dir, "builder.pub"), kp.pub);
  const st = slsa([["app-1.0.bin", createHash("sha256").update(bytes).digest("hex")]], "https://github.com/actions/runner");
  return { dir, kp, st };
}

const runProv = (dir: string, provenance: object) =>
  assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, provenance: provenance as never }), policy: policyOf() });

test("provenance: DSSE signatures verify with Ed25519, ECDSA P-256 and RSA keys; PAE matches the spec", () => {
  assert.equal(pae("http://example.com/HelloWorld", Buffer.from("hello world")).toString(), "DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  for (const t of ["ed25519", "ec", "rsa"] as const) {
    const { dir, kp, st } = provenanceRelease(t);
    writeFileSync(join(dir, "prov.json"), JSON.stringify(signStatement(st as never, kp.priv)));
    const rep = runProv(dir, { statement: "prov.json", publicKeys: ["builder.pub"], builderId: "https://github.com/actions/runner" });
    assert.equal(rep.decision, "pass", t);
    assert.equal(rep.coverage.lanes.provenance, "concluded");
  }
});

test("provenance: wrong key, wrong builder, unsigned, modified artifact and uncovered artifact all block", () => {
  const { dir, kp, st } = provenanceRelease();
  const other = keypair("ed25519");
  writeFileSync(join(dir, "other.pub"), other.pub);
  writeFileSync(join(dir, "prov.json"), JSON.stringify(signStatement(st as never, kp.priv)));
  writeFileSync(join(dir, "bare.json"), JSON.stringify(st));
  const ids = (p: object) => runProv(dir, p).gates.find((g) => g.gate === "provenanceMismatch")!.blocking.map((f) => f.id.split("/")[1]);
  assert.deepEqual(ids({ statement: "prov.json", publicKeys: ["other.pub"] }), ["bad-signature", "uncovered"]);
  assert.deepEqual(ids({ statement: "prov.json", publicKeys: ["builder.pub"], builderId: "https://evil.example/builder" }), ["builder", "uncovered"]);
  assert.deepEqual(ids({ statement: "bare.json", publicKeys: ["builder.pub"] }), ["unsigned", "uncovered"]);
  assert.deepEqual(ids({ statement: "bare.json" }), []); // no keys pinned: accepted, with a limitation recorded
  writeFileSync(join(dir, "rel/app-1.0.bin"), "tampered\n");
  assert.deepEqual(ids({ statement: "prov.json", publicKeys: ["builder.pub"] }), ["digest"]);
  put(dir, "rel/extra.bin", "unattested");
  assert.deepEqual(ids({ statement: "prov.json", publicKeys: ["builder.pub"], subjects: ["extra.bin"] }), ["uncovered"]);
  // a tampered payload under a valid signature
  const env = signStatement(st as never, kp.priv);
  const forged = { ...env, payload: Buffer.from(JSON.stringify(slsa([["app-1.0.bin", createHash("sha256").update("tampered\n").digest("hex")]], "x"))).toString("base64") };
  writeFileSync(join(dir, "forged.json"), JSON.stringify(forged));
  assert.ok(ids({ statement: "forged.json", publicKeys: ["builder.pub"], subjects: ["app-1.0.bin"] }).includes("bad-signature"));
});

test("provenance: Sigstore bundles and JSON Lines are read; unreadable provenance is inconclusive", () => {
  const { dir, kp, st } = provenanceRelease();
  const env = signStatement(st as never, kp.priv);
  writeFileSync(join(dir, "p.sigstore.json"), JSON.stringify({ mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", dsseEnvelope: env }));
  writeFileSync(join(dir, "p.jsonl"), `${JSON.stringify(env)}\n${JSON.stringify(st)}\n`);
  assert.equal(parseProvenance(readFileSync(join(dir, "p.jsonl"), "utf8")).length, 2);
  assert.equal(runProv(dir, { statement: "p.sigstore.json", publicKeys: ["builder.pub"] }).decision, "pass");
  writeFileSync(join(dir, "junk.json"), "{not json");
  const rep = assure({
    manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI, provenance: { statement: "junk.json" } }),
    policy: policyOf({ requiredLanes: ["inventory", "exposure", "placement", "provenance"] }),
  });
  assert.equal(rep.coverage.lanes.provenance, "inconclusive");
  assert.equal(rep.decision, "block");
});

// ---------------------------------------------------------------- attestations

test("attestation: a signed decision binds to the shipped bytes and verifies; tampering is detected", () => {
  const dir = tmp("anti-rea-att-");
  put(dir, "rel/app.js", "console.log('hello')\n");
  const rep = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: UI }), policy: policyOf() });
  const kp = keypair("ed25519");
  const reportJson = JSON.stringify(rep, null, 2) + "\n";
  const env = signStatement(decisionStatement(rep, reportJson), kp.priv);
  assert.equal(env.payloadType, PAYLOAD_TYPE);
  const art = { path: "app.js", sha256: createHash("sha256").update("console.log('hello')\n").digest("hex") };
  const ok = verifyAttestation(env, kp.pub, { artifacts: [art], requireDecision: "pass" });
  assert.deepEqual(ok.problems, []);
  const pred = ok.statement!.predicate as { releaseId: string; report: { sha256: string } };
  assert.equal(pred.releaseId, rep.releaseId);
  assert.equal(pred.report.sha256, createHash("sha256").update(reportJson).digest("hex"));
  assert.ok(verifyAttestation(env, kp.pub, { requireDecision: "block" }).problems.some((p) => /decision/.test(p)));
  assert.ok(verifyAttestation(env, kp.pub, { artifacts: [{ path: "x", sha256: "0".repeat(64) }] }).problems.some((p) => /not a subject/.test(p)));
  assert.equal(verifyAttestation(env, keypair("ed25519").pub).signatureValid, false);
  const forged = { ...env, payload: Buffer.from(Buffer.from(env.payload, "base64").toString().replace('"pass"', '"block"')).toString("base64") };
  assert.equal(verifyAttestation(forged, kp.pub).signatureValid, false);
});

test("validation set F: Objective-C selectors with an hf_ prefix are not Hugging Face tokens", () => {
  // shapes of the eight Home.app selector runs (Apple's HomeFoundation `hf_` category prefix)
  for (const v of ["hf_clearCachedCurrentDeviceStateIfNeed", "hf_currentUserSupportedLegacyHomeHubVe", "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"])
    assert.equal(runDetectors(`sel ${v.slice(0, 37)} x`).filter((h) => h.detector === "huggingface-token").length, 0, v);
  assert.ok(runDetectors(`HF = "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"`).some((h) => h.detector === "huggingface-token"));
});
