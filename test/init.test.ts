/**
 * `anti-rea init` scaffolding, actionable block messages, and the gap list in coverage limitations.
 *
 * The scaffold's central property: it declares ONLY expectations the build has something to apply to, so a
 * freshly scaffolded release is blocked for real reasons or for the one deliberate one (no asset model yet),
 * never because the scaffold guessed a platform the build is not.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scaffold } from "../src/engine/init.js";
import { assure } from "../src/engine/evaluate.js";
import { inventoryOfPath } from "../src/lanes/inventory.js";
import { collectPlatformFacts } from "../src/lanes/platform.js";
import { nameGaps } from "../src/lanes/exposure.js";
import { validateManifest, validatePolicy } from "../src/util/io.js";
import { writeAsar } from "../src/pack/writers.js";
import { put, tmp } from "./helpers.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.js");
const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });

function fuseWire(states: string): Buffer {
  return Buffer.concat([Buffer.alloc(100, 7), Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1"), Buffer.from([1, states.length]), Buffer.from(states, "latin1"), Buffer.alloc(100)]);
}

function scaffoldOf(dir: string) {
  const r = inventoryOfPath(dir);
  const facts = collectPlatformFacts(r.inventory);
  return scaffold({ root: "dist", app: { name: "t", version: "1" }, inventory: r.inventory, facts, electron: facts.fuses.length > 0 || r.inventory.items.some((i) => /\.asar$/.test(i.ref.path)) });
}

test("init: a plain JS/web build declares no platform expectations (nothing they could apply to)", () => {
  const dir = tmp("anti-rea-init-web-");
  put(dir, "dist/index.html", "<!doctype html><script src=app.js></script>");
  put(dir, "dist/app.js", "console.log(1)\n");
  const s = scaffoldOf(join(dir, "dist"));
  assert.equal(s.manifest.platform, undefined);
  assert.deepEqual(s.policy.requiredLanes, ["inventory", "exposure", "placement", "aids"]);
  assert.deepEqual(s.manifest.assets, []);
  assert.deepEqual(s.manifest.releaseClosure.roots, ["dist"]);
  // Valid exactly as written.
  validateManifest(JSON.parse(JSON.stringify(s.manifest)));
  validatePolicy(JSON.parse(JSON.stringify(s.policy)));
});

test("init: Electron fuses are declared only for fuses the shipped wire has; Electron aids are enabled", () => {
  const dir = tmp("anti-rea-init-el-");
  // An older wire with 4 slots: RunAsNode, EnableCookieEncryption, EnableNodeOptionsEnvironmentVariable, EnableNodeCliInspectArguments.
  put(dir, "dist/Electron Framework", fuseWire("1100"));
  writeFileSync(join(dir, "dist", "app.asar"), writeAsar([{ path: "main.js", data: Buffer.from("require('electron')\n") }]));
  const s = scaffoldOf(join(dir, "dist"));
  assert.deepEqual(s.manifest.platform?.electron?.fuses, { RunAsNode: false, EnableNodeOptionsEnvironmentVariable: false, EnableNodeCliInspectArguments: false });
  // Not inside a macOS app bundle: ASAR integrity is not readable there, so it is not declared.
  assert.equal(s.manifest.platform?.electron?.requireAsarIntegrity, undefined);
  assert.deepEqual(s.manifest.reAids?.electron, {});
  assert.ok(s.policy.requiredLanes.includes("platform"));

  // The scaffold's platform lane concludes on the build it was derived from (wire "1100": RunAsNode is ON).
  const m = validateManifest({ ...JSON.parse(JSON.stringify(s.manifest)), releaseClosure: { roots: ["dist"] } });
  const rep = assure({ manifest: { value: m, path: join(dir, "m.json"), sha256: "0".repeat(64) }, policy: { value: validatePolicy(JSON.parse(JSON.stringify(s.policy))), path: "p.json", sha256: "0".repeat(64) } });
  assert.equal(rep.coverage.lanes.platform, "concluded");
  assert.ok(rep.blockingReasons.some((r) => /Electron fuse RunAsNode is enabled/.test(r)), rep.blockingReasons.join("\n"));
});

test("init (CLI): writes a loadable scaffold, refuses to write inside the release, to a file target or over existing files", () => {
  const dir = tmp("anti-rea-init-cli-");
  put(dir, "dist/app.js", "console.log('hello')\n");
  put(dir, "dist/app.js.map", JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: ["const x: number = 1"], mappings: "AAAA" }));

  const inside = run("init", join(dir, "dist"), "--out", join(dir, "dist", "cfg"));
  assert.equal(inside.status, 1);
  assert.match(inside.stderr, /inside the release directory/);
  const file = run("init", join(dir, "dist", "app.js"), "--out", dir);
  assert.equal(file.status, 1);
  assert.match(file.stderr, /is a file; init needs the directory/);

  const ok = run("init", join(dir, "dist"), "--out", dir);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /anti-rea fingerprint --file/);
  const manifest = JSON.parse(readFileSync(join(dir, "anti-rea.manifest.json"), "utf8"));
  assert.deepEqual(manifest.releaseClosure.roots, ["dist"]);

  const again = run("init", join(dir, "dist"), "--out", dir);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /already exists; pass --force/);
  assert.equal(run("init", join(dir, "dist"), "--out", dir, "--force").status, 0);

  // First assure: blocks on the shipped source map AND explains the deliberate no-asset-model block.
  const a = run("assure", "--manifest", join(dir, "anti-rea.manifest.json"), "--policy", join(dir, "anti-rea.policy.json"), "--out", join(dir, "report"));
  assert.equal(a.status, 2, a.stdout + a.stderr);
  assert.match(a.stdout, /declaredPrivateArtifactShipped/);
  assert.match(a.stdout, /Required lane "placement" is inconclusive: No assets are declared/);
  assert.match(a.stdout, /record a policy exception \{ gate: "requiredLaneInconclusive", lane: "placement" \}/);
  assert.ok(existsSync(join(dir, "report", "report.json")));

  // Declaring an asset model (here: a public-by-design value) resolves the placement block.
  writeFileSync(join(dir, "anti-rea.manifest.json"), JSON.stringify({ ...manifest, assets: [{ id: "ui", placement: "public-by-design" }] }));
  const b = run("assure", "--manifest", join(dir, "anti-rea.manifest.json"), "--policy", join(dir, "anti-rea.policy.json"), "--out", join(dir, "report2"));
  assert.doesNotMatch(b.stdout, /Required lane "placement"/);
});

test("init (CLI): a Windows-style root in a manifest labels items exactly like the posix spelling", () => {
  const dir = tmp("anti-rea-init-win-");
  put(dir, "release/App/node_modules/dep/index.js.map", JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: ["x"], mappings: "" }));
  const manifest = { schema: "anti-rea/manifest/v1", application: { name: "t", version: "1" }, releaseClosure: { roots: ["release\\App"] }, assets: [] };
  writeFileSync(join(dir, "m.json"), JSON.stringify(manifest));
  const r = run("inventory", "--manifest", join(dir, "m.json"), "--json");
  if (process.platform !== "win32") {
    // On posix a backslash is a legal filename character, so the root does not exist; the label must still be posix.
    assert.match(r.stdout + r.stderr, /release\/App/);
    return;
  }
  assert.equal(r.status, 0, r.stderr);
  assert.ok(JSON.parse(r.stdout).items.every((i: { path: string }) => i.path.startsWith("release/App/")));
});

test("block messages: uninspectable artifacts are named with their reason", () => {
  const unsup = [
    { ref: { path: "rel/a.zip!/x.bin" }, unsupportedReason: "encrypted zip entry (content not inspected)" },
    { ref: { path: "rel/b.dmg" }, unsupportedReason: "encrypted DMG" },
    { ref: { path: "rel/c.7z" }, unsupportedReason: "7-Zip: format not supported" },
    { ref: { path: "rel/d.rar" }, unsupportedReason: "RAR" },
  ];
  const s = nameGaps(unsup);
  assert.match(s, /rel\/a\.zip!\/x\.bin: encrypted zip entry/);
  assert.match(s, /rel\/c\.7z/);
  assert.match(s, /and 1 more$/);
  assert.doesNotMatch(s, /d\.rar/);
});

test("block messages: one location per path even when a universal binary trips once per slice", () => {
  const dir = tmp("anti-rea-dedupe-");
  put(dir, "rel/a.js", "x");
  // Two findings with the same title and the same artifact, as a two-slice Mach-O produces.
  const rep = assure({
    manifest: { value: validateManifest({ schema: "anti-rea/manifest/v1", application: { name: "t", version: "1" }, releaseClosure: { roots: ["rel"], private: ["**/a.js"] }, assets: [{ id: "ui", placement: "public-by-design" }] }), path: join(dir, "m.json"), sha256: "0".repeat(64) },
    policy: { value: validatePolicy({ schema: "anti-rea/policy/v1", releaseScope: "t", requiredLanes: ["inventory"] }), path: "p.json", sha256: "0".repeat(64) },
  });
  for (const r of rep.blockingReasons) {
    const at = r.split(" @ ")[1];
    if (!at) continue;
    const locs = at.split(", ");
    assert.equal(new Set(locs).size, locs.length, `duplicate locations in: ${r}`);
  }
});
