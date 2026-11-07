#!/usr/bin/env node
// False-lead calibration on real third-party code that is NOT part of the benchmark corpus.
//   node bench/calibration/calibrate.mjs <dir>...
// Prints, per target, lead counts per gate and detector, with REDACTED witnesses only.
import { basename } from "node:path";
import { buildInventory, exposureLane } from "../../build/src/index.js";

const targets = process.argv.slice(2);
const summary = [];
for (const dir of targets) {
  const t0 = performance.now();
  const manifest = { schema: "anti-rea/manifest/v1", application: { name: "calibration", version: "0" }, releaseClosure: { roots: [dir] }, assets: [] };
  const inv = buildInventory(manifest, "/");
  const recs = exposureLane(manifest, inv, new Date().toISOString());
  const leads = recs.flatMap((r) => r.findings);
  const byGate = {};
  for (const f of leads) (byGate[f.gate] ??= {})[f.detector] = ((byGate[f.gate] ??= {})[f.detector] ?? 0) + 1;
  const items = inv.items.filter((i) => i.supported).length;
  const bytes = inv.items.reduce((s, i) => s + i.ref.bytes, 0);
  const row = { target: dir, items, mb: +(bytes / 1e6).toFixed(1), unsupported: inv.items.length - items, ms: Math.round(performance.now() - t0), byGate };
  summary.push(row);
  console.log(`\n== ${dir}  (${items} items, ${row.mb} MB, ${row.ms} ms)`);
  for (const [g, d] of Object.entries(byGate)) console.log(`  ${g}: ${JSON.stringify(d)}`);
  for (const f of leads.filter((f) => f.gate !== "lowConfidenceCredentialLead"))
    console.log(`    ${f.gate === "unrecognizedTokenLead" ? "S" : "F"} ${f.detector.padEnd(22)} ${f.witness.preview.padEnd(32)} ${basename(f.artifact.path).slice(-60)}${f.location?.decoded ? " [decoded " + f.location.decoded.join(">") + "]" : ""}`);
}
console.log("\nJSON " + JSON.stringify(summary));
